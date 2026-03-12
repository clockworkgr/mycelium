/// Battery level and adaptive power strategy per spec Section 16.

/// Power mode determined by battery level and mesh conditions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PowerMode {
    /// Full participation: all radios, relay for everyone.
    Full,
    /// Moderate: relay on Wi-Fi Direct only, BLE for discovery.
    Moderate,
    /// Light: own connections only, relay for direct trust.
    Light,
    /// Leaf: receive only, no relaying.
    Leaf,
    /// Hibernate: disconnect, queue outgoing.
    Hibernate,
}

/// Battery management stub. Real implementation on Android only.
pub struct BatteryManager {
    /// Current battery level (0-100). None if unknown (e.g., wired power).
    battery_level: Option<u8>,
    /// Whether the device is currently charging.
    is_charging: bool,
    /// Number of mesh neighbors.
    neighbor_count: u16,
}

impl BatteryManager {
    pub fn new() -> Self {
        Self {
            battery_level: None,
            is_charging: false,
            neighbor_count: 0,
        }
    }

    /// Create a manager for a wired/always-on device (supernode).
    pub fn always_on() -> Self {
        Self {
            battery_level: None,
            is_charging: true,
            neighbor_count: 0,
        }
    }

    /// Update battery state.
    pub fn update(&mut self, level: Option<u8>, is_charging: bool, neighbors: u16) {
        self.battery_level = level;
        self.is_charging = is_charging;
        self.neighbor_count = neighbors;
    }

    /// Determine the current power mode.
    pub fn power_mode(&self) -> PowerMode {
        let level = match self.battery_level {
            None => return PowerMode::Full, // Unknown = assume wired
            Some(l) => l,
        };

        if self.is_charging {
            return PowerMode::Full;
        }

        match level {
            0..=4 => PowerMode::Hibernate,
            5..=19 => PowerMode::Leaf,
            20..=49 => PowerMode::Light,
            50..=100 => {
                if self.neighbor_count <= 2 {
                    PowerMode::Full // Critical for connectivity
                } else {
                    PowerMode::Moderate
                }
            }
            _ => PowerMode::Full,
        }
    }

    /// Whether this node should relay messages for others.
    pub fn should_relay(&self) -> bool {
        matches!(
            self.power_mode(),
            PowerMode::Full | PowerMode::Moderate | PowerMode::Light
        )
    }

    pub fn battery_level(&self) -> Option<u8> {
        self.battery_level
    }

    pub fn is_charging(&self) -> bool {
        self.is_charging
    }
}

impl Default for BatteryManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_power_modes() {
        let mut bm = BatteryManager::new();

        bm.update(Some(100), false, 5);
        assert_eq!(bm.power_mode(), PowerMode::Moderate);

        bm.update(Some(80), true, 5);
        assert_eq!(bm.power_mode(), PowerMode::Full);

        bm.update(Some(60), false, 1);
        assert_eq!(bm.power_mode(), PowerMode::Full); // Critical node

        bm.update(Some(30), false, 5);
        assert_eq!(bm.power_mode(), PowerMode::Light);

        bm.update(Some(10), false, 5);
        assert_eq!(bm.power_mode(), PowerMode::Leaf);

        bm.update(Some(3), false, 5);
        assert_eq!(bm.power_mode(), PowerMode::Hibernate);
    }

    #[test]
    fn test_always_on() {
        let bm = BatteryManager::always_on();
        assert_eq!(bm.power_mode(), PowerMode::Full);
        assert!(bm.should_relay());
    }
}
