use serde::{Deserialize, Serialize};

/// Node configuration, loaded from TOML.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeConfig {
    /// Directory for persistent data (database, identity).
    pub data_dir: String,
    /// Human-readable display name.
    pub display_name: String,
    /// Node type.
    pub node_type: NodeTypeConfig,
    /// Transport configuration.
    pub transports: TransportConfig,
    /// DTN configuration.
    pub dtn: DtnStorageConfig,
    /// Beacon interval in seconds.
    pub beacon_interval_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NodeTypeConfig {
    Phone,
    Supernode,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransportConfig {
    pub wifi_direct: bool,
    pub ble: bool,
    pub lora: bool,
    pub internet_tunnel: bool,
    pub mock: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DtnStorageConfig {
    pub max_storage_mb: u32,
    pub per_identity_quota_mb: u32,
    pub ttl_hours: u32,
    pub spray_copies: u8,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            data_dir: "./mycelium-data".to_string(),
            display_name: "Mycelium Node".to_string(),
            node_type: NodeTypeConfig::Phone,
            transports: TransportConfig {
                wifi_direct: false,
                ble: false,
                lora: false,
                internet_tunnel: false,
                mock: true,
            },
            dtn: DtnStorageConfig {
                max_storage_mb: 256,
                per_identity_quota_mb: 10,
                ttl_hours: 72,
                spray_copies: 8,
            },
            beacon_interval_secs: 10,
        }
    }
}

impl NodeConfig {
    /// Load config from a TOML file.
    pub fn load(path: &str) -> Result<Self, anyhow::Error> {
        let content = std::fs::read_to_string(path)?;
        let config: Self = toml::from_str(&content)?;
        Ok(config)
    }

    /// Save config to a TOML file.
    pub fn save(&self, path: &str) -> Result<(), anyhow::Error> {
        let content = toml::to_string_pretty(self)?;
        std::fs::write(path, content)?;
        Ok(())
    }

    /// Supernode defaults.
    pub fn supernode() -> Self {
        Self {
            node_type: NodeTypeConfig::Supernode,
            dtn: DtnStorageConfig {
                max_storage_mb: 2048,
                per_identity_quota_mb: 50,
                ttl_hours: 72,
                spray_copies: 8,
            },
            beacon_interval_secs: 10,
            ..Default::default()
        }
    }
}
