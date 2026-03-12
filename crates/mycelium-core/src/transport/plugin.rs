//! Transport plugin API for extending Mycelium with external radio hardware.
//!
//! Third-party transports implement the `TransportPlugin` trait, which extends
//! the base `Transport` trait with configuration and metadata. Plugins are
//! registered with the `TransportManager` and participate in the mesh like
//! built-in transports.
//!
//! # Example
//!
//! ```ignore
//! struct MyRadioPlugin { /* ... */ }
//!
//! impl TransportPlugin for MyRadioPlugin {
//!     fn plugin_name(&self) -> &str { "my-radio" }
//!     fn plugin_version(&self) -> &str { "0.1.0" }
//!     fn plugin_description(&self) -> &str { "Custom radio transport" }
//!     fn configure(&mut self, config: &PluginConfig) -> Result<(), TransportError> {
//!         // Read config.settings for plugin-specific keys
//!         Ok(())
//!     }
//! }
//!
//! // Also implement Transport trait for MyRadioPlugin
//! ```

use std::collections::HashMap;

use super::TransportError;

/// Configuration passed to a transport plugin at initialization.
#[derive(Debug, Clone, Default)]
pub struct PluginConfig {
    /// Plugin name (must match the plugin's `plugin_name()`).
    pub name: String,
    /// Whether this plugin is enabled.
    pub enabled: bool,
    /// Plugin-specific key-value settings.
    pub settings: HashMap<String, String>,
}

/// Extended trait for pluggable transports.
///
/// Plugins implement this alongside the base `Transport` trait to add
/// configuration and metadata. The `TransportManager` registers plugins
/// the same way as built-in transports via `add_transport()`.
pub trait TransportPlugin: super::Transport {
    /// Unique plugin name (e.g., "meshtastic", "reticulum", "lora-sx1276").
    fn plugin_name(&self) -> &str;

    /// Semantic version string.
    fn plugin_version(&self) -> &str;

    /// Human-readable description of the plugin.
    fn plugin_description(&self) -> &str;

    /// Apply configuration from the plugin config map.
    /// Called before `start()`.
    fn configure(&mut self, config: &PluginConfig) -> Result<(), TransportError>;

    /// Whether this plugin requires platform-specific FFI callbacks.
    /// Plugins that use hardware directly (e.g., USB serial) return false.
    /// Plugins bridging to platform BLE/Wi-Fi return true.
    fn requires_platform_bridge(&self) -> bool {
        false
    }
}

/// Registry for transport plugins.
///
/// Plugins register a factory function that creates instances from config.
pub struct PluginRegistry {
    factories: HashMap<String, Box<dyn PluginFactory>>,
}

/// Factory trait for creating plugin instances.
pub trait PluginFactory: Send + Sync {
    /// Create a new plugin instance from config.
    fn create(&self, config: &PluginConfig) -> Result<Box<dyn TransportPlugin>, TransportError>;
}

impl PluginRegistry {
    pub fn new() -> Self {
        Self {
            factories: HashMap::new(),
        }
    }

    /// Register a plugin factory by name.
    pub fn register(&mut self, name: &str, factory: Box<dyn PluginFactory>) {
        self.factories.insert(name.to_string(), factory);
    }

    /// Create a plugin instance from config.
    pub fn create_plugin(
        &self,
        config: &PluginConfig,
    ) -> Result<Box<dyn TransportPlugin>, TransportError> {
        let factory = self
            .factories
            .get(&config.name)
            .ok_or_else(|| TransportError::Other(format!("unknown plugin: {}", config.name)))?;
        factory.create(config)
    }

    /// List registered plugin names.
    pub fn registered_plugins(&self) -> Vec<&str> {
        self.factories.keys().map(|s| s.as_str()).collect()
    }
}

impl Default for PluginRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plugin_config() {
        let mut config = PluginConfig::default();
        config.name = "test-radio".to_string();
        config.enabled = true;
        config
            .settings
            .insert("frequency".to_string(), "915".to_string());
        assert_eq!(config.settings.get("frequency"), Some(&"915".to_string()));
    }

    #[test]
    fn test_plugin_registry_unknown() {
        let registry = PluginRegistry::new();
        let config = PluginConfig {
            name: "nonexistent".to_string(),
            enabled: true,
            settings: HashMap::new(),
        };
        let result = registry.create_plugin(&config);
        assert!(result.is_err());
    }

    #[test]
    fn test_plugin_registry_list() {
        let registry = PluginRegistry::new();
        assert!(registry.registered_plugins().is_empty());
    }
}
