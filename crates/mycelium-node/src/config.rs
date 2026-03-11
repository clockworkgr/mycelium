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
    /// Local API server configuration.
    #[serde(default)]
    pub api: ApiConfig,
}

/// Local API server configuration (REST + WebSocket). See ADR-001.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiConfig {
    /// Whether to start the API server.
    pub enabled: bool,
    /// Bind address (default: 127.0.0.1).
    pub bind_address: String,
    /// Port (default: 9735).
    pub port: u16,
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            bind_address: "127.0.0.1".to_string(),
            port: 9735,
        }
    }
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
    /// Internet transport settings (only used when internet_tunnel=true).
    #[serde(default)]
    pub internet: InternetTransportConfig,
}

/// Settings for the TCP-based internet overlay transport.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternetTransportConfig {
    /// Port to listen on for incoming TCP connections.
    pub listen_port: u16,
    /// Bootstrap node addresses to connect to on startup.
    pub bootstrap_nodes: Vec<String>,
}

impl Default for InternetTransportConfig {
    fn default() -> Self {
        Self {
            listen_port: 9736,
            bootstrap_nodes: Vec::new(),
        }
    }
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
                internet: InternetTransportConfig::default(),
            },
            dtn: DtnStorageConfig {
                max_storage_mb: 256,
                per_identity_quota_mb: 10,
                ttl_hours: 72,
                spray_copies: 8,
            },
            beacon_interval_secs: 10,
            api: ApiConfig::default(),
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
            ..Default::default()
        }
    }
}
