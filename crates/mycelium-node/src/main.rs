use std::path::Path;

use anyhow::Result;
use tracing::info;
use tracing_subscriber::EnvFilter;

use mycelium_crypto::identity::Identity;
use mycelium_storage::db::Database;

mod battery;
mod beacon;
mod config;
mod node;
mod rate_limiter;

use config::NodeConfig;
use node::Node;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    // Load or create config
    let config_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "mycelium.toml".to_string());

    let config = if Path::new(&config_path).exists() {
        NodeConfig::load(&config_path)?
    } else {
        info!("No config file found, using defaults");
        NodeConfig::default()
    };

    // Ensure data directory exists
    std::fs::create_dir_all(&config.data_dir)?;

    // Load or generate identity
    let identity_path = format!("{}/identity.key", config.data_dir);
    let identity = if Path::new(&identity_path).exists() {
        let bytes = std::fs::read(&identity_path)?;
        let key_bytes: [u8; 96] = bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("Invalid identity file"))?;
        Identity::from_bytes(&key_bytes)?
    } else {
        let id = Identity::generate();
        std::fs::write(&identity_path, id.to_bytes())?;
        info!("Generated new identity");
        id
    };

    info!("Node ID: {}", identity.node_id());

    // Open database
    let db_path = format!("{}/mycelium.db", config.data_dir);
    let db_key = {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"mycelium-db-key:");
        hasher.update(identity.to_bytes());
        hasher.finalize().to_vec()
    };

    let db = Database::open(&db_path, &db_key)?;

    // Create and start node
    let node = Node::new(config, db, identity);
    node.register_transports().await;
    node.start().await?;

    info!("Mycelium node running. Press Ctrl+C to stop.");

    // Wait for shutdown signal
    tokio::signal::ctrl_c().await?;
    node.stop().await;

    info!("Mycelium node stopped.");
    Ok(())
}
