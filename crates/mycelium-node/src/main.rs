use std::path::Path;

use anyhow::Result;
use tracing::info;
use tracing_subscriber::EnvFilter;

use mycelium_crypto::identity::Identity;
use mycelium_storage::db::Database;

mod battery;
mod beacon;
mod config;
mod events;
mod node;
mod rate_limiter;

use config::{NodeConfig, NodeTypeConfig};
use node::Node;

fn print_usage() {
    eprintln!("Usage: mycelium-node [OPTIONS] [CONFIG_FILE]");
    eprintln!();
    eprintln!("Arguments:");
    eprintln!("  [CONFIG_FILE]   Path to TOML config file (default: mycelium.toml)");
    eprintln!();
    eprintln!("Options:");
    eprintln!("  --supernode     Run as a supernode (always-on relay, larger DTN storage)");
    eprintln!("  --data-dir DIR  Override data directory");
    eprintln!("  --port PORT     Override API server port");
    eprintln!("  --help          Print this help message");
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    // Parse CLI arguments
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut supernode = false;
    let mut config_path = "mycelium.toml".to_string();
    let mut data_dir_override: Option<String> = None;
    let mut port_override: Option<u16> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--supernode" => supernode = true,
            "--data-dir" => {
                i += 1;
                data_dir_override = Some(
                    args.get(i)
                        .ok_or_else(|| anyhow::anyhow!("--data-dir requires a value"))?
                        .clone(),
                );
            }
            "--port" => {
                i += 1;
                let port_str = args
                    .get(i)
                    .ok_or_else(|| anyhow::anyhow!("--port requires a value"))?;
                port_override = Some(
                    port_str
                        .parse()
                        .map_err(|_| anyhow::anyhow!("invalid port: {}", port_str))?,
                );
            }
            "--help" | "-h" => {
                print_usage();
                return Ok(());
            }
            arg if arg.starts_with('-') => {
                eprintln!("Unknown option: {}", arg);
                print_usage();
                std::process::exit(1);
            }
            // Positional: config file path
            _ => config_path = args[i].clone(),
        }
        i += 1;
    }

    // Load or create config
    let mut config = if Path::new(&config_path).exists() {
        NodeConfig::load(&config_path)?
    } else if supernode {
        info!("No config file found, using supernode defaults");
        NodeConfig::supernode()
    } else {
        info!("No config file found, using defaults");
        NodeConfig::default()
    };

    // Apply --supernode flag
    if supernode {
        config.node_type = NodeTypeConfig::Supernode;
        // Supernode auto-configuration: larger DTN, enable internet transport
        config.dtn.max_storage_mb = config.dtn.max_storage_mb.max(2048);
        config.dtn.per_identity_quota_mb = config.dtn.per_identity_quota_mb.max(50);
        config.transports.internet_tunnel = true;
        // Bind API on all interfaces for remote management
        config.api.bind_address = "0.0.0.0".to_string();
        info!("Running as supernode: internet transport enabled, API bound to 0.0.0.0");
    }

    // Apply CLI overrides
    if let Some(dir) = data_dir_override {
        config.data_dir = dir;
    }
    if let Some(port) = port_override {
        config.api.port = port;
    }

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
