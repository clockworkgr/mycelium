//! `mycelium-node`: the standalone daemon binary.
//!
//! Runs the mesh node from `mycelium-node` and exposes the local REST +
//! WebSocket API from `mycelium-api` (ADR-001, ADR-002). Used directly on
//! desktops, in the Docker testbed, and packaged for OpenWRT supernodes.

use std::path::Path;
use std::sync::Arc;

use anyhow::Result;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

use mycelium_crypto::identity::Identity;
use mycelium_node::config::{NodeConfig, NodeTypeConfig};
use mycelium_node::node::Node;
use mycelium_storage::db::Database;

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
    eprintln!();
    eprintln!("Environment (overridden by the flags above):");
    eprintln!("  MYCELIUM_CONFIG        Config file path");
    eprintln!("  MYCELIUM_DATA_DIR      Data directory");
    eprintln!("  MYCELIUM_DISPLAY_NAME  Display name shown to peers");
    eprintln!("  MYCELIUM_PORT          API server port");
    eprintln!("  MYCELIUM_SUPERNODE     Set to 1/true to run as a supernode");
}

/// Read a non-empty environment variable.
fn env_opt(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.trim().is_empty())
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    // Environment defaults (used by the Docker testbed and container
    // deployments); CLI flags below take precedence.
    let mut supernode = env_opt("MYCELIUM_SUPERNODE")
        .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes"))
        .unwrap_or(false);
    let mut config_path = env_opt("MYCELIUM_CONFIG").unwrap_or_else(|| "mycelium.toml".to_string());
    let mut data_dir_override: Option<String> = env_opt("MYCELIUM_DATA_DIR");
    let display_name_override: Option<String> = env_opt("MYCELIUM_DISPLAY_NAME");
    let mut port_override: Option<u16> = match env_opt("MYCELIUM_PORT") {
        Some(p) => Some(
            p.trim()
                .parse()
                .map_err(|_| anyhow::anyhow!("invalid MYCELIUM_PORT: {}", p))?,
        ),
        None => None,
    };

    // Parse CLI arguments
    let args: Vec<String> = std::env::args().skip(1).collect();

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
        // Supernode auto-configuration: larger DTN, faster beacons, enable
        // internet transport (also applied on top of a loaded config file)
        config.dtn.max_storage_mb = config.dtn.max_storage_mb.max(2048);
        config.dtn.per_identity_quota_mb = config.dtn.per_identity_quota_mb.max(50);
        config.beacon_interval_secs = config.beacon_interval_secs.clamp(1, 10);
        config.transports.internet_tunnel = true;
        // Bind API on all interfaces for remote management
        config.api.bind_address = "0.0.0.0".to_string();
        info!("Running as supernode: internet transport enabled, API bound to 0.0.0.0");
    }

    // Apply CLI / environment overrides
    if let Some(dir) = data_dir_override {
        config.data_dir = dir;
    }
    if let Some(name) = display_name_override {
        config.display_name = name;
    }
    if let Some(port) = port_override {
        config.api.port = port;
    }

    // Ensure data directory exists
    std::fs::create_dir_all(&config.data_dir)?;

    // API bearer token: from the config file, else <data_dir>/api.token
    // (generated on first start, owner-readable only).
    if config.api.enabled && config.api.auth_token.is_none() {
        let token = mycelium_api::load_or_create_api_token(&config.data_dir)?;
        config.api.auth_token = Some(token);
        info!(
            "API token stored at {}/{} (clients send `Authorization: Bearer <token>`)",
            config.data_dir,
            mycelium_api::TOKEN_FILE_NAME
        );
    }

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
        write_private_file(&identity_path, &id.to_bytes())?;
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
    let api_config = config.api.clone();
    let node = Arc::new(Node::new(config, db, identity));
    node.register_transports().await;
    node.start().await?;

    // Local REST + WebSocket API (ADR-001). A bind failure is fatal when the
    // API is enabled: the daemon exists to serve clients.
    let api = if api_config.enabled {
        if api_config.bind_address != "127.0.0.1" && api_config.bind_address != "localhost" {
            warn!(
                "API bound to {}: reachable from the network, protected only by the bearer token (plain HTTP, no TLS)",
                api_config.bind_address
            );
        }
        let handle = mycelium_api::start_server(node.clone(), &api_config).await?;
        info!(
            "API server listening on {}:{}",
            api_config.bind_address, api_config.port
        );
        Some(handle)
    } else {
        info!("API server disabled by configuration");
        None
    };

    info!("Mycelium node running. Press Ctrl+C to stop.");

    // Wait for shutdown signal
    tokio::signal::ctrl_c().await?;
    if let Some(api) = api {
        api.shutdown();
    }
    node.stop().await;

    info!("Mycelium node stopped.");
    Ok(())
}

/// Write a file that only the owner may read (the identity file holds the
/// long-term private key).
fn write_private_file(path: &str, bytes: &[u8]) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        f.write_all(bytes)
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, bytes)
    }
}
