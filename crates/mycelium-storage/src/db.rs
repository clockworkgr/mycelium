use std::sync::Mutex;

use rusqlite::Connection;
use thiserror::Error;
use tracing::info;

use crate::migrations;

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),
    #[error("migration error: {0}")]
    Migration(String),
    #[error("not found")]
    NotFound,
    #[error("serialization error: {0}")]
    Serialization(String),
}

/// SQLCipher-encrypted database handle.
///
/// Wraps `Connection` in a `Mutex` to satisfy `Send + Sync` requirements
/// for use across async tasks (rusqlite's Connection is `Send` but not `Sync`).
pub struct Database {
    conn: Mutex<Connection>,
}

impl Database {
    /// Open (or create) an encrypted database at the given path.
    pub fn open(path: &str, encryption_key: &[u8]) -> Result<Self, StorageError> {
        let conn = Connection::open(path)?;

        // Set SQLCipher encryption key
        let hex_key = encryption_key
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>();
        conn.pragma_update(None, "key", format!("x'{}'", hex_key))?;

        // Verify the database is accessible (will fail if key is wrong)
        conn.pragma_query_value(None, "cipher_version", |row| row.get::<_, String>(0))
            .map_err(|_| StorageError::Migration("Failed to verify SQLCipher key".to_string()))?;

        let mut db = Self {
            conn: Mutex::new(conn),
        };
        db.run_migrations()?;
        info!("Database opened successfully at {}", path);
        Ok(db)
    }

    /// Open an in-memory database (for testing).
    pub fn open_in_memory() -> Result<Self, StorageError> {
        let conn = Connection::open_in_memory()?;
        let mut db = Self {
            conn: Mutex::new(conn),
        };
        db.run_migrations()?;
        Ok(db)
    }

    /// Get a reference to the underlying connection.
    pub fn conn(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.conn.lock().expect("database mutex poisoned")
    }

    fn run_migrations(&mut self) -> Result<(), StorageError> {
        let conn = self.conn.lock().expect("database mutex poisoned");
        migrations::run_all(&conn)
    }
}
