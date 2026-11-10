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
    #[error("database key is wrong or the file is not a Mycelium database")]
    WrongKey,
}

/// Convert a BLOB column into a fixed-size array, reporting a conversion
/// error instead of panicking on a malformed row.
pub(crate) fn blob_to_array<const N: usize>(
    column: usize,
    bytes: Vec<u8>,
) -> rusqlite::Result<[u8; N]> {
    let len = bytes.len();
    bytes.try_into().map_err(|_| {
        rusqlite::Error::FromSqlConversionFailure(
            column,
            rusqlite::types::Type::Blob,
            format!("expected {} bytes, found {}", N, len).into(),
        )
    })
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

        // `cipher_version` only proves SQLCipher is linked; it never touches
        // the file. Reading the schema does, and fails with "file is not a
        // database" when the key is wrong.
        conn.pragma_query_value(None, "cipher_version", |row| row.get::<_, String>(0))
            .map_err(|_| StorageError::Migration("SQLCipher is not available".to_string()))?;
        conn.query_row("SELECT count(*) FROM sqlite_master", [], |row| {
            row.get::<_, i64>(0)
        })
        .map_err(|_| StorageError::WrongKey)?;

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

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_db_path(tag: &str) -> String {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        std::env::temp_dir()
            .join(format!(
                "mycelium-{}-{}-{}.db",
                tag,
                std::process::id(),
                nanos
            ))
            .to_string_lossy()
            .into_owned()
    }

    #[test]
    fn test_open_with_wrong_key_fails() {
        let path = temp_db_path("wrongkey");
        let key_a = [1u8; 32];
        let key_b = [2u8; 32];

        {
            let db = Database::open(&path, &key_a).expect("open with key A");
            drop(db);
        }
        // Reopening with the right key works.
        Database::open(&path, &key_a).expect("reopen with key A");
        // Reopening with a different key must be reported, not silently create
        // an empty schema or panic later.
        match Database::open(&path, &key_b) {
            Err(StorageError::WrongKey) => {}
            Err(other) => panic!("expected WrongKey, got {:?}", other),
            Ok(_) => panic!("opened with the wrong key"),
        }

        let _ = std::fs::remove_file(&path);
    }
}
