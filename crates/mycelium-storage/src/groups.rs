use rusqlite::params;

use crate::db::{Database, StorageError};

fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

impl Database {
    /// Save a serialized group state blob.
    pub fn save_group_blob(&self, group_id: &[u8; 32], data: &[u8]) -> Result<(), StorageError> {
        let key = format!("group:{}", bytes_to_hex(group_id));
        self.conn().execute(
            "INSERT OR REPLACE INTO config (key, value) VALUES (?1, ?2)",
            params![key, data],
        )?;
        Ok(())
    }

    /// Load a serialized group state blob.
    pub fn load_group_blob(&self, group_id: &[u8; 32]) -> Result<Vec<u8>, StorageError> {
        let key = format!("group:{}", bytes_to_hex(group_id));
        self.conn()
            .query_row(
                "SELECT value FROM config WHERE key = ?1",
                params![key],
                |row| row.get(0),
            )
            .map_err(|_| StorageError::NotFound)
    }

    /// List all saved group blobs. Returns (key_suffix, data) pairs.
    pub fn list_group_blobs(&self) -> Result<Vec<Vec<u8>>, StorageError> {
        let conn = self.conn();
        let mut stmt = conn.prepare("SELECT value FROM config WHERE key LIKE 'group:%'")?;
        let rows = stmt.query_map([], |row| {
            row.get::<_, Vec<u8>>(0)
        })?;
        let mut result = Vec::new();
        for row in rows {
            result.push(row?);
        }
        Ok(result)
    }

    /// Remove a saved group blob.
    pub fn remove_group_blob(&self, group_id: &[u8; 32]) -> Result<(), StorageError> {
        let key = format!("group:{}", bytes_to_hex(group_id));
        self.conn().execute(
            "DELETE FROM config WHERE key = ?1",
            params![key],
        )?;
        Ok(())
    }
}
