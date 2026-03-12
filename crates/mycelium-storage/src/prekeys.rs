use rusqlite::params;

use crate::db::{Database, StorageError};

/// Prekey record stored in database.
#[derive(Debug, Clone)]
pub struct PrekeyRecord {
    pub prekey_id: u32,
    pub prekey_type: String, // "signed" or "one_time"
    pub secret_key: Vec<u8>,
    pub public_key: Vec<u8>,
    pub used: bool,
}

impl Database {
    /// Store a prekey.
    pub fn store_prekey(&self, prekey: &PrekeyRecord) -> Result<(), StorageError> {
        self.conn().execute(
            "INSERT OR REPLACE INTO our_prekeys
             (prekey_id, prekey_type, secret_key, public_key, used)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                prekey.prekey_id,
                prekey.prekey_type,
                prekey.secret_key,
                prekey.public_key,
                prekey.used as i32,
            ],
        )?;
        Ok(())
    }

    /// Get an unused one-time prekey.
    pub fn get_unused_one_time_prekey(&self) -> Result<PrekeyRecord, StorageError> {
        self.conn()
            .query_row(
                "SELECT prekey_id, prekey_type, secret_key, public_key, used
                 FROM our_prekeys
                 WHERE prekey_type = 'one_time' AND used = 0
                 LIMIT 1",
                [],
                |row| {
                    Ok(PrekeyRecord {
                        prekey_id: row.get(0)?,
                        prekey_type: row.get(1)?,
                        secret_key: row.get(2)?,
                        public_key: row.get(3)?,
                        used: row.get::<_, i32>(4)? != 0,
                    })
                },
            )
            .map_err(|_| StorageError::NotFound)
    }

    /// Mark a prekey as used.
    pub fn mark_prekey_used(&self, prekey_id: u32) -> Result<(), StorageError> {
        self.conn().execute(
            "UPDATE our_prekeys SET used = 1 WHERE prekey_id = ?1",
            params![prekey_id],
        )?;
        Ok(())
    }

    /// Count available one-time prekeys.
    pub fn count_unused_one_time_prekeys(&self) -> Result<u32, StorageError> {
        let count: i64 = self.conn().query_row(
            "SELECT COUNT(*) FROM our_prekeys WHERE prekey_type = 'one_time' AND used = 0",
            [],
            |row| row.get(0),
        )?;
        Ok(count as u32)
    }

    /// Store a cached prekey bundle for a remote node.
    pub fn cache_prekey_bundle(
        &self,
        node_id: &[u8],
        bundle_data: &[u8],
    ) -> Result<(), StorageError> {
        self.conn().execute(
            "INSERT OR REPLACE INTO prekey_cache
             (node_id, bundle_data, fetched_at)
             VALUES (?1, ?2, strftime('%s', 'now'))",
            params![node_id, bundle_data],
        )?;
        Ok(())
    }

    /// Get a cached prekey bundle for a remote node.
    pub fn get_cached_prekey_bundle(&self, node_id: &[u8]) -> Result<Vec<u8>, StorageError> {
        self.conn()
            .query_row(
                "SELECT bundle_data FROM prekey_cache WHERE node_id = ?1",
                params![node_id],
                |row| row.get(0),
            )
            .map_err(|_| StorageError::NotFound)
    }

    /// List all cached prekey bundles (node_id, bundle_data).
    #[allow(clippy::type_complexity)]
    pub fn list_cached_prekey_bundles(&self) -> Result<Vec<(Vec<u8>, Vec<u8>)>, StorageError> {
        let conn = self.conn();
        let mut stmt = conn.prepare("SELECT node_id, bundle_data FROM prekey_cache")?;
        let rows = stmt.query_map([], |row| {
            Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?))
        })?;
        let mut result = Vec::new();
        for row in rows {
            result.push(row?);
        }
        Ok(result)
    }

    /// Remove a cached prekey bundle for a remote node.
    pub fn remove_cached_prekey_bundle(&self, node_id: &[u8]) -> Result<(), StorageError> {
        self.conn().execute(
            "DELETE FROM prekey_cache WHERE node_id = ?1",
            params![node_id],
        )?;
        Ok(())
    }

    /// Save the serialized prekey state blob to the config table.
    pub fn save_prekey_state_blob(&self, data: &[u8]) -> Result<(), StorageError> {
        self.conn().execute(
            "INSERT OR REPLACE INTO config (key, value) VALUES ('prekey_state', ?1)",
            params![data],
        )?;
        Ok(())
    }

    /// Load the serialized prekey state blob from the config table.
    pub fn load_prekey_state_blob(&self) -> Result<Vec<u8>, StorageError> {
        self.conn()
            .query_row(
                "SELECT value FROM config WHERE key = 'prekey_state'",
                [],
                |row| row.get(0),
            )
            .map_err(|_| StorageError::NotFound)
    }
}
