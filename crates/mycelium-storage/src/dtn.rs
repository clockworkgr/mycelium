use rusqlite::params;

use mycelium_protocol::types::{MessageId, NodeId};

use crate::db::{Database, StorageError};

/// DTN bundle database record.
#[derive(Debug, Clone)]
pub struct DtnBundleRecord {
    pub message_id: MessageId,
    pub destination: NodeId,
    pub source: NodeId,
    pub payload: Vec<u8>,
    pub copies_remaining: u8,
    pub expires_at: u64,
    pub size: usize,
}

impl Database {
    /// Store a DTN bundle.
    pub fn store_dtn_bundle(&self, bundle: &DtnBundleRecord) -> Result<(), StorageError> {
        self.conn().execute(
            "INSERT OR REPLACE INTO dtn_store
             (message_id, destination, source, payload, copies_remaining, expires_at, size)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                bundle.message_id.as_bytes().as_slice(),
                bundle.destination.as_bytes().as_slice(),
                bundle.source.as_bytes().as_slice(),
                bundle.payload,
                bundle.copies_remaining as i32,
                bundle.expires_at as i64,
                bundle.size as i64,
            ],
        )?;
        Ok(())
    }

    /// Get all DTN bundles for a destination.
    pub fn get_dtn_bundles_for(
        &self,
        destination: &NodeId,
    ) -> Result<Vec<DtnBundleRecord>, StorageError> {
        let conn = self.conn();
        let mut stmt = conn.prepare(
            "SELECT message_id, destination, source, payload, copies_remaining, expires_at, size
             FROM dtn_store WHERE destination = ?1",
        )?;

        let rows = stmt.query_map(params![destination.as_bytes().as_slice()], |row| {
            let mid_bytes: Vec<u8> = row.get(0)?;
            let dst_bytes: Vec<u8> = row.get(1)?;
            let src_bytes: Vec<u8> = row.get(2)?;
            Ok(DtnBundleRecord {
                message_id: MessageId::from_bytes(mid_bytes.try_into().unwrap_or([0; 16])),
                destination: NodeId::from_bytes(dst_bytes.try_into().unwrap_or([0; 32])),
                source: NodeId::from_bytes(src_bytes.try_into().unwrap_or([0; 32])),
                payload: row.get(3)?,
                copies_remaining: row.get::<_, i32>(4)? as u8,
                expires_at: row.get::<_, i64>(5)? as u64,
                size: row.get::<_, i64>(6)? as usize,
            })
        })?;

        let mut bundles = Vec::new();
        for row in rows {
            bundles.push(row?);
        }
        Ok(bundles)
    }

    /// Remove a DTN bundle.
    pub fn remove_dtn_bundle(&self, message_id: &MessageId) -> Result<(), StorageError> {
        self.conn().execute(
            "DELETE FROM dtn_store WHERE message_id = ?1",
            params![message_id.as_bytes().as_slice()],
        )?;
        Ok(())
    }

    /// Remove expired DTN bundles.
    pub fn expire_dtn_bundles(&self, now_secs: u64) -> Result<usize, StorageError> {
        let deleted = self.conn().execute(
            "DELETE FROM dtn_store WHERE expires_at < ?1",
            params![now_secs as i64],
        )?;
        Ok(deleted)
    }

    /// Load all DTN bundles from the database.
    pub fn list_all_dtn_bundles(&self) -> Result<Vec<DtnBundleRecord>, StorageError> {
        let conn = self.conn();
        let mut stmt = conn.prepare(
            "SELECT message_id, destination, source, payload, copies_remaining, expires_at, size
             FROM dtn_store",
        )?;

        let rows = stmt.query_map([], |row| {
            let mid_bytes: Vec<u8> = row.get(0)?;
            let dst_bytes: Vec<u8> = row.get(1)?;
            let src_bytes: Vec<u8> = row.get(2)?;
            Ok(DtnBundleRecord {
                message_id: MessageId::from_bytes(mid_bytes.try_into().unwrap_or([0; 16])),
                destination: NodeId::from_bytes(dst_bytes.try_into().unwrap_or([0; 32])),
                source: NodeId::from_bytes(src_bytes.try_into().unwrap_or([0; 32])),
                payload: row.get(3)?,
                copies_remaining: row.get::<_, i32>(4)? as u8,
                expires_at: row.get::<_, i64>(5)? as u64,
                size: row.get::<_, i64>(6)? as usize,
            })
        })?;

        let mut bundles = Vec::new();
        for row in rows {
            bundles.push(row?);
        }
        Ok(bundles)
    }

    /// Update the copies_remaining for a DTN bundle.
    pub fn update_dtn_copies(
        &self,
        message_id: &MessageId,
        copies: u8,
    ) -> Result<(), StorageError> {
        self.conn().execute(
            "UPDATE dtn_store SET copies_remaining = ?1 WHERE message_id = ?2",
            params![copies as i32, message_id.as_bytes().as_slice()],
        )?;
        Ok(())
    }

    /// Get total DTN storage used in bytes.
    pub fn dtn_storage_used(&self) -> Result<usize, StorageError> {
        let total: i64 =
            self.conn()
                .query_row("SELECT COALESCE(SUM(size), 0) FROM dtn_store", [], |row| {
                    row.get(0)
                })?;
        Ok(total as usize)
    }
}
