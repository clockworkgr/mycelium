use rusqlite::params;

use mycelium_protocol::types::NodeId;

use crate::db::{Database, StorageError};

/// Stored contact record.
#[derive(Debug, Clone)]
pub struct ContactRecord {
    pub node_id: NodeId,
    pub display_name: String,
    pub public_key: Vec<u8>,
    pub trust_score: f32,
    pub is_verified: bool,
    pub last_seen: Option<u64>,
}

impl Database {
    /// Save or update a contact.
    pub fn save_contact(&self, contact: &ContactRecord) -> Result<(), StorageError> {
        self.conn().execute(
            "INSERT OR REPLACE INTO contacts
             (node_id, display_name, public_key, trust_score, is_verified, last_seen)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                contact.node_id.as_bytes().as_slice(),
                contact.display_name,
                contact.public_key,
                contact.trust_score as f64,
                contact.is_verified as i32,
                contact.last_seen.map(|t| t as i64),
            ],
        )?;
        Ok(())
    }

    /// Get a contact by node ID.
    pub fn get_contact(&self, node_id: &NodeId) -> Result<ContactRecord, StorageError> {
        self.conn()
            .query_row(
                "SELECT node_id, display_name, public_key, trust_score, is_verified, last_seen
                 FROM contacts WHERE node_id = ?1",
                params![node_id.as_bytes().as_slice()],
                |row| {
                    let nid_bytes: Vec<u8> = row.get(0)?;
                    Ok(ContactRecord {
                        node_id: NodeId::from_bytes(nid_bytes.try_into().unwrap_or([0; 32])),
                        display_name: row.get(1)?,
                        public_key: row.get(2)?,
                        trust_score: row.get::<_, f64>(3)? as f32,
                        is_verified: row.get::<_, i32>(4)? != 0,
                        last_seen: row.get::<_, Option<i64>>(5)?.map(|t| t as u64),
                    })
                },
            )
            .map_err(|_| StorageError::NotFound)
    }

    /// List all contacts.
    pub fn list_contacts(&self) -> Result<Vec<ContactRecord>, StorageError> {
        let conn = self.conn();
        let mut stmt = conn.prepare(
            "SELECT node_id, display_name, public_key, trust_score, is_verified, last_seen
             FROM contacts ORDER BY display_name",
        )?;

        let rows = stmt.query_map([], |row| {
            let nid_bytes: Vec<u8> = row.get(0)?;
            Ok(ContactRecord {
                node_id: NodeId::from_bytes(nid_bytes.try_into().unwrap_or([0; 32])),
                display_name: row.get(1)?,
                public_key: row.get(2)?,
                trust_score: row.get::<_, f64>(3)? as f32,
                is_verified: row.get::<_, i32>(4)? != 0,
                last_seen: row.get::<_, Option<i64>>(5)?.map(|t| t as u64),
            })
        })?;

        let mut contacts = Vec::new();
        for row in rows {
            contacts.push(row?);
        }
        Ok(contacts)
    }
}
