use rusqlite::params;

use mycelium_protocol::types::NodeId;

use crate::db::{Database, StorageError};

/// Stored vouch record for Web of Trust.
#[derive(Debug, Clone)]
pub struct VouchRecord {
    pub voucher_id: NodeId,
    pub vouchee_id: NodeId,
    pub voucher_public_key: Vec<u8>,
    pub display_name: String,
    pub signature: Vec<u8>,
    pub timestamp: u64,
}

impl Database {
    /// Save a vouch (insert or replace).
    pub fn save_vouch(&self, vouch: &VouchRecord) -> Result<(), StorageError> {
        self.conn().execute(
            "INSERT OR REPLACE INTO vouches
             (voucher_id, vouchee_id, voucher_public_key, display_name, signature, timestamp)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                vouch.voucher_id.as_bytes().as_slice(),
                vouch.vouchee_id.as_bytes().as_slice(),
                vouch.voucher_public_key,
                vouch.display_name,
                vouch.signature,
                vouch.timestamp as i64,
            ],
        )?;
        Ok(())
    }

    /// Get all vouches made by a given voucher.
    pub fn get_vouches_by(&self, voucher_id: &NodeId) -> Result<Vec<VouchRecord>, StorageError> {
        let conn = self.conn();
        let mut stmt = conn.prepare(
            "SELECT voucher_id, vouchee_id, voucher_public_key, display_name, signature, timestamp
             FROM vouches WHERE voucher_id = ?1",
        )?;

        let rows = stmt.query_map(params![voucher_id.as_bytes().as_slice()], |row| {
            let voucher_bytes: Vec<u8> = row.get(0)?;
            let vouchee_bytes: Vec<u8> = row.get(1)?;
            Ok(VouchRecord {
                voucher_id: NodeId::from_bytes(voucher_bytes.try_into().unwrap_or([0; 32])),
                vouchee_id: NodeId::from_bytes(vouchee_bytes.try_into().unwrap_or([0; 32])),
                voucher_public_key: row.get(2)?,
                display_name: row.get(3)?,
                signature: row.get(4)?,
                timestamp: row.get::<_, i64>(5)? as u64,
            })
        })?;

        let mut vouches = Vec::new();
        for row in rows {
            vouches.push(row?);
        }
        Ok(vouches)
    }

    /// Get all vouches for a given vouchee.
    pub fn get_vouches_for(&self, vouchee_id: &NodeId) -> Result<Vec<VouchRecord>, StorageError> {
        let conn = self.conn();
        let mut stmt = conn.prepare(
            "SELECT voucher_id, vouchee_id, voucher_public_key, display_name, signature, timestamp
             FROM vouches WHERE vouchee_id = ?1",
        )?;

        let rows = stmt.query_map(params![vouchee_id.as_bytes().as_slice()], |row| {
            let voucher_bytes: Vec<u8> = row.get(0)?;
            let vouchee_bytes: Vec<u8> = row.get(1)?;
            Ok(VouchRecord {
                voucher_id: NodeId::from_bytes(voucher_bytes.try_into().unwrap_or([0; 32])),
                vouchee_id: NodeId::from_bytes(vouchee_bytes.try_into().unwrap_or([0; 32])),
                voucher_public_key: row.get(2)?,
                display_name: row.get(3)?,
                signature: row.get(4)?,
                timestamp: row.get::<_, i64>(5)? as u64,
            })
        })?;

        let mut vouches = Vec::new();
        for row in rows {
            vouches.push(row?);
        }
        Ok(vouches)
    }

    /// List all vouches in the database.
    pub fn list_all_vouches(&self) -> Result<Vec<VouchRecord>, StorageError> {
        let conn = self.conn();
        let mut stmt = conn.prepare(
            "SELECT voucher_id, vouchee_id, voucher_public_key, display_name, signature, timestamp
             FROM vouches ORDER BY timestamp",
        )?;

        let rows = stmt.query_map([], |row| {
            let voucher_bytes: Vec<u8> = row.get(0)?;
            let vouchee_bytes: Vec<u8> = row.get(1)?;
            Ok(VouchRecord {
                voucher_id: NodeId::from_bytes(voucher_bytes.try_into().unwrap_or([0; 32])),
                vouchee_id: NodeId::from_bytes(vouchee_bytes.try_into().unwrap_or([0; 32])),
                voucher_public_key: row.get(2)?,
                display_name: row.get(3)?,
                signature: row.get(4)?,
                timestamp: row.get::<_, i64>(5)? as u64,
            })
        })?;

        let mut vouches = Vec::new();
        for row in rows {
            vouches.push(row?);
        }
        Ok(vouches)
    }

    /// Remove a vouch.
    pub fn remove_vouch(
        &self,
        voucher_id: &NodeId,
        vouchee_id: &NodeId,
    ) -> Result<(), StorageError> {
        self.conn().execute(
            "DELETE FROM vouches WHERE voucher_id = ?1 AND vouchee_id = ?2",
            params![
                voucher_id.as_bytes().as_slice(),
                vouchee_id.as_bytes().as_slice(),
            ],
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vouch_crud() {
        let db = Database::open_in_memory().unwrap();

        let voucher = NodeId([1u8; 32]);
        let vouchee = NodeId([2u8; 32]);

        let vouch = VouchRecord {
            voucher_id: voucher,
            vouchee_id: vouchee,
            voucher_public_key: vec![0xAA; 32],
            display_name: "Bob".to_string(),
            signature: vec![0xBB; 64],
            timestamp: 1000,
        };

        db.save_vouch(&vouch).unwrap();

        let by_voucher = db.get_vouches_by(&voucher).unwrap();
        assert_eq!(by_voucher.len(), 1);
        assert_eq!(by_voucher[0].display_name, "Bob");
        assert_eq!(by_voucher[0].vouchee_id, vouchee);

        let for_vouchee = db.get_vouches_for(&vouchee).unwrap();
        assert_eq!(for_vouchee.len(), 1);
        assert_eq!(for_vouchee[0].voucher_id, voucher);

        let all = db.list_all_vouches().unwrap();
        assert_eq!(all.len(), 1);

        db.remove_vouch(&voucher, &vouchee).unwrap();
        let after = db.list_all_vouches().unwrap();
        assert_eq!(after.len(), 0);
    }

    #[test]
    fn test_multiple_vouches() {
        let db = Database::open_in_memory().unwrap();

        let alice = NodeId([1u8; 32]);
        let bob = NodeId([2u8; 32]);
        let carol = NodeId([3u8; 32]);

        db.save_vouch(&VouchRecord {
            voucher_id: alice,
            vouchee_id: bob,
            voucher_public_key: vec![0xAA; 32],
            display_name: "Bob".to_string(),
            signature: vec![0xBB; 64],
            timestamp: 1000,
        })
        .unwrap();

        db.save_vouch(&VouchRecord {
            voucher_id: alice,
            vouchee_id: carol,
            voucher_public_key: vec![0xAA; 32],
            display_name: "Carol".to_string(),
            signature: vec![0xCC; 64],
            timestamp: 1001,
        })
        .unwrap();

        let by_alice = db.get_vouches_by(&alice).unwrap();
        assert_eq!(by_alice.len(), 2);

        let for_bob = db.get_vouches_for(&bob).unwrap();
        assert_eq!(for_bob.len(), 1);
    }
}
