use rusqlite::params;

use mycelium_protocol::types::NodeId;

use crate::db::{Database, StorageError};

/// Summary of a channel for listing.
#[derive(Debug, Clone)]
pub struct ChannelInfo {
    pub channel_id: [u8; 32],
    pub name: String,
    pub creator_id: NodeId,
    pub created_at: u64,
}

/// A message posted to a channel.
#[derive(Debug, Clone)]
pub struct ChannelMessageInfo {
    pub message_id: [u8; 16],
    pub channel_id: [u8; 32],
    pub source: NodeId,
    pub data: Vec<u8>,
    pub content_type: u8,
    pub timestamp: u64,
}

impl Database {
    /// Create a new channel.
    pub fn create_channel(
        &self,
        channel_id: &[u8; 32],
        name: &str,
        creator_id: &NodeId,
    ) -> Result<(), StorageError> {
        self.conn().execute(
            "INSERT OR IGNORE INTO channels (channel_id, name, creator_id) VALUES (?1, ?2, ?3)",
            params![
                channel_id.as_slice(),
                name,
                creator_id.as_bytes().as_slice()
            ],
        )?;
        Ok(())
    }

    /// Get a channel by ID.
    pub fn get_channel(&self, channel_id: &[u8; 32]) -> Result<ChannelInfo, StorageError> {
        let conn = self.conn();
        conn.query_row(
            "SELECT channel_id, name, creator_id, created_at FROM channels WHERE channel_id = ?1",
            params![channel_id.as_slice()],
            |row| {
                let cid: Vec<u8> = row.get(0)?;
                let name: String = row.get(1)?;
                let creator: Vec<u8> = row.get(2)?;
                let created_at: u64 = row.get(3)?;
                let mut channel_id = [0u8; 32];
                channel_id.copy_from_slice(&cid);
                let mut creator_bytes = [0u8; 32];
                creator_bytes.copy_from_slice(&creator);
                Ok(ChannelInfo {
                    channel_id,
                    name,
                    creator_id: NodeId(creator_bytes),
                    created_at,
                })
            },
        )
        .map_err(|_| StorageError::NotFound)
    }

    /// List all known channels.
    pub fn list_channels(&self) -> Result<Vec<ChannelInfo>, StorageError> {
        let conn = self.conn();
        let mut stmt = conn.prepare(
            "SELECT channel_id, name, creator_id, created_at FROM channels ORDER BY created_at DESC",
        )?;
        let rows = stmt.query_map([], |row| {
            let cid: Vec<u8> = row.get(0)?;
            let name: String = row.get(1)?;
            let creator: Vec<u8> = row.get(2)?;
            let created_at: u64 = row.get(3)?;
            let mut channel_id = [0u8; 32];
            channel_id.copy_from_slice(&cid);
            let mut creator_bytes = [0u8; 32];
            creator_bytes.copy_from_slice(&creator);
            Ok(ChannelInfo {
                channel_id,
                name,
                creator_id: NodeId(creator_bytes),
                created_at,
            })
        })?;
        let mut result = Vec::new();
        for row in rows {
            result.push(row?);
        }
        Ok(result)
    }

    /// Subscribe to a channel.
    pub fn subscribe_channel(&self, channel_id: &[u8; 32]) -> Result<(), StorageError> {
        self.conn().execute(
            "INSERT OR IGNORE INTO channel_subscriptions (channel_id) VALUES (?1)",
            params![channel_id.as_slice()],
        )?;
        Ok(())
    }

    /// Unsubscribe from a channel.
    pub fn unsubscribe_channel(&self, channel_id: &[u8; 32]) -> Result<(), StorageError> {
        self.conn().execute(
            "DELETE FROM channel_subscriptions WHERE channel_id = ?1",
            params![channel_id.as_slice()],
        )?;
        Ok(())
    }

    /// Check if subscribed to a channel.
    pub fn is_subscribed(&self, channel_id: &[u8; 32]) -> Result<bool, StorageError> {
        let conn = self.conn();
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM channel_subscriptions WHERE channel_id = ?1",
            params![channel_id.as_slice()],
            |row| row.get(0),
        )?;
        Ok(count > 0)
    }

    /// List subscribed channel IDs.
    pub fn list_subscriptions(&self) -> Result<Vec<[u8; 32]>, StorageError> {
        let conn = self.conn();
        let mut stmt = conn.prepare("SELECT channel_id FROM channel_subscriptions")?;
        let rows = stmt.query_map([], |row| {
            let cid: Vec<u8> = row.get(0)?;
            let mut channel_id = [0u8; 32];
            channel_id.copy_from_slice(&cid);
            Ok(channel_id)
        })?;
        let mut result = Vec::new();
        for row in rows {
            result.push(row?);
        }
        Ok(result)
    }

    /// Store a channel message.
    pub fn store_channel_message(
        &self,
        message_id: &[u8; 16],
        channel_id: &[u8; 32],
        source: &NodeId,
        data: &[u8],
        content_type: u8,
        timestamp: u64,
    ) -> Result<(), StorageError> {
        self.conn().execute(
            "INSERT OR IGNORE INTO channel_messages \
             (message_id, channel_id, source, data, content_type, timestamp) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                message_id.as_slice(),
                channel_id.as_slice(),
                source.as_bytes().as_slice(),
                data,
                content_type as i64,
                timestamp as i64,
            ],
        )?;
        Ok(())
    }

    /// Get channel messages, ordered by timestamp descending.
    pub fn get_channel_messages(
        &self,
        channel_id: &[u8; 32],
        limit: u32,
        offset: u32,
    ) -> Result<Vec<ChannelMessageInfo>, StorageError> {
        let conn = self.conn();
        let mut stmt = conn.prepare(
            "SELECT message_id, channel_id, source, data, content_type, timestamp \
             FROM channel_messages WHERE channel_id = ?1 \
             ORDER BY timestamp DESC LIMIT ?2 OFFSET ?3",
        )?;
        let rows = stmt.query_map(params![channel_id.as_slice(), limit, offset], |row| {
            let mid: Vec<u8> = row.get(0)?;
            let cid: Vec<u8> = row.get(1)?;
            let src: Vec<u8> = row.get(2)?;
            let data: Vec<u8> = row.get(3)?;
            let ct: i64 = row.get(4)?;
            let ts: u64 = row.get(5)?;
            let mut message_id = [0u8; 16];
            message_id.copy_from_slice(&mid);
            let mut channel_id = [0u8; 32];
            channel_id.copy_from_slice(&cid);
            let mut source_bytes = [0u8; 32];
            source_bytes.copy_from_slice(&src);
            Ok(ChannelMessageInfo {
                message_id,
                channel_id,
                source: NodeId(source_bytes),
                data,
                content_type: ct as u8,
                timestamp: ts,
            })
        })?;
        let mut result = Vec::new();
        for row in rows {
            result.push(row?);
        }
        Ok(result)
    }

    /// Delete a channel and all its messages and subscriptions.
    pub fn delete_channel(&self, channel_id: &[u8; 32]) -> Result<(), StorageError> {
        let conn = self.conn();
        conn.execute(
            "DELETE FROM channel_messages WHERE channel_id = ?1",
            params![channel_id.as_slice()],
        )?;
        conn.execute(
            "DELETE FROM channel_subscriptions WHERE channel_id = ?1",
            params![channel_id.as_slice()],
        )?;
        conn.execute(
            "DELETE FROM channels WHERE channel_id = ?1",
            params![channel_id.as_slice()],
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_db() -> Database {
        Database::open_in_memory().unwrap()
    }

    #[test]
    fn test_channel_crud() {
        let db = test_db();
        let channel_id = [0xAA; 32];
        let creator = NodeId([1u8; 32]);

        // Create
        db.create_channel(&channel_id, "test-channel", &creator)
            .unwrap();

        // Get
        let ch = db.get_channel(&channel_id).unwrap();
        assert_eq!(ch.name, "test-channel");
        assert_eq!(ch.creator_id, creator);

        // List
        let channels = db.list_channels().unwrap();
        assert_eq!(channels.len(), 1);
        assert_eq!(channels[0].name, "test-channel");

        // Delete
        db.delete_channel(&channel_id).unwrap();
        assert!(db.get_channel(&channel_id).is_err());
    }

    #[test]
    fn test_channel_subscriptions() {
        let db = test_db();
        let channel_id = [0xBB; 32];
        let creator = NodeId([2u8; 32]);

        db.create_channel(&channel_id, "sub-test", &creator)
            .unwrap();

        // Initially not subscribed
        assert!(!db.is_subscribed(&channel_id).unwrap());
        assert_eq!(db.list_subscriptions().unwrap().len(), 0);

        // Subscribe
        db.subscribe_channel(&channel_id).unwrap();
        assert!(db.is_subscribed(&channel_id).unwrap());
        assert_eq!(db.list_subscriptions().unwrap().len(), 1);

        // Double subscribe is idempotent
        db.subscribe_channel(&channel_id).unwrap();
        assert_eq!(db.list_subscriptions().unwrap().len(), 1);

        // Unsubscribe
        db.unsubscribe_channel(&channel_id).unwrap();
        assert!(!db.is_subscribed(&channel_id).unwrap());
    }

    #[test]
    fn test_channel_messages() {
        let db = test_db();
        let channel_id = [0xCC; 32];
        let creator = NodeId([3u8; 32]);
        let sender = NodeId([4u8; 32]);

        db.create_channel(&channel_id, "msg-test", &creator)
            .unwrap();

        // Store messages
        let msg1 = [1u8; 16];
        let msg2 = [2u8; 16];
        db.store_channel_message(&msg1, &channel_id, &sender, b"hello", 0, 1000)
            .unwrap();
        db.store_channel_message(&msg2, &channel_id, &sender, b"world", 0, 2000)
            .unwrap();

        // Get messages (newest first)
        let msgs = db.get_channel_messages(&channel_id, 50, 0).unwrap();
        assert_eq!(msgs.len(), 2);
        assert_eq!(msgs[0].timestamp, 2000);
        assert_eq!(msgs[0].data, b"world");
        assert_eq!(msgs[1].timestamp, 1000);
        assert_eq!(msgs[1].data, b"hello");

        // Pagination
        let page = db.get_channel_messages(&channel_id, 1, 0).unwrap();
        assert_eq!(page.len(), 1);
        assert_eq!(page[0].timestamp, 2000);

        // Duplicate message_id is ignored
        db.store_channel_message(&msg1, &channel_id, &sender, b"duplicate", 0, 3000)
            .unwrap();
        let all = db.get_channel_messages(&channel_id, 50, 0).unwrap();
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn test_delete_channel_cascades() {
        let db = test_db();
        let channel_id = [0xDD; 32];
        let creator = NodeId([5u8; 32]);
        let sender = NodeId([6u8; 32]);

        db.create_channel(&channel_id, "cascade", &creator).unwrap();
        db.subscribe_channel(&channel_id).unwrap();
        db.store_channel_message(&[7u8; 16], &channel_id, &sender, b"msg", 0, 1000)
            .unwrap();

        db.delete_channel(&channel_id).unwrap();

        assert!(!db.is_subscribed(&channel_id).unwrap());
        assert_eq!(
            db.get_channel_messages(&channel_id, 50, 0).unwrap().len(),
            0
        );
        assert!(db.get_channel(&channel_id).is_err());
    }
}
