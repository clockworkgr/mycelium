use rusqlite::params;

use mycelium_protocol::types::{MessageId, NodeId};

use crate::db::{Database, StorageError};

/// Stored message record.
#[derive(Debug, Clone)]
pub struct MessageRecord {
    pub message_id: MessageId,
    pub source: NodeId,
    pub destination: NodeId,
    pub content_type: String,
    pub plaintext: Vec<u8>,
    pub lamport_clock: u64,
    pub device_timestamp: u64,
    pub status: String,
    pub is_incoming: bool,
}

impl Database {
    /// Insert a new message.
    pub fn insert_message(&self, msg: &MessageRecord) -> Result<(), StorageError> {
        self.conn().execute(
            "INSERT OR REPLACE INTO messages
             (message_id, source, destination, content_type, plaintext,
              lamport_clock, device_timestamp, status, is_incoming)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                msg.message_id.as_bytes().as_slice(),
                msg.source.as_bytes().as_slice(),
                msg.destination.as_bytes().as_slice(),
                msg.content_type,
                msg.plaintext,
                msg.lamport_clock as i64,
                msg.device_timestamp as i64,
                msg.status,
                msg.is_incoming as i32,
            ],
        )?;
        Ok(())
    }

    /// Get a message by ID.
    pub fn get_message(&self, message_id: &MessageId) -> Result<MessageRecord, StorageError> {
        let row = self.conn().query_row(
            "SELECT message_id, source, destination, content_type, plaintext,
                    lamport_clock, device_timestamp, status, is_incoming
             FROM messages WHERE message_id = ?1",
            params![message_id.as_bytes().as_slice()],
            |row| {
                let msg_id_bytes: Vec<u8> = row.get(0)?;
                let src_bytes: Vec<u8> = row.get(1)?;
                let dst_bytes: Vec<u8> = row.get(2)?;

                Ok(MessageRecord {
                    message_id: MessageId::from_bytes(msg_id_bytes.try_into().unwrap_or([0; 16])),
                    source: NodeId::from_bytes(src_bytes.try_into().unwrap_or([0; 32])),
                    destination: NodeId::from_bytes(dst_bytes.try_into().unwrap_or([0; 32])),
                    content_type: row.get(3)?,
                    plaintext: row.get(4)?,
                    lamport_clock: row.get::<_, i64>(5)? as u64,
                    device_timestamp: row.get::<_, i64>(6)? as u64,
                    status: row.get(7)?,
                    is_incoming: row.get::<_, i32>(8)? != 0,
                })
            },
        )?;
        Ok(row)
    }

    /// Update message status.
    pub fn update_message_status(
        &self,
        message_id: &MessageId,
        status: &str,
    ) -> Result<(), StorageError> {
        self.conn().execute(
            "UPDATE messages SET status = ?1 WHERE message_id = ?2",
            params![status, message_id.as_bytes().as_slice()],
        )?;
        Ok(())
    }

    /// Get conversation messages between two nodes, ordered by Lamport clock.
    pub fn get_conversation(
        &self,
        local_id: &NodeId,
        peer_id: &NodeId,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<MessageRecord>, StorageError> {
        let conn = self.conn();
        let mut stmt = conn.prepare(
            "SELECT message_id, source, destination, content_type, plaintext,
                    lamport_clock, device_timestamp, status, is_incoming
             FROM messages
             WHERE (source = ?1 AND destination = ?2) OR (source = ?2 AND destination = ?1)
             ORDER BY lamport_clock ASC, device_timestamp ASC
             LIMIT ?3 OFFSET ?4",
        )?;

        let rows = stmt.query_map(
            params![
                local_id.as_bytes().as_slice(),
                peer_id.as_bytes().as_slice(),
                limit,
                offset,
            ],
            |row| {
                let msg_id_bytes: Vec<u8> = row.get(0)?;
                let src_bytes: Vec<u8> = row.get(1)?;
                let dst_bytes: Vec<u8> = row.get(2)?;

                Ok(MessageRecord {
                    message_id: MessageId::from_bytes(msg_id_bytes.try_into().unwrap_or([0; 16])),
                    source: NodeId::from_bytes(src_bytes.try_into().unwrap_or([0; 32])),
                    destination: NodeId::from_bytes(dst_bytes.try_into().unwrap_or([0; 32])),
                    content_type: row.get(3)?,
                    plaintext: row.get(4)?,
                    lamport_clock: row.get::<_, i64>(5)? as u64,
                    device_timestamp: row.get::<_, i64>(6)? as u64,
                    status: row.get(7)?,
                    is_incoming: row.get::<_, i32>(8)? != 0,
                })
            },
        )?;

        let mut messages = Vec::new();
        for row in rows {
            messages.push(row?);
        }
        Ok(messages)
    }

    /// List all conversations for a node (unique peers with messages).
    pub fn list_conversations(
        &self,
        local_id: &NodeId,
    ) -> Result<Vec<ConversationSummaryRecord>, StorageError> {
        let conn = self.conn();
        let mut stmt = conn.prepare(
            "SELECT peer_id, MAX(device_timestamp) as last_time, COUNT(*) as msg_count,
                    SUM(CASE WHEN is_incoming = 1 AND status = 'received' THEN 1 ELSE 0 END) as unread
             FROM (
                SELECT CASE WHEN source = ?1 THEN destination ELSE source END as peer_id,
                       device_timestamp, is_incoming, status
                FROM messages
                WHERE source = ?1 OR destination = ?1
             )
             GROUP BY peer_id
             ORDER BY last_time DESC",
        )?;

        let rows = stmt.query_map(
            params![local_id.as_bytes().as_slice()],
            |row| {
                let pid_bytes: Vec<u8> = row.get(0)?;
                Ok(ConversationSummaryRecord {
                    peer_id: NodeId::from_bytes(pid_bytes.try_into().unwrap_or([0; 32])),
                    last_message_time: row.get::<_, i64>(1)? as u64,
                    message_count: row.get::<_, i64>(2)? as u32,
                    has_unread: row.get::<_, i64>(3)? > 0,
                })
            },
        )?;

        let mut result = Vec::new();
        for row in rows {
            result.push(row?);
        }
        Ok(result)
    }

    /// Mark all incoming messages from a peer as read.
    pub fn mark_messages_read(
        &self,
        local_id: &NodeId,
        peer_id: &NodeId,
    ) -> Result<usize, StorageError> {
        let updated = self.conn().execute(
            "UPDATE messages SET status = 'read'
             WHERE source = ?1 AND destination = ?2 AND is_incoming = 1 AND status = 'received'",
            params![
                peer_id.as_bytes().as_slice(),
                local_id.as_bytes().as_slice(),
            ],
        )?;
        Ok(updated)
    }

    /// Count unread incoming messages from a peer.
    pub fn unread_count(
        &self,
        local_id: &NodeId,
        peer_id: &NodeId,
    ) -> Result<u32, StorageError> {
        let count: i64 = self.conn().query_row(
            "SELECT COUNT(*) FROM messages
             WHERE source = ?1 AND destination = ?2 AND is_incoming = 1 AND status = 'received'",
            params![
                peer_id.as_bytes().as_slice(),
                local_id.as_bytes().as_slice(),
            ],
            |row| row.get(0),
        )?;
        Ok(count as u32)
    }

    /// Count total unread incoming messages across all peers.
    pub fn total_unread_count(
        &self,
        local_id: &NodeId,
    ) -> Result<u32, StorageError> {
        let count: i64 = self.conn().query_row(
            "SELECT COUNT(*) FROM messages
             WHERE destination = ?1 AND is_incoming = 1 AND status = 'received'",
            params![local_id.as_bytes().as_slice()],
            |row| row.get(0),
        )?;
        Ok(count as u32)
    }

    /// Delete all messages in a conversation between local_id and peer_id.
    pub fn delete_conversation(
        &self,
        local_id: &NodeId,
        peer_id: &NodeId,
    ) -> Result<usize, StorageError> {
        let deleted = self.conn().execute(
            "DELETE FROM messages
             WHERE (source = ?1 AND destination = ?2) OR (source = ?2 AND destination = ?1)",
            params![
                local_id.as_bytes().as_slice(),
                peer_id.as_bytes().as_slice(),
            ],
        )?;
        Ok(deleted)
    }
}

/// Summary of a conversation with a peer.
#[derive(Debug, Clone)]
pub struct ConversationSummaryRecord {
    pub peer_id: NodeId,
    pub last_message_time: u64,
    pub message_count: u32,
    pub has_unread: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_crud() {
        let db = Database::open_in_memory().unwrap();

        let msg = MessageRecord {
            message_id: MessageId::random(),
            source: NodeId([1u8; 32]),
            destination: NodeId([2u8; 32]),
            content_type: "text".to_string(),
            plaintext: b"hello world".to_vec(),
            lamport_clock: 1,
            device_timestamp: 1000,
            status: "sent".to_string(),
            is_incoming: false,
        };

        db.insert_message(&msg).unwrap();

        let retrieved = db.get_message(&msg.message_id).unwrap();
        assert_eq!(retrieved.plaintext, b"hello world");
        assert_eq!(retrieved.status, "sent");

        db.update_message_status(&msg.message_id, "delivered")
            .unwrap();
        let updated = db.get_message(&msg.message_id).unwrap();
        assert_eq!(updated.status, "delivered");
    }

    #[test]
    fn test_mark_read_and_unread_count() {
        let db = Database::open_in_memory().unwrap();
        let alice = NodeId([1u8; 32]);
        let bob = NodeId([2u8; 32]);

        // Insert 3 incoming messages with "received" status
        for i in 0..3 {
            let msg = MessageRecord {
                message_id: MessageId::random(),
                source: bob,
                destination: alice,
                content_type: "text".to_string(),
                plaintext: format!("msg {}", i).into_bytes(),
                lamport_clock: i as u64,
                device_timestamp: 1000 + i as u64,
                status: "received".to_string(),
                is_incoming: true,
            };
            db.insert_message(&msg).unwrap();
        }

        // Insert 1 outgoing (should not count as unread)
        let out_msg = MessageRecord {
            message_id: MessageId::random(),
            source: alice,
            destination: bob,
            content_type: "text".to_string(),
            plaintext: b"outgoing".to_vec(),
            lamport_clock: 3,
            device_timestamp: 1003,
            status: "sent".to_string(),
            is_incoming: false,
        };
        db.insert_message(&out_msg).unwrap();

        assert_eq!(db.unread_count(&alice, &bob).unwrap(), 3);
        assert_eq!(db.total_unread_count(&alice).unwrap(), 3);

        let marked = db.mark_messages_read(&alice, &bob).unwrap();
        assert_eq!(marked, 3);

        assert_eq!(db.unread_count(&alice, &bob).unwrap(), 0);
        assert_eq!(db.total_unread_count(&alice).unwrap(), 0);
    }

    #[test]
    fn test_conversation_query() {
        let db = Database::open_in_memory().unwrap();
        let alice = NodeId([1u8; 32]);
        let bob = NodeId([2u8; 32]);

        for i in 0..5 {
            let msg = MessageRecord {
                message_id: MessageId::random(),
                source: if i % 2 == 0 { alice } else { bob },
                destination: if i % 2 == 0 { bob } else { alice },
                content_type: "text".to_string(),
                plaintext: format!("message {}", i).into_bytes(),
                lamport_clock: i as u64,
                device_timestamp: 1000 + i as u64,
                status: "delivered".to_string(),
                is_incoming: i % 2 != 0,
            };
            db.insert_message(&msg).unwrap();
        }

        let conversation = db.get_conversation(&alice, &bob, 100, 0).unwrap();
        assert_eq!(conversation.len(), 5);
        // Should be ordered by lamport clock
        assert_eq!(conversation[0].lamport_clock, 0);
        assert_eq!(conversation[4].lamport_clock, 4);
    }
}
