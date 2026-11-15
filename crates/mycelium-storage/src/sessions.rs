use rusqlite::params;

use mycelium_protocol::types::{MessageId, NodeId};

use crate::db::{Database, StorageError};

/// Stored session record for a Double Ratchet session.
#[derive(Debug, Clone)]
pub struct SessionRecord {
    pub peer_id: NodeId,
    pub session_data: Vec<u8>,
    pub safety_number: Option<String>,
    pub is_verified: bool,
}

impl Database {
    /// Save or update a session.
    pub fn save_session(&self, session: &SessionRecord) -> Result<(), StorageError> {
        self.conn().execute(
            "INSERT OR REPLACE INTO sessions
             (peer_id, session_data, safety_number, is_verified, updated_at)
             VALUES (?1, ?2, ?3, ?4, strftime('%s', 'now'))",
            params![
                session.peer_id.as_bytes().as_slice(),
                session.session_data,
                session.safety_number,
                session.is_verified as i32,
            ],
        )?;
        Ok(())
    }

    /// Load a session by peer ID.
    pub fn load_session(&self, peer_id: &NodeId) -> Result<SessionRecord, StorageError> {
        self.conn()
            .query_row(
                "SELECT peer_id, session_data, safety_number, is_verified
                 FROM sessions WHERE peer_id = ?1",
                params![peer_id.as_bytes().as_slice()],
                |row| {
                    let peer_bytes: Vec<u8> = row.get(0)?;
                    Ok(SessionRecord {
                        peer_id: NodeId::from_bytes(peer_bytes.try_into().unwrap_or([0; 32])),
                        session_data: row.get(1)?,
                        safety_number: row.get(2)?,
                        is_verified: row.get::<_, i32>(3)? != 0,
                    })
                },
            )
            .map_err(|_| StorageError::NotFound)
    }

    /// List all stored sessions.
    pub fn list_sessions(&self) -> Result<Vec<SessionRecord>, StorageError> {
        let conn = self.conn();
        let mut stmt =
            conn.prepare("SELECT peer_id, session_data, safety_number, is_verified FROM sessions")?;

        let rows = stmt.query_map([], |row| {
            let peer_bytes: Vec<u8> = row.get(0)?;
            Ok(SessionRecord {
                peer_id: NodeId::from_bytes(peer_bytes.try_into().unwrap_or([0; 32])),
                session_data: row.get(1)?,
                safety_number: row.get(2)?,
                is_verified: row.get::<_, i32>(3)? != 0,
            })
        })?;

        let mut sessions = Vec::new();
        for row in rows {
            sessions.push(row?);
        }
        Ok(sessions)
    }

    /// Delete a session.
    pub fn delete_session(&self, peer_id: &NodeId) -> Result<(), StorageError> {
        self.conn().execute(
            "DELETE FROM sessions WHERE peer_id = ?1",
            params![peer_id.as_bytes().as_slice()],
        )?;
        Ok(())
    }

    /// Discard everything an abandoned handshake leaves behind: the session
    /// row, the cached prekey bundle it was built from, and the "sent" status
    /// of the messages that died with it.
    ///
    /// One transaction, because the caller keeps the in-memory handshake until
    /// this returns and retries on the next tick if it did not. Run as three
    /// separate statements, a failure part-way through committed some of them
    /// and the retry could never undo it: the session row was already gone
    /// while the live session stayed in memory, and once a receipt
    /// acknowledged that handshake the sweep stopped offering it, so nothing
    /// cleaned up the rest (ADR-015, T-41).
    ///
    /// `mark_message_failed`'s status guard is preserved: a message already
    /// received, delivered or read keeps that status.
    pub fn abandon_unconfirmed_handshake(
        &self,
        peer_id: &NodeId,
        sent: &[MessageId],
    ) -> Result<(), StorageError> {
        let conn = self.conn();
        let tx = conn.unchecked_transaction()?;
        tx.execute(
            "DELETE FROM sessions WHERE peer_id = ?1",
            params![peer_id.as_bytes().as_slice()],
        )?;
        tx.execute(
            "DELETE FROM prekey_cache WHERE node_id = ?1",
            params![peer_id.as_bytes().as_slice()],
        )?;
        for message_id in sent {
            tx.execute(
                "UPDATE messages SET status = 'failed' \
                 WHERE message_id = ?1 AND status IN ('pending', 'sent', 'dtn_pending')",
                params![message_id.as_bytes().as_slice()],
            )?;
        }
        tx.commit()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::messages::MessageRecord;

    fn a_session(peer: NodeId) -> SessionRecord {
        SessionRecord {
            peer_id: peer,
            session_data: vec![7u8; 48],
            safety_number: Some("12345".to_string()),
            is_verified: false,
        }
    }

    fn a_sent_message(peer: NodeId, id: MessageId) -> MessageRecord {
        MessageRecord {
            message_id: id,
            source: NodeId([9u8; 32]),
            destination: peer,
            content_type: "text".to_string(),
            plaintext: b"under the handshake".to_vec(),
            lamport_clock: 1,
            device_timestamp: 1000,
            status: "sent".to_string(),
            is_incoming: false,
        }
    }

    #[test]
    fn test_abandoning_a_handshake_clears_everything_it_left_behind() {
        let db = Database::open_in_memory().unwrap();
        let peer = NodeId([3u8; 32]);
        let id = MessageId::random();

        db.save_session(&a_session(peer)).unwrap();
        db.cache_prekey_bundle(peer.as_bytes(), &[1u8; 16]).unwrap();
        db.insert_message(&a_sent_message(peer, id)).unwrap();

        db.abandon_unconfirmed_handshake(&peer, &[id]).unwrap();

        assert!(
            db.load_session(&peer).is_err(),
            "session row should be gone"
        );
        assert!(
            db.get_cached_prekey_bundle(peer.as_bytes()).is_err(),
            "cached bundle should be gone"
        );
        assert_eq!(db.get_message(&id).unwrap().status, "failed");
    }

    #[test]
    fn test_abandoning_a_handshake_commits_all_or_nothing() {
        // The caller keeps the in-memory handshake when this fails and retries
        // on the next tick, so a failure must leave *nothing* committed. As
        // three independent writes the session row went first and stayed gone,
        // and a single follow-up receipt could acknowledge the handshake and
        // cancel the retry for good — a live session with no row to reload
        // (ADR-015, T-41).
        let db = Database::open_in_memory().unwrap();
        let peer = NodeId([4u8; 32]);
        let id = MessageId::random();

        db.save_session(&a_session(peer)).unwrap();
        db.cache_prekey_bundle(peer.as_bytes(), &[2u8; 16]).unwrap();

        // Make the last statement of the group fail, after the first two would
        // already have succeeded on their own.
        db.conn().execute_batch("DROP TABLE messages").unwrap();

        assert!(
            db.abandon_unconfirmed_handshake(&peer, &[id]).is_err(),
            "a failed write must be reported"
        );
        assert!(
            db.load_session(&peer).is_ok(),
            "the session row must survive a cleanup that could not finish"
        );
        assert!(
            db.get_cached_prekey_bundle(peer.as_bytes()).is_ok(),
            "the cached bundle must survive a cleanup that could not finish"
        );
    }
}
