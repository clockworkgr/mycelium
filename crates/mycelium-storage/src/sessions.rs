use rusqlite::params;

use mycelium_protocol::types::NodeId;

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
}
