use rusqlite::params;

use mycelium_protocol::types::{MessageId, NodeId};

use crate::db::{blob_to_array, Database, StorageError};

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
    /// True when this node originated the bundle. Eviction protects local
    /// bundles from being displaced by relay traffic, so the flag has to
    /// survive a restart (ROADMAP T-11).
    pub is_local: bool,
    /// Peers that already hold a copy, so a restart does not spend spray
    /// copies on them again.
    pub sprayed_to: Vec<NodeId>,
}

/// Columns selected by every bundle query, in the order the row mapper expects.
const BUNDLE_COLUMNS: &str = "message_id, destination, source, payload, \
                              copies_remaining, expires_at, size, is_local, sprayed_to";

/// Pack NodeIds into a single BLOB of 32-byte records.
fn pack_node_ids(ids: &[NodeId]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(ids.len() * 32);
    for id in ids {
        buf.extend_from_slice(id.as_bytes());
    }
    buf
}

/// Unpack a BLOB written by [`pack_node_ids`]. A trailing partial record is
/// ignored rather than treated as a zero NodeId: `NodeId::ZERO` is the
/// broadcast address, so inventing one from a truncated row would be worse
/// than dropping it.
fn unpack_node_ids(bytes: &[u8]) -> Vec<NodeId> {
    bytes
        .chunks_exact(32)
        .map(|chunk| {
            let mut id = [0u8; 32];
            id.copy_from_slice(chunk);
            NodeId::from_bytes(id)
        })
        .collect()
}

fn row_to_bundle(row: &rusqlite::Row<'_>) -> rusqlite::Result<DtnBundleRecord> {
    let mid_bytes: Vec<u8> = row.get(0)?;
    let dst_bytes: Vec<u8> = row.get(1)?;
    let src_bytes: Vec<u8> = row.get(2)?;
    let sprayed: Vec<u8> = row.get(8)?;
    Ok(DtnBundleRecord {
        // A malformed id is a conversion error, not a zero id. The previous
        // `unwrap_or([0; 32])` turned a corrupt destination row into a bundle
        // addressed to the broadcast address.
        message_id: MessageId::from_bytes(blob_to_array(0, mid_bytes)?),
        destination: NodeId::from_bytes(blob_to_array(1, dst_bytes)?),
        source: NodeId::from_bytes(blob_to_array(2, src_bytes)?),
        payload: row.get(3)?,
        copies_remaining: row.get::<_, i32>(4)? as u8,
        expires_at: row.get::<_, i64>(5)? as u64,
        size: row.get::<_, i64>(6)? as usize,
        is_local: row.get::<_, i64>(7)? != 0,
        sprayed_to: unpack_node_ids(&sprayed),
    })
}

impl Database {
    /// Store a DTN bundle.
    pub fn store_dtn_bundle(&self, bundle: &DtnBundleRecord) -> Result<(), StorageError> {
        self.conn().execute(
            "INSERT OR REPLACE INTO dtn_store
             (message_id, destination, source, payload, copies_remaining, expires_at, size,
              is_local, sprayed_to)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                bundle.message_id.as_bytes().as_slice(),
                bundle.destination.as_bytes().as_slice(),
                bundle.source.as_bytes().as_slice(),
                bundle.payload,
                bundle.copies_remaining as i32,
                bundle.expires_at as i64,
                bundle.size as i64,
                bundle.is_local as i32,
                pack_node_ids(&bundle.sprayed_to),
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
        let sql = format!("SELECT {BUNDLE_COLUMNS} FROM dtn_store WHERE destination = ?1");
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map(params![destination.as_bytes().as_slice()], row_to_bundle)?;

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
        let sql = format!("SELECT {BUNDLE_COLUMNS} FROM dtn_store");
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map([], row_to_bundle)?;

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

    /// Record a spray: the remaining copy count and the peers that hold one.
    ///
    /// Both move in a single statement. Written separately, a failure between
    /// them leaves a restart either re-spraying a peer that already holds a
    /// copy or believing it still has copies it has spent.
    pub fn update_dtn_spray_state(
        &self,
        message_id: &MessageId,
        copies_remaining: u8,
        sprayed_to: &[NodeId],
    ) -> Result<(), StorageError> {
        self.conn().execute(
            "UPDATE dtn_store SET copies_remaining = ?1, sprayed_to = ?2 WHERE message_id = ?3",
            params![
                copies_remaining as i32,
                pack_node_ids(sprayed_to),
                message_id.as_bytes().as_slice()
            ],
        )?;
        Ok(())
    }

    /// Reconstruct the origin flag for rows written before migration v3.
    ///
    /// Migration v3 defaults every pre-existing row to relay traffic, because
    /// the migration runs inside `Database::open` and has no idea which NodeId
    /// is ours. Without this the first start after an upgrade would strip
    /// eviction protection from the user's own queued messages (ROADMAP T-11).
    ///
    /// `dtn_store.source` must **not** be trusted on its own: for a relayed
    /// bundle it is copied from the envelope, which is unauthenticated, so a
    /// peer could claim our NodeId and have its traffic promoted to
    /// unevictable local mail.
    ///
    /// A row is promoted only when all of the following hold, which together
    /// are evidence we recorded locally rather than anything a peer supplied:
    ///
    /// - `messages` has a row with the same `message_id`, `is_incoming = 0`
    ///   and `source` equal to us — we composed it;
    /// - that row is still `pending` or `dtn_pending` — it is genuinely
    ///   awaiting delivery. Message ids travel in cleartext envelope headers,
    ///   so a peer that has seen our traffic knows them; without this clause a
    ///   forged relay bundle replaying the id of an already-delivered message
    ///   would qualify;
    /// - this is the first run, guarded by a marker in `config`, so a bundle
    ///   arriving after the upgrade is never reconsidered.
    ///
    /// Residual exposure: a peer that forges a bundle replaying the id of a
    /// message of ours that is *currently* queued, and does so before the
    /// first post-upgrade start. That bundle collides with our own row on the
    /// `message_id` primary key, so it cannot add storage beyond it.
    ///
    /// Returns the number of rows updated.
    pub fn backfill_dtn_local_origin(&self, local_id: &NodeId) -> Result<usize, StorageError> {
        const MARKER: &str = "dtn_local_origin_backfilled";
        let conn = self.conn();

        let already: Option<Vec<u8>> = conn
            .query_row(
                "SELECT value FROM config WHERE key = ?1",
                params![MARKER],
                |row| row.get(0),
            )
            .ok();
        if already.is_some() {
            return Ok(0);
        }

        let updated = conn.execute(
            "UPDATE dtn_store SET is_local = 1
             WHERE is_local = 0
               AND source = ?1
               AND message_id IN (
                   SELECT message_id FROM messages
                   WHERE is_incoming = 0
                     AND source = ?1
                     AND status IN ('pending', 'dtn_pending')
               )",
            params![local_id.as_bytes().as_slice()],
        )?;

        conn.execute(
            "INSERT OR REPLACE INTO config (key, value) VALUES (?1, ?2)",
            params![MARKER, vec![1u8]],
        )?;

        Ok(updated)
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

#[cfg(test)]
mod tests {
    use super::*;

    fn node(byte: u8) -> NodeId {
        NodeId([byte; 32])
    }

    fn record(is_local: bool, sprayed_to: Vec<NodeId>) -> DtnBundleRecord {
        DtnBundleRecord {
            message_id: MessageId::random(),
            destination: node(2),
            source: node(1),
            payload: b"opaque blob".to_vec(),
            copies_remaining: 4,
            expires_at: 9_999_999_999,
            size: 11,
            is_local,
            sprayed_to,
        }
    }

    /// A bundle's origin and spray history must survive a round trip, or a
    /// restart loses eviction protection and re-sprays copies (ROADMAP T-11).
    #[test]
    fn test_dtn_bundle_roundtrip_keeps_origin_and_spray_history() {
        let db = Database::open_in_memory().unwrap();

        let local = record(true, vec![node(7), node(8)]);
        let relay = record(false, vec![]);
        db.store_dtn_bundle(&local).unwrap();
        db.store_dtn_bundle(&relay).unwrap();

        let all = db.list_all_dtn_bundles().unwrap();
        assert_eq!(all.len(), 2);

        let loaded_local = all
            .iter()
            .find(|b| b.message_id == local.message_id)
            .expect("local bundle");
        assert!(loaded_local.is_local, "origin must round trip");
        assert_eq!(
            loaded_local.sprayed_to,
            vec![node(7), node(8)],
            "spray history must round trip in order"
        );

        let loaded_relay = all
            .iter()
            .find(|b| b.message_id == relay.message_id)
            .expect("relay bundle");
        assert!(!loaded_relay.is_local);
        assert!(loaded_relay.sprayed_to.is_empty());
    }

    #[test]
    fn test_update_dtn_spray_state() {
        let db = Database::open_in_memory().unwrap();
        let bundle = record(false, vec![]);
        db.store_dtn_bundle(&bundle).unwrap();

        db.update_dtn_spray_state(&bundle.message_id, 2, &[node(3)])
            .unwrap();

        let loaded = db.list_all_dtn_bundles().unwrap();
        assert_eq!(loaded[0].sprayed_to, vec![node(3)]);
        assert_eq!(
            loaded[0].copies_remaining, 2,
            "copies and holders must be written together"
        );
    }

    fn outgoing_message(db: &Database, message_id: MessageId, source: NodeId) {
        db.insert_message(&crate::messages::MessageRecord {
            message_id,
            source,
            destination: node(9),
            content_type: "text".to_string(),
            plaintext: b"hi".to_vec(),
            lamport_clock: 1,
            device_timestamp: 1,
            status: "dtn_pending".to_string(),
            is_incoming: false,
        })
        .unwrap();
    }

    /// After an upgrade, the user's own queued bundles must regain their
    /// origin flag, or the first start strips their eviction protection.
    ///
    /// Only bundles corroborated by a locally recorded outgoing message are
    /// promoted: `dtn_store.source` is copied from an unauthenticated envelope
    /// for relayed traffic, so trusting it alone would let a peer claim our
    /// NodeId and get unevictable storage.
    #[test]
    fn test_backfill_marks_only_corroborated_bundles_local() {
        let db = Database::open_in_memory().unwrap();
        let us = node(1);

        // Ours: a bundle with a matching outgoing message row.
        let mut ours = record(false, vec![]);
        ours.source = us;
        db.store_dtn_bundle(&ours).unwrap();
        outgoing_message(&db, ours.message_id, us);

        // A relayed bundle spoofing our NodeId, with no outgoing message row.
        let mut spoofed = record(false, vec![]);
        spoofed.source = us;
        db.store_dtn_bundle(&spoofed).unwrap();

        // A relayed bundle replaying the id of a message of ours that was
        // already delivered. Message ids are cleartext on the wire, so this is
        // the realistic forgery; the delivered status must disqualify it.
        let mut replayed = record(false, vec![]);
        replayed.source = us;
        db.store_dtn_bundle(&replayed).unwrap();
        db.insert_message(&crate::messages::MessageRecord {
            message_id: replayed.message_id,
            source: us,
            destination: node(9),
            content_type: "text".to_string(),
            plaintext: b"old".to_vec(),
            lamport_clock: 1,
            device_timestamp: 1,
            status: "delivered".to_string(),
            is_incoming: false,
        })
        .unwrap();

        // Ordinary relay traffic.
        let mut theirs = record(false, vec![]);
        theirs.source = node(3);
        db.store_dtn_bundle(&theirs).unwrap();

        let updated = db.backfill_dtn_local_origin(&us).unwrap();
        assert_eq!(updated, 1, "only the corroborated bundle may be promoted");

        let all = db.list_all_dtn_bundles().unwrap();
        let by_id = |id: MessageId| all.iter().find(|b| b.message_id == id).unwrap().is_local;
        assert!(by_id(ours.message_id));
        assert!(
            !by_id(spoofed.message_id),
            "a spoofed source must not earn eviction protection"
        );
        assert!(
            !by_id(replayed.message_id),
            "replaying the id of a delivered message must not earn protection"
        );
        assert!(!by_id(theirs.message_id));
    }

    /// The backfill runs once. A bundle arriving later that claims our NodeId
    /// must never be reconsidered.
    #[test]
    fn test_backfill_runs_only_once() {
        let db = Database::open_in_memory().unwrap();
        let us = node(1);
        assert_eq!(db.backfill_dtn_local_origin(&us).unwrap(), 0);

        let mut late = record(false, vec![]);
        late.source = us;
        db.store_dtn_bundle(&late).unwrap();
        outgoing_message(&db, late.message_id, us);

        assert_eq!(
            db.backfill_dtn_local_origin(&us).unwrap(),
            0,
            "the backfill must not run a second time"
        );
        assert!(!db.list_all_dtn_bundles().unwrap()[0].is_local);
    }

    /// Rows written before migration v3 have no origin recorded. They must
    /// read back as relay traffic: a bundle whose origin we cannot establish
    /// should not gain eviction protection.
    #[test]
    fn test_pre_v3_rows_default_to_relay_traffic() {
        let db = Database::open_in_memory().unwrap();
        let message_id = MessageId::random();

        // Insert without touching the v3 columns, as a v2 writer would.
        db.conn()
            .execute(
                "INSERT INTO dtn_store
                 (message_id, destination, source, payload, copies_remaining, expires_at, size)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    message_id.as_bytes().as_slice(),
                    node(2).as_bytes().as_slice(),
                    node(1).as_bytes().as_slice(),
                    b"blob".to_vec(),
                    4,
                    9_999_999_999i64,
                    4i64,
                ],
            )
            .unwrap();

        let loaded = db.list_all_dtn_bundles().unwrap();
        assert_eq!(loaded.len(), 1);
        assert!(!loaded[0].is_local);
        assert!(loaded[0].sprayed_to.is_empty());
    }
}
