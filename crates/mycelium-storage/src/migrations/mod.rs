use rusqlite::Connection;

use crate::db::StorageError;

/// Run all database migrations.
pub fn run_all(conn: &Connection) -> Result<(), StorageError> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS schema_version (
            version INTEGER PRIMARY KEY
        );
        ",
    )?;

    let current_version: i64 = conn
        .query_row(
            "SELECT COALESCE(MAX(version), 0) FROM schema_version",
            [],
            |row| row.get(0),
        )
        .unwrap_or(0);

    if current_version < 1 {
        migrate_v1(conn)?;
    }

    Ok(())
}

fn migrate_v1(conn: &Connection) -> Result<(), StorageError> {
    conn.execute_batch(
        "
        -- Messages table
        CREATE TABLE IF NOT EXISTS messages (
            message_id BLOB PRIMARY KEY,
            source BLOB NOT NULL,
            destination BLOB NOT NULL,
            content_type TEXT NOT NULL,
            plaintext BLOB NOT NULL,
            lamport_clock INTEGER NOT NULL,
            device_timestamp INTEGER NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            is_incoming INTEGER NOT NULL DEFAULT 0,
            created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
        );
        CREATE INDEX IF NOT EXISTS idx_messages_conversation
            ON messages(source, destination, lamport_clock);
        CREATE INDEX IF NOT EXISTS idx_messages_destination
            ON messages(destination, status);

        -- Crypto sessions (Double Ratchet state)
        CREATE TABLE IF NOT EXISTS sessions (
            peer_id BLOB PRIMARY KEY,
            session_data BLOB NOT NULL,
            safety_number TEXT,
            is_verified INTEGER NOT NULL DEFAULT 0,
            updated_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
        );

        -- Contacts
        CREATE TABLE IF NOT EXISTS contacts (
            node_id BLOB PRIMARY KEY,
            display_name TEXT NOT NULL,
            public_key BLOB NOT NULL,
            trust_score REAL NOT NULL DEFAULT 0.0,
            is_verified INTEGER NOT NULL DEFAULT 0,
            last_seen INTEGER,
            created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
        );

        -- Web of Trust vouches
        CREATE TABLE IF NOT EXISTS vouches (
            voucher_id BLOB NOT NULL,
            vouchee_id BLOB NOT NULL,
            voucher_public_key BLOB NOT NULL,
            display_name TEXT NOT NULL,
            signature BLOB NOT NULL,
            timestamp INTEGER NOT NULL,
            PRIMARY KEY (voucher_id, vouchee_id)
        );

        -- Prekey cache (other nodes' prekey bundles)
        CREATE TABLE IF NOT EXISTS prekey_cache (
            node_id BLOB NOT NULL,
            bundle_data BLOB NOT NULL,
            fetched_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
            PRIMARY KEY (node_id)
        );

        -- Our own prekeys
        CREATE TABLE IF NOT EXISTS our_prekeys (
            prekey_id INTEGER PRIMARY KEY,
            prekey_type TEXT NOT NULL, -- 'signed' or 'one_time'
            secret_key BLOB NOT NULL,
            public_key BLOB NOT NULL,
            created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
            used INTEGER NOT NULL DEFAULT 0
        );

        -- DTN bundle store
        CREATE TABLE IF NOT EXISTS dtn_store (
            message_id BLOB PRIMARY KEY,
            destination BLOB NOT NULL,
            source BLOB NOT NULL,
            payload BLOB NOT NULL,
            copies_remaining INTEGER NOT NULL,
            expires_at INTEGER NOT NULL,
            created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
            size INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_dtn_destination ON dtn_store(destination);
        CREATE INDEX IF NOT EXISTS idx_dtn_expires ON dtn_store(expires_at);

        -- General config
        CREATE TABLE IF NOT EXISTS config (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );

        INSERT INTO schema_version (version) VALUES (1);
        ",
    )?;

    Ok(())
}
