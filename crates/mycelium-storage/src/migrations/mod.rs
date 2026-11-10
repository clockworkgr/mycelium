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
    if current_version < 2 {
        migrate_v2(conn)?;
    }
    if current_version < 3 {
        migrate_v3(conn)?;
    }

    Ok(())
}

/// v3: record a DTN bundle's origin and spray history.
///
/// `is_local` distinguishes the user's own outgoing mail from traffic carried
/// for other nodes, so eviction can protect the former (ROADMAP T-11).
/// `sprayed_to` is the concatenation of the 32-byte NodeIds a bundle has
/// already been handed to, so a restart does not spend copies re-spraying
/// peers that already hold one.
///
/// Existing rows default to relay traffic with no spray history: that is the
/// safe reading, since a bundle whose origin we cannot establish should not
/// gain eviction protection.
fn migrate_v3(conn: &Connection) -> Result<(), StorageError> {
    // Wrapped in a transaction: `ALTER TABLE ADD COLUMN` is not idempotent, so
    // committing the columns without the version row would make the next
    // startup re-run this migration and fail with "duplicate column name".
    conn.execute_batch(
        "
        BEGIN;
        ALTER TABLE dtn_store ADD COLUMN is_local INTEGER NOT NULL DEFAULT 0;
        ALTER TABLE dtn_store ADD COLUMN sprayed_to BLOB NOT NULL DEFAULT x'';
        INSERT INTO schema_version (version) VALUES (3);
        COMMIT;
        ",
    )?;

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

fn migrate_v2(conn: &Connection) -> Result<(), StorageError> {
    conn.execute_batch(
        "
        -- Public channels
        CREATE TABLE IF NOT EXISTS channels (
            channel_id BLOB PRIMARY KEY,
            name TEXT NOT NULL,
            creator_id BLOB NOT NULL,
            created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
        );

        -- Channel messages
        CREATE TABLE IF NOT EXISTS channel_messages (
            message_id BLOB PRIMARY KEY,
            channel_id BLOB NOT NULL,
            source BLOB NOT NULL,
            data BLOB NOT NULL,
            content_type INTEGER NOT NULL DEFAULT 0,
            timestamp INTEGER NOT NULL,
            FOREIGN KEY (channel_id) REFERENCES channels(channel_id)
        );
        CREATE INDEX IF NOT EXISTS idx_channel_messages_channel
            ON channel_messages(channel_id, timestamp);

        -- Channel subscriptions
        CREATE TABLE IF NOT EXISTS channel_subscriptions (
            channel_id BLOB NOT NULL,
            subscribed_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
            PRIMARY KEY (channel_id)
        );

        INSERT INTO schema_version (version) VALUES (2);
        ",
    )?;

    Ok(())
}
