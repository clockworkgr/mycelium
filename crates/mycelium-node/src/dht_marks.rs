//! Durable DHT high-water marks, behind `mycelium-core`'s `MarkStore` trait.
//!
//! The admission rules are in `mycelium-core` and the table is in
//! `mycelium-storage`; this is the bridge between them, and it is the only
//! piece that needs both. Core stays storage-agnostic, which is what lets its
//! own tests exercise the capacity rules against an in-memory table
//! (ADR-016, ROADMAP T-38).

use std::sync::Arc;

use async_trait::async_trait;
use mycelium_core::dht::marks::{Mark, MarkStore, MarkStoreError};
use mycelium_protocol::types::NodeId;
use mycelium_storage::db::Database;
use mycelium_storage::dht_marks::DhtMark;

/// A `MarkStore` backed by the node's SQLCipher database.
pub struct DbMarkStore {
    db: Arc<Database>,
    /// One outstanding load at a time.
    ///
    /// A caller that times out waiting for the marks abandons its `load`
    /// future, but the `spawn_blocking` job behind it keeps running — it is
    /// waiting on the database mutex, and nothing can cancel it. Admission
    /// retries on every record, so a stalled database would pile up one
    /// blocked job per attempt until the runtime's blocking pool was gone,
    /// taking every other `spawn_blocking` in the process with it.
    ///
    /// The permit is moved *into* the blocking job, so it is released when
    /// that job finishes rather than when the caller gives up. While one is
    /// outstanding, a further load fails fast instead of queueing — and
    /// failing is already the safe direction here: it refuses admission.
    load_slot: Arc<tokio::sync::Semaphore>,
}

impl DbMarkStore {
    pub fn new(db: Arc<Database>) -> Self {
        Self {
            db,
            load_slot: Arc::new(tokio::sync::Semaphore::new(1)),
        }
    }
}

fn to_row(mark: &Mark) -> DhtMark {
    DhtMark {
        newest_published_at: mark.newest_published_at,
        first_seen: mark.first_seen,
        last_refreshed: mark.last_refreshed,
        established: mark.established,
    }
}

fn from_row(row: DhtMark) -> Mark {
    Mark {
        newest_published_at: row.newest_published_at,
        first_seen: row.first_seen,
        last_refreshed: row.last_refreshed,
        established: row.established,
    }
}

/// Every call goes through `spawn_blocking`.
///
/// `Database` is a `std::sync::Mutex<Connection>`, so its guard must not cross
/// an await, and a SQLCipher write on a slow disk would otherwise stall
/// unrelated tasks on the same runtime worker.
///
/// That a blocking job can outlive a cancelled caller is exactly what the
/// trait's monotonicity contract was written for. Ordering is preserved on top
/// of that: every write reaches this type through the engine's single writer
/// task, which awaits each one before taking the next off the queue.
#[async_trait]
impl MarkStore for DbMarkStore {
    async fn load(&self) -> Result<Vec<(NodeId, Mark)>, MarkStoreError> {
        // Taken before anything is spawned, and held by the job rather than by
        // this future, so an abandoned load cannot be joined by another.
        let permit = self
            .load_slot
            .clone()
            .try_acquire_owned()
            .map_err(|_| MarkStoreError("a mark load is already outstanding".to_string()))?;
        let db = self.db.clone();
        // Reported, never flattened to an empty table: an unreadable backend
        // and one with nothing in it are opposite situations, and treating the
        // first as the second would accept every replay the database could
        // have refused. The engine turns this into a refusal.
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            db.load_dht_marks()
        })
        .await
        .map_err(|e| MarkStoreError(format!("mark load task failed: {}", e)))?
        .map(|rows| rows.into_iter().map(|(id, m)| (id, from_row(m))).collect())
        .map_err(|e| MarkStoreError(e.to_string()))
    }

    async fn put(&self, id: NodeId, mark: Mark) -> Result<(), MarkStoreError> {
        let db = self.db.clone();
        let row = to_row(&mark);
        tokio::task::spawn_blocking(move || db.write_dht_mark(&id, &row))
            .await
            .map_err(|e| MarkStoreError(format!("mark write task failed: {}", e)))?
            .map_err(|e| MarkStoreError(e.to_string()))
    }

    async fn remove_not_newer(&self, ids: &[(NodeId, u64)]) -> Result<(), MarkStoreError> {
        let db = self.db.clone();
        let ids = ids.to_vec();
        tokio::task::spawn_blocking(move || db.remove_dht_marks_not_newer(&ids))
            .await
            .map_err(|e| MarkStoreError(format!("mark sweep task failed: {}", e)))?
            .map_err(|e| MarkStoreError(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use mycelium_core::dht::marks::MemoryMarkStore;
    use mycelium_core::dht::record::{unix_now, DhtRecord, RecordRejection};
    use mycelium_core::dht::{DhtConfig, DhtEngine, RecordSource};
    use mycelium_crypto::identity::Identity;

    use super::*;

    fn store_on(db: &Arc<Database>) -> Arc<dyn MarkStore> {
        Arc::new(DbMarkStore::new(db.clone()))
    }

    fn engine(marks: Arc<dyn MarkStore>) -> DhtEngine {
        DhtEngine::with_mark_store(Arc::new(Identity::generate()), DhtConfig::default(), marks)
    }

    fn addr(last: u8) -> SocketAddr {
        format!("203.0.113.{}:9736", last).parse().expect("addr")
    }

    fn from_a_peer(byte: u8) -> RecordSource {
        RecordSource::Peer(NodeId([byte; 32]))
    }

    #[tokio::test]
    async fn test_a_mark_written_through_the_trait_comes_back() {
        let db = Arc::new(Database::open_in_memory().expect("db"));
        let store = DbMarkStore::new(db.clone());
        let id = NodeId([9u8; 32]);
        let mark = Mark {
            newest_published_at: 2_000,
            first_seen: 1_000,
            last_refreshed: 2_000,
            established: true,
        };

        store.put(id, mark).await.expect("put");
        assert_eq!(store.load().await.unwrap(), vec![(id, mark)]);

        // The monotonic contract, through the async bridge rather than the SQL.
        store
            .put(
                id,
                Mark {
                    newest_published_at: 1_500,
                    first_seen: 1_200,
                    last_refreshed: 1_500,
                    established: false,
                },
            )
            .await
            .expect("late put");
        assert_eq!(store.load().await.unwrap(), vec![(id, mark)]);

        // And the conditional delete: the stored mark is newer than what the
        // sweep saw, so it survives.
        store.remove_not_newer(&[(id, 1_500)]).await.expect("sweep");
        assert_eq!(store.load().await.unwrap().len(), 1);
        store.remove_not_newer(&[(id, 2_000)]).await.expect("sweep");
        assert!(store.load().await.unwrap().is_empty());
    }

    /// The whole of T-38, end to end and across a restart.
    ///
    /// Every other test in this task proves a rule inside one process. This
    /// one admits a record, lets the engine go, builds a new one over the same
    /// database, and replays the victim's older record. The second engine's
    /// record store is empty — the records do not survive, and that is the
    /// point. Only the mark does, and it is what refuses the replay.
    #[tokio::test]
    async fn test_a_replay_is_refused_after_a_restart() {
        let db = Arc::new(Database::open_in_memory().expect("db"));
        let victim = Identity::generate();
        let now = unix_now();
        let older = DhtRecord::new_signed(&victim, addr(4), now - 600);
        let newer = DhtRecord::new_signed(&victim, addr(7), now - 60);

        {
            let first_run = engine(store_on(&db));
            first_run.restore_marks().await;
            first_run
                .store_record(newer, from_a_peer(1))
                .await
                .expect("the victim's current record is admitted");
            first_run.flush_marks().await;
        }

        let second_run = engine(store_on(&db));
        second_run.restore_marks().await;
        let replayed = second_run.store_record(older, from_a_peer(2)).await;
        assert!(
            matches!(replayed, Err(RecordRejection::RolledBack)),
            "a replay after a restart was not refused: {:?}",
            replayed
        );
    }

    /// The reason the test above is not vacuous.
    ///
    /// With marks that live only in memory — which is what every engine built
    /// through `DhtEngine::new` has — the second run has nothing to compare
    /// against and the rollback lands. This is the defect T-38 names, left in
    /// place as a test so the durable path cannot quietly stop being used.
    #[tokio::test]
    async fn test_without_a_durable_store_the_replay_succeeds() {
        let victim = Identity::generate();
        let now = unix_now();
        let older = DhtRecord::new_signed(&victim, addr(4), now - 600);
        let newer = DhtRecord::new_signed(&victim, addr(7), now - 60);

        {
            let first_run = engine(Arc::new(MemoryMarkStore::default()));
            first_run.restore_marks().await;
            first_run
                .store_record(newer, from_a_peer(1))
                .await
                .expect("admitted");
            first_run.flush_marks().await;
        }

        let second_run = engine(Arc::new(MemoryMarkStore::default()));
        second_run.restore_marks().await;
        second_run
            .store_record(older, from_a_peer(2))
            .await
            .expect("without a durable mark the replay is accepted");
    }
}
