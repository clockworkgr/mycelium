//! DHT high-water marks (ADR-016, ROADMAP T-38).
//!
//! One row per publisher, remembering the newest `published_at` ever admitted
//! for it. The mark outlives the record it guards, which is what makes
//! ADR-011's rollback rule true even after capacity eviction has thrown the
//! record away — and persisting it is what makes that survive a restart. On a
//! phone the daemon stops whenever the OS decides, so in-memory marks would
//! rarely be more than a few hours old.
//!
//! The admission rules live in `mycelium-core`; this module is only the table.
//! It is deliberately *not* a plain read-modify-write: see
//! [`Database::merge_dht_mark`].

use mycelium_protocol::types::NodeId;
use rusqlite::params;

use crate::db::{blob_to_array, Database, StorageError};

/// One `dht_marks` row.
///
/// A separate type from `mycelium_core::dht::marks::Mark` because the
/// dependency runs the other way — core depends on storage — so this crate
/// cannot name it. The caller converts; it is four fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DhtMark {
    /// The newest `published_at` ever admitted for this id.
    pub newest_published_at: u64,
    /// Unix seconds when the id was first admitted. Drives graduation.
    pub first_seen: u64,
    /// Unix seconds when the id was last admitted.
    pub last_refreshed: u64,
    /// Whether the mark has graduated out of the evictable region.
    pub established: bool,
}

/// SQLite integers are signed, and a `u64` cast that wrapped would read back
/// *negative* — i.e. as a watermark of zero, silently losing the protection
/// this table exists to provide. Saturating instead keeps every field moving
/// the one direction the merge below relies on.
///
/// Nothing reachable comes near the boundary: `published_at` is validated
/// against the clock on admission, and the other two fields come from the
/// clock itself. This is the behaviour if that ever stops being true, not a
/// case anyone expects to hit.
fn to_secs(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

fn from_secs(value: i64) -> u64 {
    value.max(0) as u64
}

impl Database {
    /// Every persisted mark, or an error.
    ///
    /// **A partial load is a failure, not a result.** Skipping an unreadable
    /// row and returning the rest looks like the forgiving choice and is the
    /// opposite: the engine would treat the omitted publisher as a mark it has
    /// never seen, so startup reconciliation would delete that row as an
    /// orphan — destroying the protection permanently rather than losing it
    /// for one run. The caller refuses admission while this fails, which is
    /// the direction ADR-016 chooses, and retries.
    pub fn load_dht_marks(&self) -> Result<Vec<(NodeId, DhtMark)>, StorageError> {
        let conn = self.conn();
        let mut stmt = conn.prepare(
            "SELECT node_id, newest_published_at, first_seen, last_refreshed, established
             FROM dht_marks",
        )?;
        let rows = stmt.query_map([], |row| {
            let id_bytes: Vec<u8> = row.get(0)?;
            Ok((
                NodeId::from_bytes(blob_to_array(0, id_bytes)?),
                DhtMark {
                    newest_published_at: from_secs(row.get::<_, i64>(1)?),
                    first_seen: from_secs(row.get::<_, i64>(2)?),
                    last_refreshed: from_secs(row.get::<_, i64>(3)?),
                    established: row.get::<_, i64>(4)? != 0,
                },
            ))
        })?;

        let mut marks = Vec::new();
        for row in rows {
            marks.push(row?);
        }
        Ok(marks)
    }

    /// Write one mark, unless the stored one is newer.
    ///
    /// **One statement, and not a merge.** A mark write can outlive the caller
    /// that issued it — admission holds a lock across the call and a lookup has
    /// a deadline, so a dropped future releases the guard wherever it happened
    /// to be — and two writes can therefore land in the opposite order to the
    /// one they were issued in. Doing this as a read, a decision and a write
    /// would make that ordering load-bearing; the `WHERE` makes a write
    /// carrying an older `newest_published_at` than the stored row do nothing
    /// at all.
    ///
    /// Every column comes from the caller, because the caller's table is the
    /// authority on the publisher's current lifetime. An earlier version
    /// merged field by field — greater watermark, earlier `first_seen`, never
    /// un-establishing — which survives reordering equally well and makes
    /// every write a delta that can never correct anything. It could not
    /// express a lifetime that retention had ended and the publisher then
    /// restarted (so establishment was banked across a silence longer than the
    /// whole replay window), nor an establishment that restoration had
    /// withdrawn (so the demoted publisher was promoted again at the next
    /// start).
    ///
    /// An **equal** watermark writes. A mark can be evicted and the very same
    /// record re-admitted — neither stale nor a rollback, because the mark and
    /// the record went together — and that is a new lifetime at an unchanged
    /// timestamp.
    pub fn write_dht_mark(&self, id: &NodeId, mark: &DhtMark) -> Result<(), StorageError> {
        self.conn().execute(
            "INSERT INTO dht_marks
                 (node_id, newest_published_at, first_seen, last_refreshed, established)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(node_id) DO UPDATE SET
                 newest_published_at = excluded.newest_published_at,
                 first_seen          = excluded.first_seen,
                 last_refreshed      = excluded.last_refreshed,
                 established         = excluded.established
             WHERE excluded.newest_published_at >= newest_published_at",
            params![
                id.as_bytes().as_slice(),
                to_secs(mark.newest_published_at),
                to_secs(mark.first_seen),
                to_secs(mark.last_refreshed),
                mark.established as i64,
            ],
        )?;
        Ok(())
    }

    /// Forget each id whose stored mark is no newer than the paired
    /// `newest_published_at`.
    ///
    /// A conditional delete, for the same reason the merge above is one
    /// statement: a retention sweep decides what to drop from the mark it read,
    /// and by the time the delete runs that id may have been refreshed — in
    /// which case deleting it would reopen rollback at the next restart. The
    /// `<=` is what spares it. An unconditional `DELETE ... WHERE node_id = ?`
    /// is wrong here even though it passes the obvious tests.
    ///
    /// The batch is one transaction so a failure part-way leaves no half-swept
    /// table.
    pub fn remove_dht_marks_not_newer(&self, ids: &[(NodeId, u64)]) -> Result<(), StorageError> {
        if ids.is_empty() {
            return Ok(());
        }
        let conn = self.conn();
        let tx = conn.unchecked_transaction()?;
        for (id, newest) in ids {
            tx.execute(
                "DELETE FROM dht_marks WHERE node_id = ?1 AND newest_published_at <= ?2",
                params![id.as_bytes().as_slice(), to_secs(*newest)],
            )?;
        }
        tx.commit()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mark(newest: u64) -> DhtMark {
        DhtMark {
            newest_published_at: newest,
            first_seen: 1_000,
            last_refreshed: newest,
            established: false,
        }
    }

    fn id(byte: u8) -> NodeId {
        NodeId([byte; 32])
    }

    #[test]
    fn test_a_mark_moves_forward_and_never_back() {
        let db = Database::open_in_memory().expect("open");
        db.write_dht_mark(&id(1), &mark(500)).expect("first");

        // A later record raises the watermark.
        db.write_dht_mark(&id(1), &mark(900)).expect("newer");
        let loaded = db.load_dht_marks().expect("load");
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].1.newest_published_at, 900);

        // A write that was issued earlier but lands later must not lower it.
        // This is the whole reason the merge is a single statement.
        db.write_dht_mark(&id(1), &mark(400)).expect("older");
        let loaded = db.load_dht_marks().expect("load");
        assert_eq!(loaded[0].1.newest_published_at, 900);
    }

    #[test]
    fn test_establishment_and_first_seen_survive_a_late_write() {
        let db = Database::open_in_memory().expect("open");
        db.write_dht_mark(
            &id(2),
            &DhtMark {
                newest_published_at: 500,
                first_seen: 100,
                last_refreshed: 500,
                established: true,
            },
        )
        .expect("established");

        // A late write carrying the pre-graduation state must not undo it.
        //
        // The mechanism is the `WHERE`, not a field-by-field merge: this
        // write's watermark is *older* than the stored row's, so the whole
        // statement does nothing. That is the only reason establishment and
        // `first_seen` survive here, and it is worth saying because the
        // earlier version of this table reached the same assertions by
        // merging — which also quietly preserved an *ended* lifetime's
        // establishment, the defect
        // `test_a_new_lifetime_replaces_an_ended_one_rather_than_merging_with_it`
        // covers.
        db.write_dht_mark(
            &id(2),
            &DhtMark {
                newest_published_at: 400,
                first_seen: 300,
                last_refreshed: 400,
                established: false,
            },
        )
        .expect("late");

        let loaded = db.load_dht_marks().expect("load");
        assert!(loaded[0].1.established, "establishment was undone");
        assert_eq!(loaded[0].1.first_seen, 100, "first_seen moved later");
        assert_eq!(loaded[0].1.last_refreshed, 500);
    }

    #[test]
    fn test_a_conditional_delete_spares_a_refreshed_mark() {
        let db = Database::open_in_memory().expect("open");
        db.write_dht_mark(&id(3), &mark(500)).expect("put");
        db.write_dht_mark(&id(4), &mark(500)).expect("put");

        // id(3) was refreshed after the sweep read it; id(4) was not.
        db.write_dht_mark(&id(3), &mark(900)).expect("refresh");
        db.remove_dht_marks_not_newer(&[(id(3), 500), (id(4), 500)])
            .expect("sweep");

        let loaded = db.load_dht_marks().expect("load");
        assert_eq!(loaded.len(), 1, "the refreshed mark was deleted");
        assert_eq!(loaded[0].0, id(3));
        assert_eq!(loaded[0].1.newest_published_at, 900);
    }

    #[test]
    fn test_a_new_lifetime_replaces_an_ended_one_rather_than_merging_with_it() {
        let db = Database::open_in_memory().expect("open");
        // An established publisher, whose mark retention later expired.
        db.write_dht_mark(
            &id(7),
            &DhtMark {
                newest_published_at: 500,
                first_seen: 100,
                last_refreshed: 500,
                established: true,
            },
        )
        .expect("established");

        // It republishes after the gap. The caller's table has no mark for it,
        // so this is a first sighting: a merge here would resurrect
        // `first_seen: 100` and `established: true`, handing back establishment
        // that was never re-earned.
        db.write_dht_mark(
            &id(7),
            &DhtMark {
                newest_published_at: 9_000,
                first_seen: 9_000,
                last_refreshed: 9_000,
                established: false,
            },
        )
        .expect("replace");

        let loaded = db.load_dht_marks().expect("load");
        assert_eq!(
            loaded[0].1,
            DhtMark {
                newest_published_at: 9_000,
                first_seen: 9_000,
                last_refreshed: 9_000,
                established: false,
            },
            "the ended lifetime's first_seen or establishment survived"
        );

        // And it is still monotonic on the watermark: a write carrying an
        // older timestamp must do nothing at all rather than replace the row.
        db.write_dht_mark(
            &id(7),
            &DhtMark {
                newest_published_at: 8_000,
                first_seen: 8_000,
                last_refreshed: 8_000,
                established: false,
            },
        )
        .expect("late replace");
        assert_eq!(
            db.load_dht_marks().expect("load")[0].1.newest_published_at,
            9_000,
            "a late replace must not lower the watermark"
        );
    }

    /// An **equal** timestamp must still reset the lifetime.
    ///
    /// A mark can be evicted and the very same record re-admitted: with the
    /// mark gone and the record evicted alongside it, the republish is neither
    /// stale nor a rollback. That is a new lifetime at an unchanged timestamp,
    /// and a strictly-newer condition would skip it — leaving the ended
    /// lifetime's `first_seen` and `established` in the row, so a restart
    /// would restore a graduation age the publisher never served.
    /// Restoration can withdraw establishment, and that has to be writable.
    ///
    /// A table whose capacity shrank, or whose reserve grew, demotes the
    /// established marks that no longer fit. A merging write could never
    /// persist that — `established` only ever moved upward — so the demoted
    /// publisher was promoted again at the next start, and a previously
    /// protected one demoted in its place. Which publishers hold the protected
    /// region then churned arbitrarily across restarts, and an identity that
    /// had once been established kept competing for it for good.
    #[test]
    fn test_a_withdrawn_establishment_can_be_persisted() {
        let db = Database::open_in_memory().expect("open");
        db.write_dht_mark(
            &id(9),
            &DhtMark {
                newest_published_at: 1_000,
                first_seen: 100,
                last_refreshed: 1_000,
                established: true,
            },
        )
        .expect("established");

        // The same lifetime, same watermark, demoted.
        db.write_dht_mark(
            &id(9),
            &DhtMark {
                newest_published_at: 1_000,
                first_seen: 100,
                last_refreshed: 1_000,
                established: false,
            },
        )
        .expect("demote");

        assert!(
            !db.load_dht_marks().expect("load")[0].1.established,
            "a demotion must reach the row, or the next start undoes it"
        );
    }

    #[test]
    fn test_an_equal_timestamp_still_resets_the_lifetime() {
        let db = Database::open_in_memory().expect("open");
        db.write_dht_mark(
            &id(8),
            &DhtMark {
                newest_published_at: 500,
                first_seen: 100,
                last_refreshed: 500,
                established: true,
            },
        )
        .expect("established");

        db.write_dht_mark(
            &id(8),
            &DhtMark {
                newest_published_at: 500,
                first_seen: 500,
                last_refreshed: 500,
                established: false,
            },
        )
        .expect("replace at the same timestamp");

        let loaded = db.load_dht_marks().expect("load");
        assert!(
            !loaded[0].1.established,
            "an equal-timestamp re-admission must not keep establishment"
        );
        assert_eq!(loaded[0].1.first_seen, 500);
    }

    #[test]
    fn test_an_unreadable_row_fails_the_whole_load() {
        let db = Database::open_in_memory().expect("open");
        db.write_dht_mark(&id(6), &mark(500)).expect("good row");
        // A short `node_id` blob: the kind of row a truncated write or a
        // schema change leaves behind.
        db.conn()
            .execute(
                "INSERT INTO dht_marks
                     (node_id, newest_published_at, first_seen, last_refreshed, established)
                 VALUES (?1, 1, 1, 1, 0)",
                params![vec![0u8; 7]],
            )
            .expect("insert a malformed row");

        // Skipping it and returning the good row would be worse than failing:
        // the engine would treat the omitted publisher as one it has never
        // seen, and startup reconciliation would then delete its row as an
        // orphan — losing that protection for good rather than for one run.
        assert!(
            db.load_dht_marks().is_err(),
            "a partial load must be reported as a failure"
        );
    }

    #[test]
    fn test_marks_survive_reopening_the_database() {
        let path = std::env::temp_dir()
            .join(format!(
                "mycelium-dhtmarks-{}-{}.db",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos()
            ))
            .to_string_lossy()
            .into_owned();
        let key = [7u8; 32];

        {
            let db = Database::open(&path, &key).expect("open");
            db.write_dht_mark(
                &id(5),
                &DhtMark {
                    newest_published_at: 1_700,
                    first_seen: 1_000,
                    last_refreshed: 1_700,
                    established: true,
                },
            )
            .expect("put");
        }

        let db = Database::open(&path, &key).expect("reopen");
        let loaded = db.load_dht_marks().expect("load");
        assert_eq!(
            loaded,
            vec![(
                id(5),
                DhtMark {
                    newest_published_at: 1_700,
                    first_seen: 1_000,
                    last_refreshed: 1_700,
                    established: true,
                }
            )]
        );

        let _ = std::fs::remove_file(&path);
    }
}
