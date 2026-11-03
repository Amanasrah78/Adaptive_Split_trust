//! Durable transactional replay protection for ASTRA-PQ service processes.

#![forbid(unsafe_code)]

use astra_common::{Digest32, SESSION_CLOCK_SKEW_SECONDS, SessionId};
use astra_governance::LocalGovernanceState;
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use std::path::Path;
use thiserror::Error;

/// Additional time retained after protocol expiry and permitted clock skew.
///
/// This covers delayed completion and ensures that a recently completed or
/// crash-interrupted session cannot immediately become replayable.
pub const REPLAY_RETENTION_SECONDS: u64 = 60;

/// Durable state associated with an observed replay key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReplayStatus {
    /// Processing has started but has not reached a terminal outcome.
    Pending,
    /// Processing completed successfully.
    Accepted,
    /// Processing reached a terminal rejection.
    Rejected,
}

impl ReplayStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
        }
    }

    fn parse(value: &str) -> Result<Self, ReplayStoreError> {
        match value {
            "pending" => Ok(Self::Pending),
            "accepted" => Ok(Self::Accepted),
            "rejected" => Ok(Self::Rejected),
            _ => Err(ReplayStoreError::InvalidStoredStatus(value.to_owned())),
        }
    }
}

/// Errors produced by the durable replay store.
#[derive(Debug, Error)]
pub enum ReplayStoreError {
    /// SQLite persistence failed.
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),

    /// A replay key already exists and therefore must not be processed again.
    #[error("replay state already exists with status {status:?}")]
    AlreadyObserved {
        /// Existing durable state.
        status: ReplayStatus,
    },

    /// A stored replay status was not one of the protocol-defined states.
    #[error("invalid stored replay status: {0}")]
    InvalidStoredStatus(String),

    /// A terminal transition was requested for a replay key that does not exist.
    #[error("replay reservation does not exist")]
    MissingReservation,

    /// A terminal transition was attempted from a non-pending state.
    #[error("replay state cannot transition from {0:?}")]
    InvalidTransition(ReplayStatus),

    /// An integer cannot be represented safely by SQLite's signed INTEGER.
    #[error("replay integer is outside SQLite range: {0}")]
    IntegerRange(&'static str),

    /// A stored governance checkpoint digest is malformed.
    #[error("stored governance checkpoint hash has invalid length {0}")]
    InvalidCheckpointHashLength(usize),

    /// A caller attempted to persist an older governance epoch.
    #[error("governance epoch rollback detected: stored {stored}, candidate {candidate}")]
    GovernanceEpochRollback {
        /// Highest epoch already persisted.
        stored: u64,
        /// Candidate epoch.
        candidate: u64,
    },

    /// A caller attempted to skip a governance epoch.
    #[error("governance epoch gap detected: stored {stored}, candidate {candidate}")]
    GovernanceEpochGap {
        /// Highest epoch already persisted.
        stored: u64,
        /// Candidate epoch.
        candidate: u64,
    },

    /// The same governance epoch was presented with different immutable state.
    #[error("conflicting governance state for epoch {epoch}")]
    GovernanceConflict {
        /// Conflicting epoch.
        epoch: u64,
    },

    /// The IOTA object version did not advance monotonically.
    #[error("governance object-version rollback detected: stored {stored}, candidate {candidate}")]
    GovernanceObjectVersionRollback {
        /// Highest object version already persisted.
        stored: u64,
        /// Candidate object version.
        candidate: u64,
    },

    /// Local validation time moved backwards.
    #[error("governance validation time rollback detected: stored {stored}, candidate {candidate}")]
    GovernanceValidationTimeRollback {
        /// Last persisted validation time.
        stored: u64,
        /// Candidate validation time.
        candidate: u64,
    },
}

/// SQLite-backed replay state.
///
/// One instance owns one database connection. Service processes already
/// serialize mutable protocol state with a mutex, while SQLite transactions
/// additionally protect the replay invariant across connections/processes.
pub struct ReplayStore {
    connection: Connection,
}

impl ReplayStore {
    /// Opens or creates a durable replay database.
    pub fn open(path: &Path) -> Result<Self, ReplayStoreError> {
        let connection = Connection::open(path)?;

        connection.pragma_update(None, "journal_mode", "WAL")?;
        connection.pragma_update(None, "synchronous", "FULL")?;
        connection.pragma_update(None, "foreign_keys", "ON")?;
        connection.busy_timeout(std::time::Duration::from_secs(5))?;

        connection.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS replay_state (
                scope       TEXT    NOT NULL,
                session_id  BLOB    NOT NULL,
                epoch       INTEGER NOT NULL,
                expires_at  INTEGER NOT NULL,
                status      TEXT    NOT NULL
                    CHECK(status IN ('pending', 'accepted', 'rejected')),
                created_at  INTEGER NOT NULL,
                updated_at  INTEGER NOT NULL,
                PRIMARY KEY(scope, session_id, epoch)
            );

            CREATE INDEX IF NOT EXISTS replay_state_expiry_idx
                ON replay_state(expires_at);

            CREATE TABLE IF NOT EXISTS governance_state (
                scope            TEXT    PRIMARY KEY,
                highest_epoch    INTEGER NOT NULL,
                checkpoint_hash  BLOB    NOT NULL,
                validated_at     INTEGER NOT NULL,
                object_version   INTEGER NOT NULL
            );
            "#,
        )?;

        Ok(Self { connection })
    }

    /// Atomically reserves a previously unseen replay key as `pending`.
    ///
    /// Any existing state, including `pending` left by a crashed process,
    /// causes fail-closed replay rejection.
    pub fn reserve(
        &mut self,
        scope: &str,
        session_id: &SessionId,
        epoch: u64,
        expires_at: u64,
        now: u64,
    ) -> Result<(), ReplayStoreError> {
        let epoch = sqlite_u64(epoch, "epoch")?;
        let expires_at = sqlite_u64(expires_at, "expires_at")?;
        let now = sqlite_u64(now, "now")?;

        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;

        let existing = transaction
            .query_row(
                r#"
                SELECT status
                FROM replay_state
                WHERE scope = ?1
                  AND session_id = ?2
                  AND epoch = ?3
                "#,
                params![scope, session_id.as_bytes().as_slice(), epoch],
                |row| row.get::<_, String>(0),
            )
            .optional()?;

        if let Some(status) = existing {
            return Err(ReplayStoreError::AlreadyObserved {
                status: ReplayStatus::parse(&status)?,
            });
        }

        transaction.execute(
            r#"
            INSERT INTO replay_state
                (scope, session_id, epoch, expires_at, status, created_at, updated_at)
            VALUES
                (?1, ?2, ?3, ?4, 'pending', ?5, ?5)
            "#,
            params![
                scope,
                session_id.as_bytes().as_slice(),
                epoch,
                expires_at,
                now
            ],
        )?;

        transaction.commit()?;
        Ok(())
    }

    /// Marks an existing pending replay reservation as accepted.
    pub fn mark_accepted(
        &mut self,
        scope: &str,
        session_id: &SessionId,
        epoch: u64,
        now: u64,
    ) -> Result<(), ReplayStoreError> {
        self.transition(scope, session_id, epoch, ReplayStatus::Accepted, now)
    }

    /// Marks an existing pending replay reservation as rejected.
    pub fn mark_rejected(
        &mut self,
        scope: &str,
        session_id: &SessionId,
        epoch: u64,
        now: u64,
    ) -> Result<(), ReplayStoreError> {
        self.transition(scope, session_id, epoch, ReplayStatus::Rejected, now)
    }

    /// Returns the durable status of a replay key, if present.
    pub fn status(
        &self,
        scope: &str,
        session_id: &SessionId,
        epoch: u64,
    ) -> Result<Option<ReplayStatus>, ReplayStoreError> {
        let epoch = sqlite_u64(epoch, "epoch")?;

        let stored = self
            .connection
            .query_row(
                r#"
                SELECT status
                FROM replay_state
                WHERE scope = ?1
                  AND session_id = ?2
                  AND epoch = ?3
                "#,
                params![scope, session_id.as_bytes().as_slice(), epoch],
                |row| row.get::<_, String>(0),
            )
            .optional()?;

        stored.map(|value| ReplayStatus::parse(&value)).transpose()
    }

    /// Removes replay records only after their safe retention horizon.
    ///
    /// Records remain protected through:
    ///
    /// `expires_at + protocol_clock_skew + REPLAY_RETENTION_SECONDS`.
    pub fn cleanup_expired(&mut self, now: u64) -> Result<usize, ReplayStoreError> {
        let retention = SESSION_CLOCK_SKEW_SECONDS.saturating_add(REPLAY_RETENTION_SECONDS);

        let cutoff = now.saturating_sub(retention);
        let cutoff = sqlite_u64(cutoff, "cleanup cutoff")?;

        Ok(self.connection.execute(
            "DELETE FROM replay_state WHERE expires_at < ?1",
            params![cutoff],
        )?)
    }

    /// Loads rollback-protected governance state for one service scope.
    pub fn load_governance_state(
        &self,
        scope: &str,
    ) -> Result<Option<LocalGovernanceState>, ReplayStoreError> {
        let stored = self
            .connection
            .query_row(
                r#"
                SELECT highest_epoch,
                       checkpoint_hash,
                       validated_at,
                       object_version
                FROM governance_state
                WHERE scope = ?1
                "#,
                params![scope],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, i64>(3)?,
                    ))
                },
            )
            .optional()?;

        let Some((highest_epoch, checkpoint_hash, validated_at, object_version)) = stored else {
            return Ok(None);
        };

        let highest_epoch = u64::try_from(highest_epoch)
            .map_err(|_| ReplayStoreError::IntegerRange("highest_epoch"))?;
        let validated_at = u64::try_from(validated_at)
            .map_err(|_| ReplayStoreError::IntegerRange("validated_at"))?;
        let object_version = u64::try_from(object_version)
            .map_err(|_| ReplayStoreError::IntegerRange("object_version"))?;

        if checkpoint_hash.len() != 32 {
            return Err(ReplayStoreError::InvalidCheckpointHashLength(
                checkpoint_hash.len(),
            ));
        }

        let mut digest = [0_u8; 32];
        digest.copy_from_slice(&checkpoint_hash);

        Ok(Some(LocalGovernanceState {
            highest_epoch,
            checkpoint_hash: Digest32::from_bytes(digest),
            validated_at,
            object_version,
        }))
    }

    /// Persists governance high-water state transactionally.
    ///
    /// The store independently enforces monotonic epoch, object-version,
    /// and validation-time invariants so a future caller cannot accidentally
    /// overwrite durable rollback protection with older state.
    pub fn store_governance_state(
        &mut self,
        scope: &str,
        candidate: &LocalGovernanceState,
    ) -> Result<(), ReplayStoreError> {
        let candidate_epoch = sqlite_u64(candidate.highest_epoch, "highest_epoch")?;
        let candidate_validated_at = sqlite_u64(candidate.validated_at, "validated_at")?;
        let candidate_object_version = sqlite_u64(candidate.object_version, "object_version")?;

        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;

        let existing = transaction
            .query_row(
                r#"
                SELECT highest_epoch,
                       checkpoint_hash,
                       validated_at,
                       object_version
                FROM governance_state
                WHERE scope = ?1
                "#,
                params![scope],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, i64>(3)?,
                    ))
                },
            )
            .optional()?;

        if let Some((stored_epoch, stored_hash, stored_validated_at, stored_object_version)) =
            existing
        {
            let stored_epoch = u64::try_from(stored_epoch)
                .map_err(|_| ReplayStoreError::IntegerRange("stored highest_epoch"))?;
            let stored_validated_at = u64::try_from(stored_validated_at)
                .map_err(|_| ReplayStoreError::IntegerRange("stored validated_at"))?;
            let stored_object_version = u64::try_from(stored_object_version)
                .map_err(|_| ReplayStoreError::IntegerRange("stored object_version"))?;

            if candidate.highest_epoch < stored_epoch {
                return Err(ReplayStoreError::GovernanceEpochRollback {
                    stored: stored_epoch,
                    candidate: candidate.highest_epoch,
                });
            }

            if candidate.highest_epoch == stored_epoch {
                if stored_hash.as_slice() != candidate.checkpoint_hash.as_bytes()
                    || candidate.object_version != stored_object_version
                {
                    return Err(ReplayStoreError::GovernanceConflict {
                        epoch: candidate.highest_epoch,
                    });
                }

                if candidate.validated_at < stored_validated_at {
                    return Err(ReplayStoreError::GovernanceValidationTimeRollback {
                        stored: stored_validated_at,
                        candidate: candidate.validated_at,
                    });
                }
            } else {
                let expected =
                    stored_epoch
                        .checked_add(1)
                        .ok_or(ReplayStoreError::GovernanceEpochGap {
                            stored: stored_epoch,
                            candidate: candidate.highest_epoch,
                        })?;

                if candidate.highest_epoch != expected {
                    return Err(ReplayStoreError::GovernanceEpochGap {
                        stored: stored_epoch,
                        candidate: candidate.highest_epoch,
                    });
                }

                if candidate.object_version <= stored_object_version {
                    return Err(ReplayStoreError::GovernanceObjectVersionRollback {
                        stored: stored_object_version,
                        candidate: candidate.object_version,
                    });
                }

                if candidate.validated_at < stored_validated_at {
                    return Err(ReplayStoreError::GovernanceValidationTimeRollback {
                        stored: stored_validated_at,
                        candidate: candidate.validated_at,
                    });
                }
            }

            transaction.execute(
                r#"
                UPDATE governance_state
                SET highest_epoch   = ?2,
                    checkpoint_hash = ?3,
                    validated_at    = ?4,
                    object_version  = ?5
                WHERE scope = ?1
                "#,
                params![
                    scope,
                    candidate_epoch,
                    candidate.checkpoint_hash.as_bytes().as_slice(),
                    candidate_validated_at,
                    candidate_object_version,
                ],
            )?;
        } else {
            transaction.execute(
                r#"
                INSERT INTO governance_state
                    (
                        scope,
                        highest_epoch,
                        checkpoint_hash,
                        validated_at,
                        object_version
                    )
                VALUES
                    (?1, ?2, ?3, ?4, ?5)
                "#,
                params![
                    scope,
                    candidate_epoch,
                    candidate.checkpoint_hash.as_bytes().as_slice(),
                    candidate_validated_at,
                    candidate_object_version,
                ],
            )?;
        }

        transaction.commit()?;
        Ok(())
    }

    fn transition(
        &mut self,
        scope: &str,
        session_id: &SessionId,
        epoch: u64,
        target: ReplayStatus,
        now: u64,
    ) -> Result<(), ReplayStoreError> {
        let epoch = sqlite_u64(epoch, "epoch")?;
        let now = sqlite_u64(now, "now")?;

        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;

        let current = transaction
            .query_row(
                r#"
                SELECT status
                FROM replay_state
                WHERE scope = ?1
                  AND session_id = ?2
                  AND epoch = ?3
                "#,
                params![scope, session_id.as_bytes().as_slice(), epoch],
                |row| row.get::<_, String>(0),
            )
            .optional()?;

        let Some(current) = current else {
            return Err(ReplayStoreError::MissingReservation);
        };

        let current = ReplayStatus::parse(&current)?;
        if current != ReplayStatus::Pending {
            return Err(ReplayStoreError::InvalidTransition(current));
        }

        transaction.execute(
            r#"
            UPDATE replay_state
            SET status = ?4,
                updated_at = ?5
            WHERE scope = ?1
              AND session_id = ?2
              AND epoch = ?3
            "#,
            params![
                scope,
                session_id.as_bytes().as_slice(),
                epoch,
                target.as_str(),
                now
            ],
        )?;

        transaction.commit()?;
        Ok(())
    }
}

fn sqlite_u64(value: u64, field: &'static str) -> Result<i64, ReplayStoreError> {
    i64::try_from(value).map_err(|_| ReplayStoreError::IntegerRange(field))
}

#[cfg(test)]
mod tests {
    use super::*;
    use getrandom::fill;
    use std::fs;
    use std::path::PathBuf;

    fn temporary_database(name: &str) -> PathBuf {
        let mut random = [0_u8; 16];
        fill(&mut random).unwrap();

        std::env::temp_dir().join(format!(
            "astra-pq-{name}-{}.sqlite3",
            random
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        ))
    }

    fn remove_database(path: &Path) {
        let _ = fs::remove_file(path);
        let _ = fs::remove_file(format!("{}-wal", path.display()));
        let _ = fs::remove_file(format!("{}-shm", path.display()));
    }

    #[test]
    fn duplicate_reservation_is_rejected() {
        let path = temporary_database("duplicate");
        let session = SessionId::from_bytes([1; 32]);

        {
            let mut store = ReplayStore::open(&path).unwrap();
            store.reserve("responder", &session, 7, 200, 100).unwrap();

            assert!(matches!(
                store.reserve("responder", &session, 7, 200, 101),
                Err(ReplayStoreError::AlreadyObserved {
                    status: ReplayStatus::Pending
                })
            ));
        }

        remove_database(&path);
    }

    #[test]
    fn pending_state_survives_restart() {
        let path = temporary_database("restart");
        let session = SessionId::from_bytes([2; 32]);

        {
            let mut first = ReplayStore::open(&path).unwrap();
            first.reserve("responder", &session, 7, 200, 100).unwrap();
        }

        {
            let mut restarted = ReplayStore::open(&path).unwrap();

            assert_eq!(
                restarted.status("responder", &session, 7).unwrap(),
                Some(ReplayStatus::Pending)
            );

            assert!(matches!(
                restarted.reserve("responder", &session, 7, 200, 101),
                Err(ReplayStoreError::AlreadyObserved {
                    status: ReplayStatus::Pending
                })
            ));
        }

        remove_database(&path);
    }

    #[test]
    fn accepted_state_survives_restart() {
        let path = temporary_database("accepted");
        let session = SessionId::from_bytes([3; 32]);

        {
            let mut first = ReplayStore::open(&path).unwrap();
            first.reserve("responder", &session, 7, 200, 100).unwrap();
            first.mark_accepted("responder", &session, 7, 110).unwrap();
        }

        {
            let mut restarted = ReplayStore::open(&path).unwrap();

            assert_eq!(
                restarted.status("responder", &session, 7).unwrap(),
                Some(ReplayStatus::Accepted)
            );

            assert!(matches!(
                restarted.reserve("responder", &session, 7, 200, 120),
                Err(ReplayStoreError::AlreadyObserved {
                    status: ReplayStatus::Accepted
                })
            ));
        }

        remove_database(&path);
    }

    #[test]
    fn rejected_state_is_terminal() {
        let path = temporary_database("rejected");
        let session = SessionId::from_bytes([4; 32]);

        {
            let mut store = ReplayStore::open(&path).unwrap();
            store
                .reserve("authority:a1:risk-floor:1", &session, 7, 200, 100)
                .unwrap();
            store
                .mark_rejected("authority:a1:risk-floor:1", &session, 7, 101)
                .unwrap();

            assert_eq!(
                store
                    .status("authority:a1:risk-floor:1", &session, 7)
                    .unwrap(),
                Some(ReplayStatus::Rejected)
            );

            assert!(matches!(
                store.mark_accepted("authority:a1:risk-floor:1", &session, 7, 102),
                Err(ReplayStoreError::InvalidTransition(ReplayStatus::Rejected))
            ));
        }

        remove_database(&path);
    }

    #[test]
    fn different_scopes_do_not_collide() {
        let path = temporary_database("scope");
        let session = SessionId::from_bytes([5; 32]);

        {
            let mut store = ReplayStore::open(&path).unwrap();

            store
                .reserve("authority:a1:source:1", &session, 7, 200, 100)
                .unwrap();

            store
                .reserve("authority:a1:risk-floor:1", &session, 7, 200, 100)
                .unwrap();
        }

        remove_database(&path);
    }

    #[test]
    fn cleanup_respects_expiry_skew_and_retention() {
        let path = temporary_database("cleanup");
        let session = SessionId::from_bytes([6; 32]);

        {
            let mut store = ReplayStore::open(&path).unwrap();
            store.reserve("responder", &session, 7, 200, 100).unwrap();
            store.mark_accepted("responder", &session, 7, 110).unwrap();

            let protected_until = 200 + SESSION_CLOCK_SKEW_SECONDS + REPLAY_RETENTION_SECONDS;

            assert_eq!(store.cleanup_expired(protected_until).unwrap(), 0);
            assert_eq!(
                store.status("responder", &session, 7).unwrap(),
                Some(ReplayStatus::Accepted)
            );

            assert_eq!(store.cleanup_expired(protected_until + 1).unwrap(), 1);
            assert_eq!(store.status("responder", &session, 7).unwrap(), None);
        }

        remove_database(&path);
    }
    #[test]
    fn governance_state_survives_restart() {
        let path = temporary_database("governance-restart");

        let state = LocalGovernanceState {
            highest_epoch: 4,
            checkpoint_hash: Digest32::from_bytes([41; 32]),
            validated_at: 1_800_000_000,
            object_version: 17,
        };

        {
            let mut store = ReplayStore::open(&path).unwrap();
            assert_eq!(store.load_governance_state("responder").unwrap(), None);
            store.store_governance_state("responder", &state).unwrap();
        }

        {
            let store = ReplayStore::open(&path).unwrap();
            assert_eq!(
                store.load_governance_state("responder").unwrap(),
                Some(state)
            );
        }

        remove_database(&path);
    }

    #[test]
    fn governance_epoch_rollback_is_rejected() {
        let path = temporary_database("governance-rollback");
        let mut store = ReplayStore::open(&path).unwrap();

        let current = LocalGovernanceState {
            highest_epoch: 4,
            checkpoint_hash: Digest32::from_bytes([42; 32]),
            validated_at: 100,
            object_version: 20,
        };

        store
            .store_governance_state("authority:a1", &current)
            .unwrap();

        let older = LocalGovernanceState {
            highest_epoch: 3,
            checkpoint_hash: Digest32::from_bytes([43; 32]),
            validated_at: 101,
            object_version: 19,
        };

        assert!(matches!(
            store.store_governance_state("authority:a1", &older),
            Err(ReplayStoreError::GovernanceEpochRollback { .. })
        ));

        remove_database(&path);
    }

    #[test]
    fn conflicting_same_epoch_governance_state_is_rejected() {
        let path = temporary_database("governance-conflict");
        let mut store = ReplayStore::open(&path).unwrap();

        let current = LocalGovernanceState {
            highest_epoch: 7,
            checkpoint_hash: Digest32::from_bytes([44; 32]),
            validated_at: 200,
            object_version: 31,
        };

        store.store_governance_state("responder", &current).unwrap();

        let conflicting = LocalGovernanceState {
            highest_epoch: 7,
            checkpoint_hash: Digest32::from_bytes([45; 32]),
            validated_at: 201,
            object_version: 31,
        };

        assert!(matches!(
            store.store_governance_state("responder", &conflicting),
            Err(ReplayStoreError::GovernanceConflict { epoch: 7 })
        ));

        remove_database(&path);
    }

    #[test]
    fn governance_successor_is_persisted() {
        let path = temporary_database("governance-successor");
        let mut store = ReplayStore::open(&path).unwrap();

        let first = LocalGovernanceState {
            highest_epoch: 2,
            checkpoint_hash: Digest32::from_bytes([46; 32]),
            validated_at: 300,
            object_version: 8,
        };

        let second = LocalGovernanceState {
            highest_epoch: 3,
            checkpoint_hash: Digest32::from_bytes([47; 32]),
            validated_at: 301,
            object_version: 9,
        };

        store.store_governance_state("responder", &first).unwrap();
        store.store_governance_state("responder", &second).unwrap();

        assert_eq!(
            store.load_governance_state("responder").unwrap(),
            Some(second)
        );

        remove_database(&path);
    }

    #[test]
    fn governance_epoch_gap_is_rejected_by_store() {
        let path = temporary_database("governance-gap");
        let mut store = ReplayStore::open(&path).unwrap();

        let first = LocalGovernanceState {
            highest_epoch: 2,
            checkpoint_hash: Digest32::from_bytes([48; 32]),
            validated_at: 400,
            object_version: 12,
        };

        let gap = LocalGovernanceState {
            highest_epoch: 4,
            checkpoint_hash: Digest32::from_bytes([49; 32]),
            validated_at: 401,
            object_version: 13,
        };

        store.store_governance_state("responder", &first).unwrap();

        assert!(matches!(
            store.store_governance_state("responder", &gap),
            Err(ReplayStoreError::GovernanceEpochGap {
                stored: 2,
                candidate: 4
            })
        ));

        remove_database(&path);
    }
}
