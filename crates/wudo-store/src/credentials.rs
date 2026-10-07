//! Trusted internal persistence API. Only a verified, operation-bound candidate
//! may reach activation; accepting a Passkey is not proof of verification.
use crate::{Error, Result, Store, UserId};
use rusqlite::{OptionalExtension, TransactionBehavior, params};
use webauthn_rs::prelude::{AuthenticationResult, Passkey};

/// Opaque, owner-bound verification snapshot. Not an authentication grant.
/// Keep this on the daemon side and use its passkey to begin verification.
pub struct AuthenticationSnapshot {
    user: UserId,
    key: Passkey,
    record: Vec<u8>,
}
impl AuthenticationSnapshot {
    pub fn passkey(&self) -> &Passkey {
        &self.key
    }
}

pub const RECORD_FORMAT: i64 = 1; // webauthn-rs 0.5.5 Passkey JSON, writer-normalized.
pub const MAX_ACTIVE_CREDENTIALS: i64 = 16;
pub const MAX_CREDENTIALS: i64 = 1024; // Includes retained revoked records.
const MAX_RECORD: usize = 16384;
fn valid_id(id: &[u8]) -> bool {
    !id.is_empty() && id.len() <= 1023
}
fn encode(key: &Passkey) -> Result<Vec<u8>> {
    let bytes = serde_json::to_vec(key).map_err(|_| Error::InvalidInput)?;
    if !valid_id(key.cred_id().as_ref()) || bytes.len() > MAX_RECORD {
        return Err(Error::InvalidInput);
    }
    Ok(bytes)
}
fn decode(id: &[u8], format: i64, bytes: &[u8]) -> Result<Passkey> {
    if format != RECORD_FORMAT || !valid_id(id) || bytes.is_empty() || bytes.len() > MAX_RECORD {
        return Err(Error::InvalidStore);
    }
    let key: Passkey = serde_json::from_slice(bytes).map_err(|_| Error::InvalidStore)?;
    // Only our writer's exact representation is accepted. Unknown/duplicate fields
    // or alternate encodings cannot be silently discarded by permissive Serde types.
    if key.cred_id().as_ref() != id || encode(&key).map_err(|_| Error::InvalidStore)? != bytes {
        return Err(Error::InvalidStore);
    }
    Ok(key)
}
impl Store {
    /// Capture the exact active record used by a future verification ceremony.
    pub fn authentication_snapshot(
        &self,
        user: UserId,
        id: &[u8],
    ) -> Result<Option<AuthenticationSnapshot>> {
        self.credential_for_authentication(user, id)?
            .map(|key| {
                let record = encode(&key)?;
                Ok(AuthenticationSnapshot { user, key, record })
            })
            .transpose()
    }

    /// Apply only the established verifier's metadata update, after rechecking
    /// the owner, active status and exact verification snapshot in a transaction.
    /// The caller must supply the genuine result for this snapshot's single-use,
    /// purpose-bound ceremony. This API neither verifies assertions nor grants
    /// action/session authority. A conflict requires a fresh ceremony, not retry.
    /// Returns whether metadata changed; even a no-change result rechecks state.
    pub fn commit_authentication(
        &mut self,
        snapshot: AuthenticationSnapshot,
        result: &AuthenticationResult,
    ) -> Result<bool> {
        self.credentials_ready()?;
        let mut key = snapshot.key;
        let changed = key.update_credential(result).ok_or(Error::InvalidInput)?;
        let record = encode(&key)?;
        let outcome = (|| {
            let tx = self
                .connection
                .transaction_with_behavior(TransactionBehavior::Immediate)?;
            let current: Option<(i64, Vec<u8>)> = tx.query_row(
                "SELECT format,record FROM credentials WHERE id=?1 AND user_id=?2 AND revoked=0",
                params![key.cred_id().as_ref(), snapshot.user.as_bytes().as_slice()],
                |r| Ok((r.get(0)?, r.get(1)?)),
            ).optional()?;
            let Some((format, bytes)) = current else {
                return Err(Error::Conflict);
            };
            decode(key.cred_id().as_ref(), format, &bytes)?;
            if bytes != snapshot.record {
                return Err(Error::Conflict);
            }
            if changed {
                let rows = tx.execute(
                    "UPDATE credentials SET record=?1 WHERE id=?2 AND user_id=?3 AND revoked=0",
                    params![
                        record,
                        key.cred_id().as_ref(),
                        snapshot.user.as_bytes().as_slice()
                    ],
                )?;
                if rows != 1 {
                    return Err(Error::InvalidStore);
                }
            }
            tx.commit()?;
            Ok(changed)
        })();
        self.credential_write_result(outcome)
    }

    /// Includes retained revoked records; transient reservations are daemon-owned.
    pub fn remaining_credential_capacity(&self) -> Result<usize> {
        self.credentials_ready()?;
        let count: i64 =
            self.connection
                .query_row("SELECT count(*) FROM credentials", [], |r| r.get(0))?;
        Ok((MAX_CREDENTIALS - count).max(0) as usize)
    }

    /// Includes retained revoked IDs. Enrollment must never reuse them.
    pub fn credential_id_exists(&self, id: &[u8]) -> Result<bool> {
        self.credentials_ready()?;
        if !valid_id(id) {
            return Err(Error::InvalidInput);
        }
        Ok(self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM credentials WHERE id=?1)",
            [id],
            |r| r.get(0),
        )?)
    }
    /// Trusted enrollment snapshot. Activation must recheck capacity atomically.
    pub fn enrollment_credentials(&self, user: UserId) -> Result<Vec<Vec<u8>>> {
        self.credentials_ready()?;
        if self.user_by_id(user)?.is_none() {
            return Err(Error::InvalidInput);
        }
        let total: i64 =
            self.connection
                .query_row("SELECT count(*) FROM credentials", [], |r| r.get(0))?;
        let mut query = self
            .connection
            .prepare("SELECT id FROM credentials WHERE user_id=?1 AND revoked=0 LIMIT 17")?;
        let ids = query
            .query_map([user.as_bytes().as_slice()], |r| r.get::<_, Vec<u8>>(0))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        if total >= MAX_CREDENTIALS || ids.len() >= MAX_ACTIVE_CREDENTIALS as usize {
            return Err(Error::Capacity);
        }
        Ok(ids)
    }
    fn credentials_ready(&self) -> Result<()> {
        if !self.healthy || self.needs_upgrade()? {
            return Err(Error::Unavailable);
        }
        Ok(())
    }
    fn credential_write_result<T>(&mut self, result: Result<T>) -> Result<T> {
        if matches!(result, Err(Error::Unavailable | Error::InvalidStore)) {
            self.healthy = false;
        }
        result
    }
    /// Activate a verified candidate for an existing user, never replace an ID.
    /// The caller must enforce ceremony, candidate approval and ownership binding.
    pub fn activate_credential(&mut self, user: UserId, key: &Passkey) -> Result<()> {
        self.credentials_ready()?;
        let record = encode(key)?;
        let result = (|| {
            let tx = self
                .connection
                .transaction_with_behavior(TransactionBehavior::Immediate)?;
            let user_exists: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM users WHERE id=?1)",
                [user.as_bytes().as_slice()],
                |r| r.get(0),
            )?;
            if !user_exists {
                return Err(Error::InvalidInput);
            }
            let exists: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM credentials WHERE id=?1)",
                [key.cred_id().as_ref()],
                |r| r.get(0),
            )?;
            if exists {
                return Err(Error::Conflict);
            }
            let total: i64 = tx.query_row("SELECT count(*) FROM credentials", [], |r| r.get(0))?;
            let active: i64 = tx.query_row(
                "SELECT count(*) FROM credentials WHERE user_id=?1 AND revoked=0",
                [user.as_bytes().as_slice()],
                |r| r.get(0),
            )?;
            if total >= MAX_CREDENTIALS || active >= MAX_ACTIVE_CREDENTIALS {
                return Err(Error::Capacity);
            }
            tx.execute(
                "INSERT INTO credentials(id,user_id,format,record,revoked) VALUES(?1,?2,?3,?4,0)",
                params![
                    key.cred_id().as_ref(),
                    user.as_bytes().as_slice(),
                    RECORD_FORMAT,
                    record
                ],
            )?;
            tx.commit()?;
            Ok(())
        })();
        self.credential_write_result(result)
    }
    /// Only active credentials owned by the specified user are eligible.
    /// This lookup does not authorize an action or eliminate the admission recheck.
    pub fn credential_for_authentication(
        &self,
        user: UserId,
        id: &[u8],
    ) -> Result<Option<Passkey>> {
        self.credentials_ready()?;
        if !valid_id(id) {
            return Err(Error::InvalidInput);
        }
        self.connection
            .query_row(
                "SELECT format,record FROM credentials WHERE id=?1 AND user_id=?2 AND revoked=0",
                params![id, user.as_bytes().as_slice()],
                |r| Ok((r.get::<_, i64>(0)?, r.get::<_, Vec<u8>>(1)?)),
            )
            .optional()?
            .map(|(format, bytes)| decode(id, format, &bytes))
            .transpose()
    }
    /// Retain the record permanently. Returns true only for an active -> revoked transition.
    pub fn revoke_credential(&mut self, id: &[u8]) -> Result<bool> {
        self.credentials_ready()?;
        if !valid_id(id) {
            return Err(Error::InvalidInput);
        }
        let result = (|| {
            let tx = self
                .connection
                .transaction_with_behavior(TransactionBehavior::Immediate)?;
            let changed = tx.execute(
                "UPDATE credentials SET revoked=1 WHERE id=?1 AND revoked=0",
                [id],
            )?;
            tx.commit()?;
            Ok(changed == 1)
        })();
        self.credential_write_result(result)
    }
    pub(super) fn validate_credentials(&self) -> Result<()> {
        let schema: String = self.connection.query_row(
            "SELECT sql FROM sqlite_schema WHERE type='table' AND name='credentials'",
            [],
            |r| r.get(0),
        )?;
        let expected = include_str!("../migrations/002_credentials.sql")
            .trim()
            .trim_end_matches(';');
        if schema != expected {
            return Err(Error::InvalidStore);
        }
        let fk: bool = self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM pragma_foreign_key_check)",
            [],
            |r| r.get(0),
        )?;
        let overfull: bool = self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM credentials WHERE revoked=0 GROUP BY user_id HAVING count(*)>?1)",
            [MAX_ACTIVE_CREDENTIALS],
            |r| r.get(0),
        )?;
        if fk || overfull {
            return Err(Error::InvalidStore);
        }
        let mut stmt = self
            .connection
            .prepare("SELECT id,user_id,format,record,revoked FROM credentials LIMIT 1025")?;
        let mut rows = stmt.query([])?;
        let mut count = 0;
        while let Some(r) = rows.next()? {
            let id: Vec<u8> = r.get(0)?;
            let owner: Vec<u8> = r.get(1)?;
            UserId::from_bytes(owner.try_into().map_err(|_| Error::InvalidStore)?)
                .map_err(|_| Error::InvalidStore)?;
            let format: i64 = r.get(2)?;
            let bytes: Vec<u8> = r.get(3)?;
            let revoked: i64 = r.get(4)?;
            if ![0, 1].contains(&revoked) {
                return Err(Error::InvalidStore);
            }
            decode(&id, format, &bytes)?;
            count += 1;
            if count > MAX_CREDENTIALS {
                return Err(Error::InvalidStore);
            }
        }
        Ok(())
    }
}
