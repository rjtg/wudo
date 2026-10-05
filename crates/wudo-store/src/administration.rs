//! Bounded root-administration projections. Never expose verifier records.
use crate::{Error, Result, Store, User, UserId, decode, valid_name};
use rusqlite::{OptionalExtension, TransactionBehavior, params};

pub struct Page<T, C> {
    pub items: Vec<T>,
    pub next_after: Option<C>,
}
#[derive(Debug, PartialEq, Eq)]
pub struct CredentialSummary {
    pub id: Vec<u8>,
    pub revoked: bool,
}
fn credential(row: &rusqlite::Row<'_>) -> Result<CredentialSummary> {
    let id: Vec<u8> = row.get(0)?;
    let revoked: i64 = row.get(1)?;
    if id.is_empty() || id.len() > 1023 || ![0, 1].contains(&revoked) {
        return Err(Error::InvalidStore);
    }
    Ok(CredentialSummary {
        id,
        revoked: revoked == 1,
    })
}
fn valid_id(id: &[u8]) -> Result<()> {
    if id.is_empty() || id.len() > 1023 {
        Err(Error::InvalidInput)
    } else {
        Ok(())
    }
}
impl Store {
    fn administration_ready(&self) -> Result<()> {
        if !self.healthy || self.needs_upgrade()? {
            return Err(Error::Unavailable);
        }
        Ok(())
    }
    pub fn list_users(&self, after: Option<&str>) -> Result<Page<User, String>> {
        self.administration_ready()?;
        if after.is_some_and(|s| !valid_name(s)) {
            return Err(Error::InvalidInput);
        }
        let mut q = self
            .connection
            .prepare("SELECT id,name,label FROM users WHERE name>?1 ORDER BY name LIMIT 17")?;
        let mut items = q
            .query_map([after.unwrap_or("")], |r| Ok(decode(r)))?
            .collect::<std::result::Result<Vec<_>, _>>()?
            .into_iter()
            .collect::<Result<Vec<_>>>()?;
        let next_after = if items.len() > 16 {
            items.truncate(16);
            Some(items[15].name.clone())
        } else {
            None
        };
        Ok(Page { items, next_after })
    }
    pub fn list_credentials(
        &self,
        user: UserId,
        after: Option<&[u8]>,
    ) -> Result<Option<Page<CredentialSummary, Vec<u8>>>> {
        self.administration_ready()?;
        if let Some(id) = after {
            valid_id(id)?;
        }
        if self.user_by_id(user)?.is_none() {
            return Ok(None);
        }
        let mut q = self.connection.prepare(
            "SELECT id,revoked FROM credentials WHERE user_id=?1 AND id>?2 ORDER BY id LIMIT 17",
        )?;
        let mut items = q
            .query_map(
                params![user.as_bytes().as_slice(), after.unwrap_or(&[])],
                |r| Ok(credential(r)),
            )?
            .collect::<std::result::Result<Vec<_>, _>>()?
            .into_iter()
            .collect::<Result<Vec<_>>>()?;
        let next_after = if items.len() > 16 {
            items.truncate(16);
            Some(items[15].id.clone())
        } else {
            None
        };
        Ok(Some(Page { items, next_after }))
    }
    pub fn inspect_credential(&self, user: UserId, id: &[u8]) -> Result<Option<CredentialSummary>> {
        self.administration_ready()?;
        valid_id(id)?;
        self.connection
            .query_row(
                "SELECT id,revoked FROM credentials WHERE user_id=?1 AND id=?2",
                params![user.as_bytes().as_slice(), id],
                |r| Ok(credential(r)),
            )
            .optional()?
            .transpose()
    }
    /// Owner check and terminal transition share one transaction. None means no
    /// matching owner/ID; an already-revoked matching record is a success.
    pub fn revoke_owned_credential(
        &mut self,
        user: UserId,
        id: &[u8],
    ) -> Result<Option<CredentialSummary>> {
        self.administration_ready()?;
        valid_id(id)?;
        let result = (|| {
            let tx = self
                .connection
                .transaction_with_behavior(TransactionBehavior::Immediate)?;
            let found = tx
                .query_row(
                    "SELECT id,revoked FROM credentials WHERE user_id=?1 AND id=?2",
                    params![user.as_bytes().as_slice(), id],
                    |r| Ok(credential(r)),
                )
                .optional()?
                .transpose()?;
            let Some(mut record) = found else {
                return Ok(None);
            };
            if !record.revoked {
                tx.execute(
                    "UPDATE credentials SET revoked=1 WHERE user_id=?1 AND id=?2 AND revoked=0",
                    params![user.as_bytes().as_slice(), id],
                )?;
            }
            tx.commit()?;
            record.revoked = true;
            Ok(Some(record))
        })();
        if matches!(result, Err(Error::Unavailable | Error::InvalidStore)) {
            self.healthy = false;
        }
        result
    }
}
