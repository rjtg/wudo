use crate::{Error, Page, Result, Store, UserId, valid_name};
use rusqlite::{OptionalExtension, TransactionBehavior, params};
use wudo_core::config::{ActionDefinition, Config};

pub struct ActionSummary {
    pub id: String,
    pub description: String,
    pub revision: [u8; 32],
}
impl Store {
    fn grants_ready(&self) -> Result<()> {
        if !self.healthy || self.needs_upgrade()? {
            return Err(Error::Unavailable);
        }
        Ok(())
    }
    /// Reconcile a fully validated startup snapshot atomically. Deleting a
    /// changed action cascades grants before a fresh revision is inserted.
    pub fn reconcile_actions(&mut self, config: &Config) -> Result<()> {
        self.grants_ready()?;
        let definitions = config.definitions().map_err(|_| Error::InvalidInput)?;
        let result = (|| {
            let tx = self
                .connection
                .transaction_with_behavior(TransactionBehavior::Immediate)?;
            let old: Vec<(String, Vec<u8>)> = {
                let mut stmt =
                    tx.prepare("SELECT id,definition FROM actions ORDER BY id LIMIT 129")?;
                stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
                    .collect::<std::result::Result<_, _>>()?
            };
            if old.len() > 128 {
                return Err(Error::InvalidStore);
            }
            for (id, bytes) in &old {
                if !definitions.iter().any(|d| &d.id == id && &d.bytes == bytes) {
                    tx.execute("DELETE FROM actions WHERE id=?1", [id])?;
                }
            }
            for d in &definitions {
                if old
                    .iter()
                    .any(|(id, bytes)| id == &d.id && bytes == &d.bytes)
                {
                    continue;
                }
                let mut revision = [0; 32];
                getrandom::fill(&mut revision).map_err(|_| Error::Unavailable)?;
                tx.execute(
                    "INSERT INTO actions(id,revision,definition) VALUES(?1,?2,?3)",
                    params![d.id, revision.as_slice(), d.bytes],
                )?;
            }
            tx.commit()?;
            Ok(())
        })();
        if result.is_err() {
            self.healthy = false;
        }
        result
    }
    /// Local administration only. Absence differs from an idempotent mutation.
    pub fn set_grant(
        &mut self,
        user: UserId,
        action: &str,
        granted: bool,
    ) -> Result<Option<[u8; 32]>> {
        self.grants_ready()?;
        if !valid_name(action) {
            return Err(Error::InvalidInput);
        }
        let result = (|| {
            let tx = self
                .connection
                .transaction_with_behavior(TransactionBehavior::Immediate)?;
            let exists: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM users WHERE id=?1)",
                [user.as_bytes().as_slice()],
                |r| r.get(0),
            )?;
            let revision: Option<Vec<u8>> = tx
                .query_row("SELECT revision FROM actions WHERE id=?1", [action], |r| {
                    r.get(0)
                })
                .optional()?;
            let Some(revision) = revision.filter(|_| exists) else {
                return Ok(None);
            };
            let revision: [u8; 32] = revision.try_into().map_err(|_| Error::InvalidStore)?;
            if granted {
                tx.execute("INSERT INTO grants(user_id,action_id,revision) VALUES(?1,?2,?3) ON CONFLICT(user_id,action_id) DO NOTHING",params![user.as_bytes().as_slice(),action,revision.as_slice()])?;
            } else {
                tx.execute(
                    "DELETE FROM grants WHERE user_id=?1 AND action_id=?2",
                    params![user.as_bytes().as_slice(), action],
                )?;
            }
            tx.commit()?;
            Ok(Some(revision))
        })();
        if matches!(result, Err(Error::Unavailable | Error::InvalidStore)) {
            self.healthy = false;
        }
        result
    }
    pub fn list_actions(&self, after: Option<&str>) -> Result<Page<ActionSummary, String>> {
        self.action_page(None, after)
    }
    pub fn list_grants(
        &self,
        user: UserId,
        after: Option<&str>,
    ) -> Result<Option<Page<ActionSummary, String>>> {
        if self.user_by_id(user)?.is_none() {
            return Ok(None);
        }
        self.action_page(Some(user), after).map(Some)
    }
    fn action_page(
        &self,
        user: Option<UserId>,
        after: Option<&str>,
    ) -> Result<Page<ActionSummary, String>> {
        self.grants_ready()?;
        if after.is_some_and(|v| !valid_name(v)) {
            return Err(Error::InvalidInput);
        }
        let mut stmt=self.connection.prepare("SELECT a.id,a.revision,a.definition FROM actions a WHERE a.id>?1 AND (?2 IS NULL OR EXISTS(SELECT 1 FROM grants g WHERE g.user_id=?2 AND g.action_id=a.id AND g.revision=a.revision)) ORDER BY a.id LIMIT 17")?;
        let mut rows = stmt.query(params![
            after.unwrap_or(""),
            user.map(|u| u.as_bytes().to_vec())
        ])?;
        let mut items = Vec::new();
        while let Some(row) = rows.next()? {
            let id: String = row.get(0)?;
            let rev: Vec<u8> = row.get(1)?;
            let bytes: Vec<u8> = row.get(2)?;
            let d = ActionDefinition::decode(&bytes).map_err(|_| Error::InvalidStore)?;
            if d.id != id {
                return Err(Error::InvalidStore);
            }
            items.push(ActionSummary {
                id,
                revision: rev.try_into().map_err(|_| Error::InvalidStore)?,
                description: d.description,
            });
        }
        let next_after = if items.len() > 16 {
            items.pop();
            items.last().map(|a| a.id.clone())
        } else {
            None
        };
        Ok(Page { items, next_after })
    }
    pub(super) fn validate_grants(&self) -> Result<()> {
        for statement in include_str!("../migrations/004_grants.sql")
            .split(';')
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            let table = if statement.starts_with("CREATE TABLE actions ") {
                "actions"
            } else {
                "grants"
            };
            let sql: String = self.connection.query_row(
                "SELECT sql FROM sqlite_schema WHERE type='table' AND name=?1",
                [table],
                |r| r.get(0),
            )?;
            if sql != statement {
                return Err(Error::InvalidStore);
            }
        }
        let mut stmt = self
            .connection
            .prepare("SELECT id,revision,definition FROM actions LIMIT 129")?;
        let mut rows = stmt.query([])?;
        let mut count = 0;
        while let Some(r) = rows.next()? {
            count += 1;
            let id: String = r.get(0)?;
            let revision: Vec<u8> = r.get(1)?;
            let bytes: Vec<u8> = r.get(2)?;
            let d = ActionDefinition::decode(&bytes).map_err(|_| Error::InvalidStore)?;
            if d.id != id || revision.len() != 32 || count > 128 {
                return Err(Error::InvalidStore);
            }
        }
        let invalid:bool=self.connection.query_row("SELECT EXISTS(SELECT 1 FROM grants g LEFT JOIN users u ON g.user_id=u.id LEFT JOIN actions a ON g.action_id=a.id AND g.revision=a.revision WHERE u.id IS NULL OR a.id IS NULL) OR (SELECT count(*) FROM grants)>8192",[],|r|r.get(0))?;
        if invalid {
            return Err(Error::InvalidStore);
        }
        Ok(())
    }
}
