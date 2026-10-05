use crate::{Error, Result, Store};
use rusqlite::{OptionalExtension, TransactionBehavior};
use wudo_protocol::v2::InstallationOrigin;
impl Store {
    /// Explicit root recovery: one transaction replaces all currently supported
    /// Wudo identity/settings state. Does not delete files or external resources.
    pub fn reset_installation(&mut self, origin: &str) -> Result<()> {
        if !self.healthy || self.needs_upgrade()? {
            return Err(Error::Unavailable);
        }
        let origin = InstallationOrigin::parse(origin).map_err(|_| Error::InvalidInput)?;
        let result = (|| {
            let tx = self
                .connection
                .transaction_with_behavior(TransactionBehavior::Immediate)?;
            tx.execute("DELETE FROM credentials", [])?;
            tx.execute("DELETE FROM users", [])?;
            tx.execute("DELETE FROM installation", [])?;
            tx.execute(
                "INSERT INTO installation(id,origin) VALUES(1,?1)",
                [origin.as_str()],
            )?;
            tx.commit()?;
            Ok(())
        })();
        if matches!(result, Err(Error::Unavailable)) {
            self.healthy = false;
        }
        result
    }

    /// Configure once, preserving users. Never bind historical credentials to an
    /// origin that cannot be inferred from their public records.
    pub fn configure_installation(&mut self, origin: &str) -> Result<()> {
        if !self.healthy || self.needs_upgrade()? {
            return Err(Error::Unavailable);
        }
        let origin = InstallationOrigin::parse(origin).map_err(|_| Error::InvalidInput)?;
        let result = (|| {
            let tx = self
                .connection
                .transaction_with_behavior(TransactionBehavior::Immediate)?;
            let occupied: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM installation) OR EXISTS(SELECT 1 FROM credentials)",
                [],
                |r| r.get(0),
            )?;
            if occupied {
                return Err(Error::Conflict);
            }
            tx.execute(
                "INSERT INTO installation(id,origin) VALUES(1,?1)",
                [origin.as_str()],
            )?;
            tx.commit()?;
            Ok(())
        })();
        if matches!(result, Err(Error::Unavailable)) {
            self.healthy = false;
        }
        result
    }
    pub fn installation_origin(&self) -> Result<Option<InstallationOrigin>> {
        if !self.healthy || self.needs_upgrade()? {
            return Err(Error::Unavailable);
        }
        let value: Option<String> = self
            .connection
            .query_row("SELECT origin FROM installation WHERE id=1", [], |r| {
                r.get(0)
            })
            .optional()?;
        value
            .map(|s| {
                let parsed = InstallationOrigin::parse(&s).map_err(|_| Error::InvalidStore)?;
                if parsed.as_str() != s {
                    return Err(Error::InvalidStore);
                }
                Ok(parsed)
            })
            .transpose()
    }
    pub(super) fn validate_installation(&self) -> Result<()> {
        let sql: String = self.connection.query_row(
            "SELECT sql FROM sqlite_schema WHERE name='installation' AND type='table'",
            [],
            |r| r.get(0),
        )?;
        if sql
            != include_str!("../migrations/003_installation.sql")
                .trim()
                .trim_end_matches(';')
        {
            return Err(Error::InvalidStore);
        }
        let invalid: bool = self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM installation WHERE id!=1)",
            [],
            |r| r.get(0),
        )?;
        if invalid {
            return Err(Error::InvalidStore);
        }
        self.installation_origin()?;
        Ok(())
    }
}
