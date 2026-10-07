//! Synchronous user persistence for a trusted, private local directory.
//! Not a privileged path resolver or an authentication/authorization API.
//! The caller must keep the directory and its ancestors stable and trusted for
//! the store lifetime. No daemon integration or network-selected paths.
mod grants;
pub use grants::ActionSummary;
mod administration;
pub use administration::{CredentialSummary, Page};
mod credentials;
mod installation;
pub use credentials::{
    AuthenticationSnapshot, MAX_ACTIVE_CREDENTIALS, MAX_CREDENTIALS, RECORD_FORMAT,
};

use rusqlite::{Connection, OpenFlags, OptionalExtension, TransactionBehavior, params};
use std::{
    fs,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
    time::Duration,
};

pub const MAX_USERS: usize = 64;
const APP_ID: i64 = 0x5755444f;
pub const SCHEMA_VERSION: usize = 4;
fn migrations() -> rusqlite_migration::Migrations<'static> {
    rusqlite_migration::Migrations::new(vec![
        rusqlite_migration::M::up(include_str!("../migrations/001_users.sql")),
        rusqlite_migration::M::up(include_str!("../migrations/002_credentials.sql")),
        rusqlite_migration::M::up(include_str!("../migrations/003_installation.sql")),
        rusqlite_migration::M::up(include_str!("../migrations/004_grants.sql")),
    ])
}
const MAX_DB: u64 = 4 * 1024 * 1024;
const SCHEMA: &str = "CREATE TABLE users (id BLOB PRIMARY KEY NOT NULL CHECK(length(id)=16), name TEXT NOT NULL UNIQUE CHECK(length(CAST(name AS BLOB)) BETWEEN 1 AND 64), label TEXT NOT NULL CHECK(length(CAST(label AS BLOB)) BETWEEN 1 AND 128)) STRICT";

/// Category-only failures never retain SQL, paths, user data or OS errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    InvalidInput,
    Conflict,
    Capacity,
    UnsupportedSchema,
    UpgradeRequired,
    InvalidStore,
    Unavailable,
}
pub type Result<T> = std::result::Result<T, Error>;
impl From<rusqlite::Error> for Error {
    fn from(_: rusqlite::Error) -> Self {
        Self::Unavailable
    }
}
impl From<std::io::Error> for Error {
    fn from(_: std::io::Error) -> Self {
        Self::Unavailable
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct UserId([u8; 16]);
impl UserId {
    pub fn from_bytes(bytes: [u8; 16]) -> Result<Self> {
        if bytes[6] >> 4 != 4 || bytes[8] >> 6 != 2 {
            return Err(Error::InvalidInput);
        }
        Ok(Self(bytes))
    }
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}
#[derive(Clone, PartialEq, Eq)]
pub struct User {
    pub id: UserId,
    pub name: String,
    pub label: String,
}

pub struct Store {
    connection: Connection,
    healthy: bool,
}

fn valid_name(name: &str) -> bool {
    let b = name.as_bytes();
    if b.is_empty() || b.len() > 64 || !b[0].is_ascii_lowercase() {
        return false;
    }
    let mut separator = false;
    for &c in b {
        if c.is_ascii_lowercase() || c.is_ascii_digit() {
            separator = false;
        } else if b"._-".contains(&c) && !separator {
            separator = true;
        } else {
            return false;
        }
    }
    !separator
}
fn valid_label(label: &str) -> bool {
    !label.is_empty() && label.len() <= 128 && !label.chars().any(char::is_control)
}
fn private(path: &Path, directory: bool) -> Result<()> {
    let m = fs::symlink_metadata(path)?;
    let mode = if directory { 0o700 } else { 0o600 };
    if m.uid() != rustix::process::geteuid().as_raw()
        || m.mode() & 0o7777 != mode
        || if directory {
            !m.is_dir()
        } else {
            !m.is_file() || m.nlink() != 1 || m.len() > MAX_DB
        }
    {
        return Err(Error::InvalidStore);
    }
    Ok(())
}
fn directory(path: &Path) -> Result<()> {
    if !path.is_absolute() {
        return Err(Error::InvalidStore);
    }
    private(path, true)
}

impl Store {
    /// Explicitly create a new store. Never overwrites or repairs existing state.
    /// Failure may leave an incomplete file; opening it fails closed.
    pub fn initialize(dir: &Path) -> Result<Self> {
        directory(dir)?;
        for leaf in [
            "identity.sqlite3-journal",
            "identity.sqlite3-wal",
            "identity.sqlite3-shm",
        ] {
            match fs::symlink_metadata(dir.join(leaf)) {
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                _ => return Err(Error::InvalidStore),
            }
        }
        let path = dir.join("identity.sqlite3");
        let file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::AlreadyExists {
                    Error::Conflict
                } else {
                    Error::Unavailable
                }
            })?;
        let mut connection = Self::connect(dir)?;
        migrations()
            .to_latest(&mut connection)
            .map_err(|_| Error::Unavailable)?;
        file.sync_all()?;
        fs::File::open(dir)?.sync_all()?;
        Ok(Self {
            connection,
            healthy: true,
        })
    }

    /// Open an existing store; missing, empty and incompatible databases fail.
    pub fn open(dir: &Path) -> Result<Self> {
        let store = Self::open_for_upgrade(dir)?;
        if store.needs_upgrade()? {
            return Err(Error::UpgradeRequired);
        }
        Ok(store)
    }

    /// Validate a recognized historical layout without migrating it.
    pub fn open_for_upgrade(dir: &Path) -> Result<Self> {
        let connection = Self::connect(dir)?;
        let store = Self {
            connection,
            healthy: true,
        };
        store.validate()?;
        Ok(store)
    }

    pub fn needs_upgrade(&self) -> Result<bool> {
        let version: i64 = self
            .connection
            .query_row("PRAGMA user_version", [], |r| r.get(0))?;
        Ok(version < SCHEMA_VERSION as i64)
    }

    /// Inspect a recognized schema without upgrading it. Unsupported older versions
    /// must gain explicit validation here when a real migration is introduced.
    pub fn schema_version(dir: &Path) -> Result<usize> {
        let store = Self::open_for_upgrade(dir)?;
        let version: i64 = store
            .connection
            .query_row("PRAGMA user_version", [], |r| r.get(0))?;
        usize::try_from(version).map_err(|_| Error::UnsupportedSchema)
    }

    /// Explicit upgrade only, never initialization or downgrade.
    pub fn upgrade(dir: &Path) -> Result<Self> {
        let mut store = Self::open_for_upgrade(dir)?;
        migrations()
            .to_latest(&mut store.connection)
            .map_err(|_| Error::Unavailable)?;
        store.validate()?;
        Ok(store)
    }

    fn connect(dir: &Path) -> Result<Connection> {
        directory(dir)?;
        let path = dir.join("identity.sqlite3");
        private(&path, false)?;
        for leaf in [
            "identity.sqlite3-journal",
            "identity.sqlite3-wal",
            "identity.sqlite3-shm",
        ] {
            let p = dir.join(leaf);
            match fs::symlink_metadata(&p) {
                Ok(_) => {
                    private(&p, false)?;
                    if leaf != "identity.sqlite3-journal" {
                        return Err(Error::InvalidStore);
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => return Err(Error::Unavailable),
            }
        }
        let c = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )?;
        c.busy_timeout(Duration::from_millis(100))?;
        c.set_db_config(rusqlite::config::DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true)?;
        c.set_limit(rusqlite::limits::Limit::SQLITE_LIMIT_LENGTH, 65536)?;
        c.set_limit(rusqlite::limits::Limit::SQLITE_LIMIT_SQL_LENGTH, 4096)?;
        c.set_limit(rusqlite::limits::Limit::SQLITE_LIMIT_ATTACHED, 0)?;
        c.execute_batch("PRAGMA trusted_schema=OFF; PRAGMA foreign_keys=ON; PRAGMA synchronous=EXTRA; PRAGMA temp_store=MEMORY; PRAGMA cell_size_check=ON;")?;
        let synchronous: i64 = c.query_row("PRAGMA synchronous", [], |r| r.get(0))?;
        if synchronous != 3 {
            return Err(Error::Unavailable);
        }
        let journal: String = c.query_row("PRAGMA journal_mode", [], |r| r.get(0))?;
        if journal != "delete" {
            return Err(Error::InvalidStore);
        }
        c.pragma_update(None, "max_page_count", 1024)?;
        let page_size: i64 = c.query_row("PRAGMA page_size", [], |r| r.get(0))?;
        if page_size != 4096 {
            return Err(Error::InvalidStore);
        }
        Ok(c)
    }

    fn validate(&self) -> Result<()> {
        let c = &self.connection;
        let app: i64 = c.query_row("PRAGMA application_id", [], |r| r.get(0))?;
        let version: i64 = c.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        if app != APP_ID || !(1..=SCHEMA_VERSION as i64).contains(&version) {
            return Err(Error::UnsupportedSchema);
        }
        let check: String = c.query_row("PRAGMA quick_check(1)", [], |r| r.get(0))?;
        if check != "ok" {
            return Err(Error::InvalidStore);
        }
        let count: i64 = c.query_row(
            "SELECT count(*) FROM sqlite_schema WHERE sql IS NOT NULL",
            [],
            |r| r.get(0),
        )?;
        let schema: String = c.query_row(
            "SELECT sql FROM sqlite_schema WHERE type='table' AND name='users'",
            [],
            |r| r.get(0),
        )?;
        if count != (if version == 4 { 5 } else { version }) || schema != SCHEMA {
            return Err(Error::InvalidStore);
        }
        let mut stmt = c.prepare("SELECT id, name, label FROM users LIMIT 65")?;
        let mut rows = stmt.query([])?;
        let mut count = 0;
        while let Some(row) = rows.next()? {
            decode(row)?;
            count += 1;
        }
        if count > MAX_USERS {
            return Err(Error::InvalidStore);
        }
        if version >= 2 {
            self.validate_credentials()?;
        }
        if version >= 3 {
            self.validate_installation()?;
        }
        if version >= 4 {
            self.validate_grants()?;
        }
        Ok(())
    }

    pub fn create_user(&mut self, name: &str, label: &str) -> Result<User> {
        if !self.healthy || self.needs_upgrade()? {
            return Err(Error::Unavailable);
        }
        if !valid_name(name) || !valid_label(label) {
            return Err(Error::InvalidInput);
        }
        let mut id = [0; 16];
        getrandom::fill(&mut id).map_err(|_| Error::Unavailable)?;
        id[6] = (id[6] & 0x0f) | 0x40;
        id[8] = (id[8] & 0x3f) | 0x80;
        let result = self.insert(id, name, label);
        if result == Err(Error::Unavailable) {
            self.healthy = false;
        }
        result?;
        Ok(User {
            id: UserId(id),
            name: name.into(),
            label: label.into(),
        })
    }

    fn insert(&mut self, id: [u8; 16], name: &str, label: &str) -> Result<()> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let exists: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM users WHERE name=?1 OR id=?2)",
            params![name, id.as_slice()],
            |r| r.get(0),
        )?;
        if exists {
            return Err(Error::Conflict);
        }
        let count: i64 = tx.query_row("SELECT count(*) FROM users", [], |r| r.get(0))?;
        if count >= MAX_USERS as i64 {
            return Err(Error::Capacity);
        }
        tx.execute(
            "INSERT INTO users(id,name,label) VALUES (?1,?2,?3)",
            params![id.as_slice(), name, label],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn user_by_id(&self, id: UserId) -> Result<Option<User>> {
        if !self.healthy || self.needs_upgrade()? {
            return Err(Error::Unavailable);
        }
        self.connection
            .query_row(
                "SELECT id,name,label FROM users WHERE id=?1",
                [id.0.as_slice()],
                |r| Ok(decode(r)),
            )
            .optional()?
            .transpose()
    }
    pub fn user_by_name(&self, name: &str) -> Result<Option<User>> {
        if !self.healthy || self.needs_upgrade()? {
            return Err(Error::Unavailable);
        }
        if !valid_name(name) {
            return Err(Error::InvalidInput);
        }
        self.connection
            .query_row(
                "SELECT id,name,label FROM users WHERE name=?1",
                [name],
                |r| Ok(decode(r)),
            )
            .optional()?
            .transpose()
    }
}

fn decode(row: &rusqlite::Row<'_>) -> Result<User> {
    let bytes: Vec<u8> = row.get(0)?;
    let id = UserId::from_bytes(bytes.try_into().map_err(|_| Error::InvalidStore)?)
        .map_err(|_| Error::InvalidStore)?;
    let name: String = row.get(1)?;
    let label: String = row.get(2)?;
    if !valid_name(&name) || !valid_label(&label) {
        return Err(Error::InvalidStore);
    }
    Ok(User { id, name, label })
}

#[cfg(test)]
mod migration_tests {
    use super::*;
    #[test]
    fn embedded_schema_matches_v1_and_failed_upgrade_rolls_back() {
        use rusqlite_migration::{M, Migrations};
        migrations().validate().unwrap();
        let mut c = Connection::open_in_memory().unwrap();
        Migrations::new(vec![M::up(include_str!("../migrations/001_users.sql"))])
            .to_latest(&mut c)
            .unwrap();
        let sql: String = c
            .query_row(
                "SELECT sql FROM sqlite_schema WHERE name='users'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(sql, SCHEMA);
        c.execute(
            "INSERT INTO users VALUES (?1,'alice','Alice')",
            [[0u8; 16].as_slice()],
        )
        .unwrap();
        // Synthetic v2 exercises the runner without inventing a production schema.
        let failing = Migrations::new(vec![
            M::up(include_str!("../migrations/001_users.sql")),
            M::up("ALTER TABLE users ADD COLUMN extra TEXT; INSERT INTO missing VALUES(1);"),
        ]);
        assert!(failing.to_latest(&mut c).is_err());
        let v: i64 = c
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(v, 1);
        let sql: String = c
            .query_row(
                "SELECT sql FROM sqlite_schema WHERE name='users'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(sql, SCHEMA);
        let n: i64 = c
            .query_row("SELECT count(*) FROM users", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 1);
    }
}
