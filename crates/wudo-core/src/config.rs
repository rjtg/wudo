//! Strict action/resource configuration parsing, independent of host state.
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};
use toml::{Table, Value};

pub const MAX_INPUT_BYTES: usize = 256 * 1024;
pub const MAX_ACTIONS: usize = 128;
pub const MAX_RESOURCES: usize = 32;

type Result<T> = std::result::Result<T, ConfigError>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ErrorKind {
    InputTooLarge,
    InvalidToml,
    InvalidSchema,
    UnsupportedSchema,
    UnknownField,
    InvalidValue,
    MissingReference,
    ConflictingResource,
}

/// Contains no input values, source excerpts or third-party error messages.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConfigError(ErrorKind);
impl ConfigError {
    pub fn kind(self) -> ErrorKind {
        self.0
    }
}
impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self.0 {
            ErrorKind::InputTooLarge => "input-too-large",
            ErrorKind::InvalidToml => "invalid-toml",
            ErrorKind::InvalidSchema => "invalid-schema",
            ErrorKind::UnsupportedSchema => "unsupported-schema",
            ErrorKind::UnknownField => "unknown-field",
            ErrorKind::InvalidValue => "invalid-value",
            ErrorKind::MissingReference => "missing-reference",
            ErrorKind::ConflictingResource => "conflicting-resource",
        })
    }
}
impl std::error::Error for ConfigError {}
fn error(kind: ErrorKind) -> ConfigError {
    ConfigError(kind)
}

fn name(value: &str, max: usize, separators: &[u8]) -> bool {
    let bytes = value.as_bytes();
    if bytes.is_empty() || bytes.len() > max || !bytes[0].is_ascii_lowercase() {
        return false;
    }
    let mut previous_separator = false;
    for &b in bytes {
        if b.is_ascii_lowercase() || b.is_ascii_digit() {
            previous_separator = false;
        } else if separators.contains(&b) && !previous_separator {
            previous_separator = true;
        } else {
            return false;
        }
    }
    !previous_separator
}

macro_rules! identifier {
    ($id:ident) => {
        #[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
        pub struct $id(String);
        impl $id {
            pub fn new(value: impl Into<String>) -> Result<Self> {
                let value = value.into();
                if !name(&value, 64, b"._-") {
                    return Err(error(ErrorKind::InvalidValue));
                }
                Ok(Self(value))
            }
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }
    };
}
identifier!(ActionId);
identifier!(ResourceId);
identifier!(SecretId);

#[derive(Debug)]
pub struct Config {
    resources: BTreeMap<ResourceId, Resource>,
    actions: BTreeMap<ActionId, Action>,
}
#[derive(Debug)]
pub enum Resource {
    Luks2 {
        luks_uuid: String,
        mapping_name: String,
        managed_secret: SecretId,
    },
}
#[derive(Debug)]
pub struct Action {
    pub description: String,
    pub confirmation: bool,
    pub timeout_seconds: u16,
    pub output_limit_bytes: u32,
    pub operation: Operation,
    pub prerequisite: Option<Prerequisite>,
}
#[derive(Debug)]
pub enum Operation {
    LuksUnlock { resource: ResourceId },
    SystemdStart { unit: String },
    SystemdStop { unit: String },
}
#[derive(Debug)]
pub enum Prerequisite {
    LuksUnlocked { resource: ResourceId },
}

impl Config {
    pub fn resources(&self) -> &BTreeMap<ResourceId, Resource> {
        &self.resources
    }
    pub fn actions(&self) -> &BTreeMap<ActionId, Action> {
        &self.actions
    }

    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_INPUT_BYTES {
            return Err(error(ErrorKind::InputTooLarge));
        }
        let text = std::str::from_utf8(bytes).map_err(|_| error(ErrorKind::InvalidToml))?;
        if text.starts_with('\u{feff}') {
            return Err(error(ErrorKind::InvalidToml));
        }
        // toml 0.8's default parser recursion limit remains enabled. Never enable
        // toml_edit's unbounded feature. Raw parser errors must not escape.
        let mut root: Table = text.parse().map_err(|_| error(ErrorKind::InvalidToml))?;
        fields(&root, &["schema_version", "resources", "actions"])?;
        if integer(&mut root, "schema_version")? != 1 {
            return Err(error(ErrorKind::UnsupportedSchema));
        }
        let resource_tables = table(&mut root, "resources")?;
        let action_tables = table(&mut root, "actions")?;
        if resource_tables.len() > MAX_RESOURCES || action_tables.len() > MAX_ACTIONS {
            return Err(error(ErrorKind::InvalidValue));
        }
        let mut resources = BTreeMap::new();
        let mut uuids = BTreeSet::new();
        let mut mappings = BTreeSet::new();
        let mut secrets = BTreeSet::new();
        for (id, value) in resource_tables {
            let id = ResourceId::new(id)?;
            let mut t = into_table(value)?;
            fields(&t, &["kind", "luks_uuid", "mapping_name", "managed_secret"])?;
            if string(&mut t, "kind")? != "luks2" {
                return Err(error(ErrorKind::InvalidValue));
            }
            let uuid = string(&mut t, "luks_uuid")?;
            if !valid_uuid(&uuid) {
                return Err(error(ErrorKind::InvalidValue));
            }
            let mapping = string(&mut t, "mapping_name")?;
            if !name(&mapping, 64, b"_-") {
                return Err(error(ErrorKind::InvalidValue));
            }
            let mut secret = table(&mut t, "managed_secret")?;
            fields(&secret, &["id"])?;
            let secret = SecretId::new(string(&mut secret, "id")?)?;
            if !uuids.insert(uuid.clone())
                || !mappings.insert(mapping.clone())
                || !secrets.insert(secret.clone())
            {
                return Err(error(ErrorKind::ConflictingResource));
            }
            resources.insert(
                id,
                Resource::Luks2 {
                    luks_uuid: uuid,
                    mapping_name: mapping,
                    managed_secret: secret,
                },
            );
        }
        let mut actions = BTreeMap::new();
        for (id, value) in action_tables {
            let id = ActionId::new(id)?;
            let mut t = into_table(value)?;
            fields(
                &t,
                &[
                    "description",
                    "confirmation",
                    "timeout_seconds",
                    "output_limit_bytes",
                    "operation",
                    "prerequisite",
                ],
            )?;
            let description = string(&mut t, "description")?;
            if description.trim().is_empty()
                || description.len() > 256
                || description.chars().any(char::is_control)
            {
                return Err(error(ErrorKind::InvalidValue));
            }
            let confirmation = match take(&mut t, "confirmation")? {
                Value::Boolean(v) => v,
                _ => return Err(error(ErrorKind::InvalidSchema)),
            };
            let timeout = integer(&mut t, "timeout_seconds")?;
            let output = integer(&mut t, "output_limit_bytes")?;
            if !(1..=600).contains(&timeout) || !(0..=65_536).contains(&output) {
                return Err(error(ErrorKind::InvalidValue));
            }
            let mut op = table(&mut t, "operation")?;
            let operation = match string(&mut op, "kind")?.as_str() {
                "luks-unlock" => {
                    fields(&op, &["resource"])?;
                    Operation::LuksUnlock {
                        resource: reference(&mut op, &resources)?,
                    }
                }
                "systemd-start" => {
                    fields(&op, &["unit"])?;
                    Operation::SystemdStart {
                        unit: unit(&mut op)?,
                    }
                }
                "systemd-stop" => {
                    fields(&op, &["unit"])?;
                    Operation::SystemdStop {
                        unit: unit(&mut op)?,
                    }
                }
                _ => return Err(error(ErrorKind::InvalidValue)),
            };
            let prerequisite = if let Some(value) = t.remove("prerequisite") {
                if !matches!(operation, Operation::SystemdStart { .. }) {
                    return Err(error(ErrorKind::InvalidValue));
                }
                let mut p = into_table(value)?;
                fields(&p, &["kind", "resource"])?;
                if string(&mut p, "kind")? != "luks-unlocked" {
                    return Err(error(ErrorKind::InvalidValue));
                }
                Some(Prerequisite::LuksUnlocked {
                    resource: reference(&mut p, &resources)?,
                })
            } else {
                None
            };
            actions.insert(
                id,
                Action {
                    description,
                    confirmation,
                    timeout_seconds: timeout as u16,
                    output_limit_bytes: output as u32,
                    operation,
                    prerequisite,
                },
            );
        }
        Ok(Self { resources, actions })
    }
}
fn fields(t: &Table, allowed: &[&str]) -> Result<()> {
    if t.keys().any(|k| !allowed.contains(&k.as_str())) {
        return Err(error(ErrorKind::UnknownField));
    }
    Ok(())
}
fn take(t: &mut Table, key: &str) -> Result<Value> {
    t.remove(key).ok_or(error(ErrorKind::InvalidSchema))
}
fn into_table(v: Value) -> Result<Table> {
    match v {
        Value::Table(t) => Ok(t),
        _ => Err(error(ErrorKind::InvalidSchema)),
    }
}
fn table(t: &mut Table, key: &str) -> Result<Table> {
    into_table(take(t, key)?)
}
fn string(t: &mut Table, key: &str) -> Result<String> {
    match take(t, key)? {
        Value::String(s) => Ok(s),
        _ => Err(error(ErrorKind::InvalidSchema)),
    }
}
fn integer(t: &mut Table, key: &str) -> Result<i64> {
    match take(t, key)? {
        Value::Integer(i) => Ok(i),
        _ => Err(error(ErrorKind::InvalidSchema)),
    }
}
fn reference(t: &mut Table, resources: &BTreeMap<ResourceId, Resource>) -> Result<ResourceId> {
    let id = ResourceId::new(string(t, "resource")?)?;
    if !resources.contains_key(&id) {
        return Err(error(ErrorKind::MissingReference));
    }
    Ok(id)
}
fn valid_uuid(s: &str) -> bool {
    s.len() == 36
        && s.bytes().enumerate().all(|(i, b)| {
            if [8, 13, 18, 23].contains(&i) {
                b == b'-'
            } else {
                b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
            }
        })
        && s.bytes().any(|b| b != b'0' && b != b'-')
}
fn unit(t: &mut Table) -> Result<String> {
    let unit = string(t, "unit")?;
    let stem = unit
        .strip_suffix(".service")
        .or_else(|| unit.strip_suffix(".target"));
    if unit.len() > 128 || !stem.is_some_and(|s| name(s, 128, b"._-")) {
        return Err(error(ErrorKind::InvalidValue));
    }
    Ok(unit)
}
