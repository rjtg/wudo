//! Bounded syntax scanning, never cryptographic interpretation.
use super::{Error, Result};
use minicbor::{
    Decoder,
    data::{Int, Type},
};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Key<'a> {
    Text(&'a str),
    Bytes(&'a [u8]),
    Int(Int),
}

/// The recursive call stack is bounded to eight containers, independently of
/// input length. Each map's key slots and the total item budget are bounded.
fn item<'a>(d: &mut Decoder<'a>, depth: usize, budget: &mut usize, inner: bool) -> Result<()> {
    *budget = budget.checked_sub(1).ok_or(Error::InvalidRequest)?;
    match d.datatype()? {
        Type::Map => {
            if depth == 8 {
                return Err(Error::InvalidRequest);
            }
            let n = d.map()?.ok_or(Error::InvalidRequest)?;
            let max = if inner { 128 } else { 16 };
            if n > max {
                return Err(Error::InvalidRequest);
            }
            let mut keys = [None; 128];
            for i in 0..n as usize {
                *budget = budget.checked_sub(1).ok_or(Error::InvalidRequest)?;
                let key = match d.datatype()? {
                    Type::String => {
                        let s = d.str()?;
                        if !inner && s.len() > 32 {
                            return Err(Error::InvalidRequest);
                        }
                        Key::Text(s)
                    }
                    Type::Bytes if inner => Key::Bytes(d.bytes()?),
                    Type::U8
                    | Type::U16
                    | Type::U32
                    | Type::U64
                    | Type::I8
                    | Type::I16
                    | Type::I32
                    | Type::I64
                    | Type::Int
                        if inner =>
                    {
                        Key::Int(d.int()?)
                    }
                    _ => return Err(Error::InvalidRequest),
                };
                if keys[..i].contains(&Some(key)) {
                    return Err(Error::InvalidRequest);
                }
                keys[i] = Some(key);
                item(d, depth + 1, budget, inner)?;
            }
        }
        Type::Array => {
            if depth == 8 {
                return Err(Error::InvalidRequest);
            }
            let n = d.array()?.ok_or(Error::InvalidRequest)?;
            if n > if inner { 256 } else { 16 } {
                return Err(Error::InvalidRequest);
            }
            for _ in 0..n {
                item(d, depth + 1, budget, inner)?;
            }
        }
        Type::String => {
            d.str()?;
        }
        Type::Bytes => {
            d.bytes()?;
        }
        Type::Bool => {
            d.bool()?;
        }
        Type::U8
        | Type::U16
        | Type::U32
        | Type::U64
        | Type::I8
        | Type::I16
        | Type::I32
        | Type::I64
        | Type::Int => {
            d.int()?;
        }
        _ => return Err(Error::InvalidRequest),
    }
    Ok(())
}

pub(super) fn span(d: &mut Decoder<'_>) -> Result<()> {
    item(d, 0, &mut 512, false)
}

pub(super) fn outer(bytes: &[u8]) -> Result<()> {
    let mut d = Decoder::new(bytes);
    span(&mut d)?;
    if d.position() != bytes.len() {
        return Err(Error::InvalidRequest);
    }
    Ok(())
}

pub(super) fn inner_cbor(bytes: &[u8]) -> Result<()> {
    let mut d = Decoder::new(bytes);
    item(&mut d, 0, &mut 256, true)?;
    if d.position() != bytes.len() {
        return Err(Error::InvalidRequest);
    }
    Ok(())
}

#[derive(serde::Deserialize)]
struct ClientData {
    #[serde(rename = "type")]
    kind: String,
    challenge: String,
    origin: String,
    // A missing crossOrigin is false. Explicit null is rejected, not treated
    // as an absent optional field. Derive also rejects duplicate known keys.
    #[serde(default, rename = "crossOrigin")]
    cross_origin: bool,
}

pub(super) fn client_data(bytes: &[u8], registration: bool) -> Result<()> {
    // Validate complexity and duplicate keys before serde skips extension values.
    // Never rewrite these bytes: the verifier receives the original document.
    use serde::de::DeserializeSeed;
    if bytes.is_empty() || bytes.len() > 4096 {
        return Err(Error::InvalidRequest);
    }
    let mut decoder = serde_json::Deserializer::from_slice(bytes);
    JsonBound {
        depth: 0,
        remaining: &mut 64,
    }
    .deserialize(&mut decoder)
    .map_err(|_| Error::InvalidRequest)?;
    decoder.end().map_err(|_| Error::InvalidRequest)?;
    let data: ClientData = serde_json::from_slice(bytes).map_err(|_| Error::InvalidRequest)?;
    if data.kind
        != if registration {
            "webauthn.create"
        } else {
            "webauthn.get"
        }
        || data.cross_origin
        || data.origin.is_empty()
        || data.challenge.is_empty()
    {
        return Err(Error::InvalidRequest);
    }
    // Challenge/origin values and signatures are checked by the verifier.
    Ok(())
}

/// A bounded Serde visitor, not a JSON parser. Serde owns syntax/UTF-8 handling.
struct JsonBound<'a> {
    depth: usize,
    remaining: &'a mut usize,
}
impl JsonBound<'_> {
    fn member<E: serde::de::Error>(&mut self) -> std::result::Result<(), E> {
        *self.remaining = self
            .remaining
            .checked_sub(1)
            .ok_or_else(|| E::custom("JSON budget"))?;
        Ok(())
    }
    fn container<E: serde::de::Error>(&self) -> std::result::Result<(), E> {
        if self.depth >= 8 {
            return Err(E::custom("JSON depth"));
        }
        Ok(())
    }
}
impl<'de> serde::de::DeserializeSeed<'de> for JsonBound<'_> {
    type Value = ();
    fn deserialize<D: serde::Deserializer<'de>>(self, d: D) -> std::result::Result<(), D::Error> {
        d.deserialize_any(self)
    }
}
impl<'de> serde::de::Visitor<'de> for JsonBound<'_> {
    type Value = ();
    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("bounded JSON")
    }
    fn visit_map<M: serde::de::MapAccess<'de>>(
        mut self,
        mut map: M,
    ) -> std::result::Result<(), M::Error> {
        use serde::de::Error;
        self.container()?;
        let mut keys = std::collections::BTreeSet::new();
        while let Some(key) = map.next_key::<String>()? {
            self.member()?;
            if !keys.insert(key.clone()) {
                return Err(M::Error::custom("duplicate JSON key"));
            }
            // Known unsupported ceremony semantics remain rejected.
            if self.depth == 0 && matches!(key.as_str(), "topOrigin" | "tokenBinding") {
                return Err(M::Error::custom("unsupported ceremony field"));
            }
            map.next_value_seed(JsonBound {
                depth: self.depth + 1,
                remaining: self.remaining,
            })?;
        }
        Ok(())
    }
    fn visit_seq<S: serde::de::SeqAccess<'de>>(
        mut self,
        mut seq: S,
    ) -> std::result::Result<(), S::Error> {
        if self.depth == 0 {
            return Err(serde::de::Error::custom("client data must be an object"));
        }
        self.container()?;
        while seq
            .next_element_seed(JsonBound {
                depth: self.depth + 1,
                remaining: self.remaining,
            })?
            .is_some()
        {
            self.member()?;
        }
        Ok(())
    }
    fn visit_bool<E: serde::de::Error>(self, _: bool) -> std::result::Result<(), E> {
        Ok(())
    }
    fn visit_i64<E: serde::de::Error>(self, _: i64) -> std::result::Result<(), E> {
        Ok(())
    }
    fn visit_u64<E: serde::de::Error>(self, _: u64) -> std::result::Result<(), E> {
        Ok(())
    }
    fn visit_f64<E: serde::de::Error>(self, _: f64) -> std::result::Result<(), E> {
        Ok(())
    }
    fn visit_str<E: serde::de::Error>(self, _: &str) -> std::result::Result<(), E> {
        Ok(())
    }
    fn visit_unit<E: serde::de::Error>(self) -> std::result::Result<(), E> {
        Ok(())
    }
}

/// Bounds the outer attestation CBOR syntax only. Embedded authenticator data
/// remains opaque and must be parsed/validated through the verifier adapter.
pub(super) fn attestation(bytes: &[u8]) -> Result<()> {
    if Decoder::new(bytes).datatype()? != Type::Map {
        return Err(Error::InvalidRequest);
    }
    inner_cbor(bytes)
}
