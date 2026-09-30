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
#[serde(deny_unknown_fields)]
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
    // Exactly three strings and an optional boolean: no containers can nest.
    // The input is already capped to 4096 bytes by the outer schema.
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

/// Bounds the outer attestation CBOR syntax only. Embedded authenticator data
/// remains opaque and must be parsed/validated through the verifier adapter.
pub(super) fn attestation(bytes: &[u8]) -> Result<()> {
    if Decoder::new(bytes).datatype()? != Type::Map {
        return Err(Error::InvalidRequest);
    }
    inner_cbor(bytes)
}
