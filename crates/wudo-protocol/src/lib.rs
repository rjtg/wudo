//! Bounded IPC codecs without I/O or privileged behavior.
//! The default v1 status codec performs no heap decoding; v2 is opt-in.
#[cfg(feature = "v2")]
pub mod v2;
use minicbor::{Decoder, Encoder, encode::write::Cursor};

pub const MAX_PAYLOAD: usize = 4096;
pub const ADMIN_SOCKET: &str = "/run/wudo/admin.sock";
pub const WEB_SOCKET: &str = "/run/wudo/web.sock";
pub const DEADLINE_SECONDS: u64 = 5;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    InvalidRequest,
    UnsupportedVersion,
    UnsupportedOperation,
}
impl ErrorCode {
    fn name(self) -> &'static str {
        match self {
            Self::InvalidRequest => "invalid-request",
            Self::UnsupportedVersion => "unsupported-version",
            Self::UnsupportedOperation => "unsupported-operation",
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Request {
    Status,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Response {
    Ready,
    Error(ErrorCode),
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WireError;

pub fn payload_len(header: [u8; 4]) -> Result<usize, WireError> {
    let length = u32::from_be_bytes(header);
    if length == 0 || length > MAX_PAYLOAD as u32 {
        Err(WireError)
    } else {
        Ok(length as usize)
    }
}
fn text<'a>(d: &mut Decoder<'a>, max: usize) -> Result<&'a str, WireError> {
    let value = d.str().map_err(|_| WireError)?;
    if value.len() > max {
        return Err(WireError);
    }
    Ok(value)
}
fn set<T>(slot: &mut Option<T>, value: T) -> Result<(), WireError> {
    if slot.is_some() {
        return Err(WireError);
    }
    *slot = Some(value);
    Ok(())
}
fn decoder(bytes: &[u8], count: u64) -> Result<Decoder<'_>, WireError> {
    if bytes.is_empty() || bytes.len() > MAX_PAYLOAD {
        return Err(WireError);
    }
    let mut d = Decoder::new(bytes);
    if d.map().map_err(|_| WireError)? != Some(count) {
        return Err(WireError);
    }
    Ok(d)
}
fn request_fields(bytes: &[u8]) -> Result<(u64, &str), WireError> {
    let mut d = decoder(bytes, 2)?;
    let (mut version, mut operation) = (None, None);
    for _ in 0..2 {
        match text(&mut d, 16)? {
            "version" => set(&mut version, d.u64().map_err(|_| WireError)?)?,
            "operation" => set(&mut operation, text(&mut d, 32)?)?,
            _ => return Err(WireError),
        }
    }
    if d.position() != bytes.len() {
        return Err(WireError);
    }
    Ok((version.ok_or(WireError)?, operation.ok_or(WireError)?))
}
pub fn decode_request(bytes: &[u8]) -> Result<Request, ErrorCode> {
    let (version, operation) = request_fields(bytes).map_err(|_| ErrorCode::InvalidRequest)?;
    if version != 1 {
        return Err(ErrorCode::UnsupportedVersion);
    }
    if operation != "status" {
        return Err(ErrorCode::UnsupportedOperation);
    }
    Ok(Request::Status)
}
pub fn decode_response(bytes: &[u8]) -> Result<Response, WireError> {
    let mut d = decoder(bytes, 3)?;
    let (mut version, mut result, mut status, mut code) = (None, None, None, None);
    for _ in 0..3 {
        match text(&mut d, 16)? {
            "version" => set(&mut version, d.u64().map_err(|_| WireError)?)?,
            "result" => set(&mut result, text(&mut d, 32)?)?,
            "status" => set(&mut status, text(&mut d, 32)?)?,
            "code" => set(&mut code, text(&mut d, 32)?)?,
            _ => return Err(WireError),
        }
    }
    if d.position() != bytes.len() || version != Some(1) {
        return Err(WireError);
    }
    match (result, status, code) {
        (Some("ok"), Some("ready"), None) => Ok(Response::Ready),
        (Some("error"), None, Some(code)) => Ok(Response::Error(match code {
            "invalid-request" => ErrorCode::InvalidRequest,
            "unsupported-version" => ErrorCode::UnsupportedVersion,
            "unsupported-operation" => ErrorCode::UnsupportedOperation,
            _ => return Err(WireError),
        })),
        _ => Err(WireError),
    }
}
/// Only constant server-generated fields are encoded; no input is reflected.
pub struct Encoded {
    bytes: [u8; 128],
    len: usize,
}
impl AsRef<[u8]> for Encoded {
    fn as_ref(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}
fn encode(response: Option<Response>) -> Result<Encoded, WireError> {
    let mut bytes = [0; 128];
    let mut e = Encoder::new(Cursor::new(&mut bytes[..]));
    e.map(if response.is_some() { 3 } else { 2 })
        .map_err(|_| WireError)?;
    e.str("version")
        .and_then(|e| e.u64(1))
        .map_err(|_| WireError)?;
    match response {
        None => {
            e.str("operation")
                .and_then(|e| e.str("status"))
                .map_err(|_| WireError)?;
        }
        Some(Response::Ready) => {
            e.str("result")
                .and_then(|e| e.str("ok"))
                .and_then(|e| e.str("status"))
                .and_then(|e| e.str("ready"))
                .map_err(|_| WireError)?;
        }
        Some(Response::Error(code)) => {
            e.str("result")
                .and_then(|e| e.str("error"))
                .and_then(|e| e.str("code"))
                .and_then(|e| e.str(code.name()))
                .map_err(|_| WireError)?;
        }
    }
    let len = e.into_writer().position();
    Ok(Encoded { bytes, len })
}
pub fn encode_request() -> Result<Encoded, WireError> {
    encode(None)
}
pub fn encode_response(response: Response) -> Result<Encoded, WireError> {
    encode(Some(response))
}
