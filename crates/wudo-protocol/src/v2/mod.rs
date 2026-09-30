//! Opt-in v2 codec. Decoded messages are unverified input, never authorization.
//! No handlers, storage, random generation, WebAuthn verification or execution.
//! Encoders validate their output; on error the caller must discard the buffer.
mod bounded;
mod types;
pub use types::*;

use minicbor::{Decoder, Encoder, encode::write::Cursor};

pub const MAX_PAYLOAD: usize = 65_536;
pub type Result<T> = std::result::Result<T, Error>;
type Writer<'a> = Encoder<Cursor<&'a mut [u8]>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    InvalidRequest,
    UnsupportedVersion,
    UnsupportedOperation,
    NotPermitted,
    Unavailable,
    VerificationFailed,
    Busy,
    Conflict,
    InternalError,
}
impl From<minicbor::decode::Error> for Error {
    fn from(_: minicbor::decode::Error) -> Self {
        Self::InvalidRequest
    }
}
impl<E> From<minicbor::encode::Error<E>> for Error {
    fn from(_: minicbor::encode::Error<E>) -> Self {
        Self::InvalidRequest
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Endpoint {
    Admin,
    Web,
}

pub fn payload_len(header: [u8; 4]) -> Result<usize> {
    let n = u32::from_be_bytes(header);
    if n == 0 || n > MAX_PAYLOAD as u32 {
        return Err(Error::InvalidRequest);
    }
    Ok(n as usize)
}

trait Wire<'a>: Sized {
    fn read(bytes: &'a [u8]) -> Result<Self>;
    fn write(&self, e: &mut Writer<'_>) -> Result<()>;
}

struct Fields<'a> {
    slots: [Option<(&'a str, &'a [u8])>; 16],
}
impl<'a> Fields<'a> {
    fn read(bytes: &'a [u8]) -> Result<Self> {
        let mut d = Decoder::new(bytes);
        let n = d.map()?.ok_or(Error::InvalidRequest)?;
        if n > 16 {
            return Err(Error::InvalidRequest);
        }
        let mut slots = [None; 16];
        for i in 0..n as usize {
            let key = d.str()?;
            if key.len() > 32 || slots[..i].iter().flatten().any(|(k, _)| *k == key) {
                return Err(Error::InvalidRequest);
            }
            let start = d.position();
            bounded::span(&mut d)?;
            slots[i] = Some((key, &bytes[start..d.position()]));
        }
        if d.position() != bytes.len() {
            return Err(Error::InvalidRequest);
        }
        Ok(Self { slots })
    }
    fn raw(&mut self, key: &str) -> Option<&'a [u8]> {
        self.slots
            .iter_mut()
            .find(|s| s.as_ref().is_some_and(|(k, _)| *k == key))
            .and_then(Option::take)
            .map(|(_, v)| v)
    }
    fn take<T: Wire<'a>>(&mut self, key: &str) -> Result<T> {
        T::read(self.raw(key).ok_or(Error::InvalidRequest)?)
    }
    fn optional<T: Wire<'a>>(&mut self, key: &str) -> Result<Option<T>> {
        self.raw(key).map(T::read).transpose()
    }
    fn finish(self) -> Result<()> {
        if self.slots.iter().any(Option::is_some) {
            Err(Error::InvalidRequest)
        } else {
            Ok(())
        }
    }
}

fn complete(bytes: &[u8], d: &Decoder<'_>) -> Result<()> {
    if d.position() == bytes.len() {
        Ok(())
    } else {
        Err(Error::InvalidRequest)
    }
}

impl<'a> Wire<'a> for &'a str {
    fn read(bytes: &'a [u8]) -> Result<Self> {
        let mut d = Decoder::new(bytes);
        let s = d.str()?;
        complete(bytes, &d)?;
        Ok(s)
    }
    fn write(&self, e: &mut Writer<'_>) -> Result<()> {
        e.str(self)?;
        Ok(())
    }
}
impl<'a> Wire<'a> for bool {
    fn read(bytes: &'a [u8]) -> Result<Self> {
        let mut d = Decoder::new(bytes);
        let value = d.bool()?;
        complete(bytes, &d)?;
        Ok(value)
    }
    fn write(&self, e: &mut Writer<'_>) -> Result<()> {
        e.bool(*self)?;
        Ok(())
    }
}
impl<'a> Wire<'a> for u64 {
    fn read(bytes: &'a [u8]) -> Result<Self> {
        let mut d = Decoder::new(bytes);
        let value = d.u64()?;
        complete(bytes, &d)?;
        Ok(value)
    }
    fn write(&self, e: &mut Writer<'_>) -> Result<()> {
        e.u64(*self)?;
        Ok(())
    }
}

fn checked(bytes: &[u8]) -> Result<Fields<'_>> {
    if bytes.is_empty() || bytes.len() > MAX_PAYLOAD {
        return Err(Error::InvalidRequest);
    }
    bounded::outer(bytes)?;
    let mut fields = Fields::read(bytes)?;
    if fields.take::<u64>("version")? != 2 {
        return Err(Error::UnsupportedVersion);
    }
    Ok(fields)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operation {
    Status,
    UserCreate,
    EnrollmentOpen,
    EnrollmentInspect,
    EnrollmentCancel,
    EnrollmentApprove,
    RegistrationBegin,
    RegistrationBeginInsecure,
    RegistrationFinish,
    ActionBegin,
    ActionFinish,
}
impl Operation {
    pub fn allowed(self, endpoint: Endpoint) -> bool {
        match self {
            Self::Status => true,
            Self::UserCreate
            | Self::EnrollmentOpen
            | Self::EnrollmentInspect
            | Self::EnrollmentCancel
            | Self::EnrollmentApprove => endpoint == Endpoint::Admin,
            _ => endpoint == Endpoint::Web,
        }
    }
    pub fn request_limit(self) -> usize {
        match self {
            Self::RegistrationFinish => 40960,
            Self::ActionFinish => 12288,
            _ => 4096,
        }
    }
    pub fn response_limit(self) -> usize {
        match self {
            Self::RegistrationBegin | Self::RegistrationBeginInsecure | Self::ActionBegin => {
                MAX_PAYLOAD
            }
            _ => 4096,
        }
    }
    fn name(self) -> &'static str {
        match self {
            Self::Status => "status",
            Self::UserCreate => "user.create",
            Self::EnrollmentOpen => "enrollment.open",
            Self::EnrollmentInspect => "enrollment.inspect",
            Self::EnrollmentCancel => "enrollment.cancel",
            Self::EnrollmentApprove => "enrollment.approve",
            Self::RegistrationBegin => "registration.begin",
            Self::RegistrationBeginInsecure => "registration.begin_insecure",
            Self::RegistrationFinish => "registration.finish",
            Self::ActionBegin => "action.begin",
            Self::ActionFinish => "action.finish",
        }
    }
    fn parse(s: &str) -> Result<Self> {
        [
            Self::Status,
            Self::UserCreate,
            Self::EnrollmentOpen,
            Self::EnrollmentInspect,
            Self::EnrollmentCancel,
            Self::EnrollmentApprove,
            Self::RegistrationBegin,
            Self::RegistrationBeginInsecure,
            Self::RegistrationFinish,
            Self::ActionBegin,
            Self::ActionFinish,
        ]
        .into_iter()
        .find(|op| op.name() == s)
        .ok_or(Error::UnsupportedOperation)
    }
}

// Messages deliberately do not implement Debug: tickets and credential data
// must not become diagnostics through a derived formatter.
#[derive(Clone, PartialEq, Eq)]
pub enum Request<'a> {
    Status,
    UserCreate(UserCreate<'a>),
    EnrollmentOpen(EnrollmentOpen),
    EnrollmentInspect(EnrollmentRef),
    EnrollmentCancel(EnrollmentRef),
    EnrollmentApprove(EnrollmentApprove),
    RegistrationBegin(RegistrationBegin),
    RegistrationBeginInsecure,
    RegistrationFinish(RegistrationFinish<'a>),
    ActionBegin(ActionBegin<'a>),
    ActionFinish(ActionFinish<'a>),
}
impl Request<'_> {
    pub fn operation(&self) -> Operation {
        match self {
            Self::Status => Operation::Status,
            Self::UserCreate(_) => Operation::UserCreate,
            Self::EnrollmentOpen(_) => Operation::EnrollmentOpen,
            Self::EnrollmentInspect(_) => Operation::EnrollmentInspect,
            Self::EnrollmentCancel(_) => Operation::EnrollmentCancel,
            Self::EnrollmentApprove(_) => Operation::EnrollmentApprove,
            Self::RegistrationBegin(_) => Operation::RegistrationBegin,
            Self::RegistrationBeginInsecure => Operation::RegistrationBeginInsecure,
            Self::RegistrationFinish(_) => Operation::RegistrationFinish,
            Self::ActionBegin(_) => Operation::ActionBegin,
            Self::ActionFinish(_) => Operation::ActionFinish,
        }
    }
}

pub fn decode_request(bytes: &[u8], endpoint: Endpoint) -> Result<Request<'_>> {
    let mut envelope = checked(bytes)?;
    let name: &str = envelope.take("operation")?;
    let body = envelope.raw("body").ok_or(Error::InvalidRequest)?;
    envelope.finish()?;
    if name.len() > 32 {
        return Err(Error::InvalidRequest);
    }
    // Even unknown operations require a map body, not a scalar/array.
    if Decoder::new(body).datatype()? != minicbor::data::Type::Map {
        return Err(Error::InvalidRequest);
    }
    let op = Operation::parse(name)?;
    if !op.allowed(endpoint) {
        return Err(Error::NotPermitted);
    }
    if bytes.len() > op.request_limit() {
        return Err(Error::InvalidRequest);
    }
    let request = match op {
        Operation::Status => {
            Fields::read(body)?.finish()?;
            Request::Status
        }
        Operation::UserCreate => Request::UserCreate(UserCreate::read(body)?),
        Operation::EnrollmentOpen => Request::EnrollmentOpen(EnrollmentOpen::read(body)?),
        Operation::EnrollmentInspect => Request::EnrollmentInspect(EnrollmentRef::read(body)?),
        Operation::EnrollmentCancel => Request::EnrollmentCancel(EnrollmentRef::read(body)?),
        Operation::EnrollmentApprove => Request::EnrollmentApprove(EnrollmentApprove::read(body)?),
        Operation::RegistrationBegin => Request::RegistrationBegin(RegistrationBegin::read(body)?),
        Operation::RegistrationBeginInsecure => {
            Fields::read(body)?.finish()?;
            Request::RegistrationBeginInsecure
        }
        Operation::RegistrationFinish => {
            Request::RegistrationFinish(RegistrationFinish::read(body)?)
        }
        Operation::ActionBegin => Request::ActionBegin(ActionBegin::read(body)?),
        Operation::ActionFinish => Request::ActionFinish(ActionFinish::read(body)?),
    };
    match &request {
        Request::RegistrationFinish(v) => {
            bounded::client_data(v.client_data.0, true)?;
            bounded::attestation(v.attestation_object.0)?;
        }
        Request::ActionFinish(v) => bounded::client_data(v.client_data.0, false)?,
        _ => {}
    }
    Ok(request)
}

pub fn encode_request(out: &mut [u8], request: &Request<'_>, endpoint: Endpoint) -> Result<usize> {
    let op = request.operation();
    let cap = out.len().min(op.request_limit());
    let mut e = Encoder::new(Cursor::new(&mut out[..cap]));
    e.map(3)?
        .str("version")?
        .u8(2)?
        .str("operation")?
        .str(op.name())?
        .str("body")?;
    match request {
        Request::Status | Request::RegistrationBeginInsecure => {
            e.map(0)?;
        }
        Request::UserCreate(v) => v.write(&mut e)?,
        Request::EnrollmentOpen(v) => v.write(&mut e)?,
        Request::EnrollmentInspect(v) | Request::EnrollmentCancel(v) => v.write(&mut e)?,
        Request::EnrollmentApprove(v) => v.write(&mut e)?,
        Request::RegistrationBegin(v) => v.write(&mut e)?,
        Request::RegistrationFinish(v) => v.write(&mut e)?,
        Request::ActionBegin(v) => v.write(&mut e)?,
        Request::ActionFinish(v) => v.write(&mut e)?,
    }
    let n = e.into_writer().position();
    decode_request(&out[..n], endpoint)?;
    Ok(n)
}

#[derive(Clone, PartialEq, Eq)]
pub enum Response<'a> {
    Status(StatusResult),
    UserCreated(UserCreated),
    Opened(Opened),
    OpenInspection(OpenInspection),
    CandidateInspection(CandidateInspection<'a>),
    Cancelled(CancelledResult),
    Activated(Activated<'a>),
    RegistrationChallenge(RegistrationChallenge<'a>),
    Registered(Registered),
    ActionChallenge(ActionChallenge<'a>),
    Admitted(Admitted),
    Error(Error),
}

impl Error {
    fn code(self) -> Result<&'static str> {
        Ok(match self {
            Self::InvalidRequest => "invalid-request",
            Self::UnsupportedOperation => "unsupported-operation",
            Self::NotPermitted => "not-permitted",
            Self::Unavailable => "unavailable",
            Self::VerificationFailed => "verification-failed",
            Self::Busy => "busy",
            Self::Conflict => "conflict",
            Self::InternalError => "internal-error",
            // Unsupported versions use the existing v1 error envelope, never v2.
            Self::UnsupportedVersion => return Err(Self::InvalidRequest),
        })
    }
    fn from_code(value: &str) -> Result<Self> {
        [
            Self::InvalidRequest,
            Self::UnsupportedOperation,
            Self::NotPermitted,
            Self::Unavailable,
            Self::VerificationFailed,
            Self::Busy,
            Self::Conflict,
            Self::InternalError,
        ]
        .into_iter()
        .find(|e| e.code() == Ok(value))
        .ok_or(Self::InvalidRequest)
    }
}

/// The expected request supplies response context, including enrollment mode.
/// This does not authorize that request or establish trusted peer identity.
pub fn decode_response<'a>(
    bytes: &'a [u8],
    request: &Request<'_>,
    endpoint: Endpoint,
) -> Result<Response<'a>> {
    let op = request.operation();
    if bytes.len() > op.response_limit() {
        return Err(Error::InvalidRequest);
    }
    let mut envelope = checked(bytes)?;
    let result: &str = envelope.take("result")?;
    if result == "error" {
        let code = Error::from_code(envelope.take("code")?)?;
        envelope.finish()?;
        if code == Error::Conflict && endpoint != Endpoint::Admin {
            return Err(Error::InvalidRequest);
        }
        return Ok(Response::Error(code));
    }
    if result != "ok" || !op.allowed(endpoint) {
        return Err(Error::InvalidRequest);
    }
    let body = envelope.raw("body").ok_or(Error::InvalidRequest)?;
    envelope.finish()?;
    let response = match request {
        Request::Status => Response::Status(StatusResult::read(body)?),
        Request::UserCreate(_) => Response::UserCreated(UserCreated::read(body)?),
        Request::EnrollmentOpen(request) => {
            let value = Opened::read(body)?;
            if value.ticket.is_some() != (request.mode == Mode::Confirm) {
                return Err(Error::InvalidRequest);
            }
            Response::Opened(value)
        }
        Request::EnrollmentInspect(_) => {
            let mut fields = Fields::read(body)?;
            let state: &str = fields.take("state")?;
            match state {
                "open" | "registering" => Response::OpenInspection(OpenInspection::read(body)?),
                "pending-approval" => {
                    let value = CandidateInspection::read(body)?;
                    if value.mode != Mode::Confirm {
                        return Err(Error::InvalidRequest);
                    }
                    Response::CandidateInspection(value)
                }
                _ => return Err(Error::InvalidRequest),
            }
        }
        Request::EnrollmentCancel(_) => Response::Cancelled(CancelledResult::read(body)?),
        Request::EnrollmentApprove(_) => Response::Activated(Activated::read(body)?),
        Request::RegistrationBegin(_) | Request::RegistrationBeginInsecure => {
            let value = RegistrationChallenge::read(body)?;
            let extensions = &value.options.extensions;
            if value.options.timeout_ms.0 > value.remaining_ms.0
                || extensions.cred_protect.0 != 3
                || extensions.enforce_protect
                || !extensions.uvm
                || !extensions.cred_props
            {
                return Err(Error::InvalidRequest);
            }
            Response::RegistrationChallenge(value)
        }
        Request::RegistrationFinish(_) => Response::Registered(Registered::read(body)?),
        Request::ActionBegin(_) => {
            let value = ActionChallenge::read(body)?;
            if value.options.timeout_ms.0 > value.remaining_ms.0 {
                return Err(Error::InvalidRequest);
            }
            Response::ActionChallenge(value)
        }
        Request::ActionFinish(_) => Response::Admitted(Admitted::read(body)?),
    };
    Ok(response)
}

pub fn encode_response(
    out: &mut [u8],
    response: &Response<'_>,
    request: &Request<'_>,
    endpoint: Endpoint,
) -> Result<usize> {
    let cap = out.len().min(request.operation().response_limit());
    let mut e = Encoder::new(Cursor::new(&mut out[..cap]));
    e.map(3)?.str("version")?.u8(2)?.str("result")?;
    if let Response::Error(error) = response {
        e.str("error")?.str("code")?.str(error.code()?)?;
    } else {
        e.str("ok")?.str("body")?;
        match response {
            Response::Status(v) => v.write(&mut e)?,
            Response::UserCreated(v) => v.write(&mut e)?,
            Response::Opened(v) => v.write(&mut e)?,
            Response::OpenInspection(v) => v.write(&mut e)?,
            Response::CandidateInspection(v) => v.write(&mut e)?,
            Response::Cancelled(v) => v.write(&mut e)?,
            Response::Activated(v) => v.write(&mut e)?,
            Response::RegistrationChallenge(v) => v.write(&mut e)?,
            Response::Registered(v) => v.write(&mut e)?,
            Response::ActionChallenge(v) => v.write(&mut e)?,
            Response::Admitted(v) => v.write(&mut e)?,
            Response::Error(_) => return Err(Error::InvalidRequest),
        }
    }
    let n = e.into_writer().position();
    decode_response(&out[..n], request, endpoint)?;
    Ok(n)
}
