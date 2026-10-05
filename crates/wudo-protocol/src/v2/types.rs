use super::{Decoder, Error, Fields, Result, Wire, Writer, complete};

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Blob<'a, const MIN: usize, const MAX: usize>(pub &'a [u8]);
impl<'a, const MIN: usize, const MAX: usize> Wire<'a> for Blob<'a, MIN, MAX> {
    fn read(bytes: &'a [u8]) -> Result<Self> {
        let mut d = Decoder::new(bytes);
        let value = d.bytes()?;
        complete(bytes, &d)?;
        if !(MIN..=MAX).contains(&value.len()) {
            return Err(Error::InvalidRequest);
        }
        Ok(Self(value))
    }
    fn write(&self, e: &mut Writer<'_>) -> Result<()> {
        e.bytes(self.0)?;
        Ok(())
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Text<'a, const MAX: usize>(pub &'a str);
impl<'a, const MAX: usize> Wire<'a> for Text<'a, MAX> {
    fn read(bytes: &'a [u8]) -> Result<Self> {
        let value = <&str>::read(bytes)?;
        if value.is_empty() || value.len() > MAX {
            return Err(Error::InvalidRequest);
        }
        Ok(Self(value))
    }
    fn write(&self, e: &mut Writer<'_>) -> Result<()> {
        e.str(self.0)?;
        Ok(())
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Name<'a>(pub &'a str);
impl<'a> Wire<'a> for Name<'a> {
    fn read(bytes: &'a [u8]) -> Result<Self> {
        let value = Text::<64>::read(bytes)?.0;
        let b = value.as_bytes();
        if !b[0].is_ascii_lowercase() {
            return Err(Error::InvalidRequest);
        }
        let mut separator = false;
        for ch in b {
            if ch.is_ascii_lowercase() || ch.is_ascii_digit() {
                separator = false;
            } else if matches!(ch, b'.' | b'_' | b'-') && !separator {
                separator = true;
            } else {
                return Err(Error::InvalidRequest);
            }
        }
        if separator {
            return Err(Error::InvalidRequest);
        }
        Ok(Self(value))
    }
    fn write(&self, e: &mut Writer<'_>) -> Result<()> {
        e.str(self.0)?;
        Ok(())
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Label<'a>(pub &'a str);
impl<'a> Wire<'a> for Label<'a> {
    fn read(bytes: &'a [u8]) -> Result<Self> {
        let value = Text::<128>::read(bytes)?.0;
        if value.chars().any(char::is_control) {
            return Err(Error::InvalidRequest);
        }
        Ok(Self(value))
    }
    fn write(&self, e: &mut Writer<'_>) -> Result<()> {
        e.str(self.0)?;
        Ok(())
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Number<const MAX: u64>(pub u64);
impl<'a, const MAX: u64> Wire<'a> for Number<MAX> {
    fn read(bytes: &'a [u8]) -> Result<Self> {
        let value = u64::read(bytes)?;
        if value == 0 || value > MAX {
            return Err(Error::InvalidRequest);
        }
        Ok(Self(value))
    }
    fn write(&self, e: &mut Writer<'_>) -> Result<()> {
        e.u64(self.0)?;
        Ok(())
    }
}

macro_rules! id {
    ($name:ident, $n:literal) => {
        #[derive(Clone, Copy, PartialEq, Eq)]
        pub struct $name(pub [u8; $n]);
        impl<'a> Wire<'a> for $name {
            fn read(bytes: &'a [u8]) -> Result<Self> {
                let value = Blob::<$n, $n>::read(bytes)?;
                Ok(Self(value.0.try_into().map_err(|_| Error::InvalidRequest)?))
            }
            fn write(&self, e: &mut Writer<'_>) -> Result<()> {
                e.bytes(&self.0)?;
                Ok(())
            }
        }
    };
}
id!(EnrollmentId, 32);
id!(CandidateId, 32);
id!(CeremonyId, 32);
id!(OperationId, 32);
id!(Ticket, 32);
id!(Fingerprint, 32);
id!(Challenge, 32);

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct UserId(pub [u8; 16]);
impl<'a> Wire<'a> for UserId {
    fn read(bytes: &'a [u8]) -> Result<Self> {
        let b = Blob::<16, 16>::read(bytes)?.0;
        if b[6] >> 4 != 4 || b[8] >> 6 != 2 {
            return Err(Error::InvalidRequest);
        }
        Ok(Self(b.try_into().map_err(|_| Error::InvalidRequest)?))
    }
    fn write(&self, e: &mut Writer<'_>) -> Result<()> {
        e.bytes(&self.0)?;
        Ok(())
    }
}

macro_rules! text_enum {
    ($name:ident { $($variant:ident => $value:literal),+ $(,)? }) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub enum $name { $($variant),+ }
        impl<'a> Wire<'a> for $name {
            fn read(bytes: &'a [u8]) -> Result<Self> {
                match <&str>::read(bytes)? { $($value => Ok(Self::$variant),)+ _ => Err(Error::InvalidRequest) }
            }
            fn write(&self, e: &mut Writer<'_>) -> Result<()> {
                e.str(match self { $(Self::$variant => $value),+ })?; Ok(())
            }
        }
    }
}
text_enum!(Mode { Confirm => "confirm", Insecure => "insecure" });
text_enum!(Required { Required => "required" });
text_enum!(Discouraged { Discouraged => "discouraged" });
text_enum!(NoAttestation { None => "none" });
text_enum!(Ready { Ready => "ready" });
text_enum!(Cancelled { Cancelled => "cancelled" });
text_enum!(Active { Active => "active" });
text_enum!(Accepted { Accepted => "accepted" });
text_enum!(RegistrationState { PendingApproval => "pending-approval", Active => "active" });
text_enum!(OpenState { Open => "open", Registering => "registering" });
text_enum!(PendingApproval { PendingApproval => "pending-approval" });

#[derive(Clone, PartialEq, Eq)]
pub struct CredentialList<'a, const MIN: usize>(pub Vec<Blob<'a, 1, 1023>>);
impl<'a, const MIN: usize> Wire<'a> for CredentialList<'a, MIN> {
    fn read(bytes: &'a [u8]) -> Result<Self> {
        let mut d = Decoder::new(bytes);
        let n = d.array()?.ok_or(Error::InvalidRequest)?;
        if n < MIN as u64 || n > 16 {
            return Err(Error::InvalidRequest);
        }
        let mut values: Vec<Blob<'a, 1, 1023>> = Vec::with_capacity(n as usize);
        for _ in 0..n {
            let start = d.position();
            d.bytes()?;
            let value = Blob::read(&bytes[start..d.position()])?;
            if values.contains(&value) {
                return Err(Error::InvalidRequest);
            }
            values.push(value);
        }
        complete(bytes, &d)?;
        Ok(Self(values))
    }
    fn write(&self, e: &mut Writer<'_>) -> Result<()> {
        if self.0.len() > 16 {
            return Err(Error::InvalidRequest);
        }
        e.array(self.0.len() as u64)?;
        for value in &self.0 {
            value.write(e)?;
        }
        Ok(())
    }
}
#[derive(Clone, PartialEq, Eq)]
pub struct Algorithms(pub Vec<i64>);
impl<'a> Wire<'a> for Algorithms {
    fn read(bytes: &'a [u8]) -> Result<Self> {
        let mut d = Decoder::new(bytes);
        let n = d.array()?.ok_or(Error::InvalidRequest)?;
        if !(1..=2).contains(&n) {
            return Err(Error::InvalidRequest);
        }
        let mut values = Vec::with_capacity(n as usize);
        for _ in 0..n {
            let value = d.i64()?;
            if !matches!(value, -7 | -257) || values.contains(&value) {
                return Err(Error::InvalidRequest);
            }
            values.push(value);
        }
        complete(bytes, &d)?;
        Ok(Self(values))
    }
    fn write(&self, e: &mut Writer<'_>) -> Result<()> {
        if self.0.len() > 2 {
            return Err(Error::InvalidRequest);
        }
        e.array(self.0.len() as u64)?;
        for value in &self.0 {
            e.i64(*value)?;
        }
        Ok(())
    }
}

// Repeated flat-map plumbing only. Each declaration is the complete field
// allowlist; omitted/unknown/duplicate fields are handled identically.
macro_rules! map_struct {
    ($name:ident $(<$lt:lifetime>)? { $($field:ident: $ty:ty),* $(,)? }
        optional { $($opt:ident: $oty:ty),* $(,)? }) => {
        #[derive(Clone, PartialEq, Eq)]
        pub struct $name $(<$lt>)? { $(pub $field: $ty,)* $(pub $opt: Option<$oty>,)* }
        impl<'a> Wire<'a> for $name $(<$lt>)? {
            fn read(bytes: &'a [u8]) -> Result<Self> {
                let mut fields = Fields::read(bytes)?;
                let value = Self { $($field: fields.take(stringify!($field))?,)*
                    $($opt: fields.optional(stringify!($opt))?,)* };
                fields.finish()?; Ok(value)
            }
            fn write(&self, e: &mut Writer<'_>) -> Result<()> {
                let count = 0u64 $(+ { let _ = stringify!($field); 1 })*
                    $(+ u64::from(self.$opt.is_some()))*;
                e.map(count)?;
                $(e.str(stringify!($field))?; self.$field.write(e)?;)*
                $(if let Some(value) = &self.$opt { e.str(stringify!($opt))?; value.write(e)?; })*
                Ok(())
            }
        }
    }
}

map_struct!(UserCreate<'a> { name: Name<'a>, label: Label<'a> } optional {});
map_struct!(EnrollmentOpen { user_id: UserId, mode: Mode } optional {});
map_struct!(EnrollmentRef { enrollment_id: EnrollmentId } optional {});
map_struct!(EnrollmentApprove { enrollment_id: EnrollmentId, candidate_id: CandidateId } optional {});
map_struct!(RegistrationBegin { ticket: Ticket } optional {});
map_struct!(RegistrationExtensions {} optional { resident_key: bool, cred_protect: Number<3> });
map_struct!(RegistrationFinish<'a> {
    ceremony_id: CeremonyId, credential_id: Blob<'a, 1, 1023>,
    client_data: Blob<'a, 1, 4096>, attestation_object: Blob<'a, 1, 32768>,
    client_extensions: RegistrationExtensions
} optional {});
map_struct!(ActionBegin<'a> { user_name: Name<'a>, action_id: Name<'a> } optional {});
map_struct!(ActionFinish<'a> {
    ceremony_id: CeremonyId, credential_id: Blob<'a, 1, 1023>,
    client_data: Blob<'a, 1, 4096>, authenticator_data: Blob<'a, 37, 4096>, signature: Blob<'a, 1, 1024>
} optional { user_handle: UserId });

map_struct!(StatusResult { status: Ready } optional {});
map_struct!(UserCreated { user_id: UserId } optional {});
map_struct!(Opened { enrollment_id: EnrollmentId, remaining_ms: Number<600000> } optional { ticket: Ticket });
map_struct!(CancelledResult { state: Cancelled } optional {});
map_struct!(Activated<'a> { state: Active, credential_id: Blob<'a, 1, 1023> } optional {});
map_struct!(Registered { state: RegistrationState } optional {});
map_struct!(Admitted { state: Accepted, operation_id: OperationId } optional {});
map_struct!(OpenInspection {
    state: OpenState, user_id: UserId, mode: Mode, remaining_ms: Number<600000>
} optional {});
map_struct!(CandidateInspection<'a> {
    state: PendingApproval, user_id: UserId, mode: Mode, remaining_ms: Number<600000>,
    candidate_id: CandidateId, credential_id: Blob<'a, 1, 1023>, fingerprint: Fingerprint
} optional {});
map_struct!(Rp<'a> { id: Text<'a, 253>, name: Text<'a, 128> } optional {});
map_struct!(User<'a> { id: UserId, name: Name<'a>, display_name: Label<'a> } optional {});
map_struct!(CreationExtensions {
    cred_protect: Number<3>, enforce_protect: bool, uvm: bool, cred_props: bool
} optional {});
map_struct!(CreationOptions<'a> {
    rp: Rp<'a>, user: User<'a>, challenge: Challenge, timeout_ms: Number<120000>,
    algorithms: Algorithms, exclude_credentials: CredentialList<'a, 0>,
    user_verification: Required, resident_key: Discouraged, attestation: NoAttestation,
    extensions: CreationExtensions
} optional {});
map_struct!(RequestOptions<'a> {
    rp_id: Text<'a, 253>, challenge: Challenge, timeout_ms: Number<120000>,
    allow_credentials: CredentialList<'a, 1>, user_verification: Required
} optional {});
map_struct!(RegistrationChallenge<'a> {
    ceremony_id: CeremonyId, remaining_ms: Number<120000>, options: CreationOptions<'a>
} optional {});
map_struct!(ActionChallenge<'a> {
    ceremony_id: CeremonyId, remaining_ms: Number<120000>, options: RequestOptions<'a>
} optional {});

map_struct!(UserInspect<'a> { name: Name<'a> } optional {});
map_struct!(UserInfo<'a> { user_id: UserId, name: Name<'a>, label: Label<'a> } optional {});
map_struct!(StoreReady { state: Ready } optional {});

map_struct!(InstallationInitialize<'a> { origin: Text<'a, 270> } optional {});

text_enum!(CredentialState { Active => "active", Revoked => "revoked" });
text_enum!(Revoked { Revoked => "revoked" });
map_struct!(UserList<'a> {} optional { after: Name<'a> });
map_struct!(CredentialQuery<'a> { user_id: UserId } optional { after: Blob<'a, 1, 1023> });
map_struct!(CredentialRef<'a> { user_id: UserId, credential_id: Blob<'a, 1, 1023> } optional {});
map_struct!(CredentialEntry<'a> { credential_id: Blob<'a, 1, 1023>, state: CredentialState } optional {});
map_struct!(UserPage<'a> { users: Items<UserInfo<'a>> } optional { next_after: Name<'a> });
map_struct!(CredentialPage<'a> { user_id: UserId, credentials: Items<CredentialEntry<'a>> } optional { next_after: Blob<'a, 1, 1023> });
map_struct!(CredentialInfo<'a> { user_id: UserId, credential_id: Blob<'a, 1, 1023>, state: CredentialState, fingerprint: Fingerprint } optional {});
map_struct!(CredentialRevoked<'a> { user_id: UserId, credential_id: Blob<'a, 1, 1023>, state: Revoked } optional {});

#[derive(Clone, PartialEq, Eq)]
pub struct Items<T>(pub Vec<T>);
impl<'a, T: Wire<'a>> Wire<'a> for Items<T> {
    fn read(bytes: &'a [u8]) -> Result<Self> {
        let mut d = Decoder::new(bytes);
        let n = d.array()?.ok_or(Error::InvalidRequest)?;
        if n > 16 {
            return Err(Error::InvalidRequest);
        }
        let mut items = Vec::with_capacity(n as usize);
        for _ in 0..n {
            let start = d.position();
            super::bounded::span(&mut d)?;
            items.push(T::read(&bytes[start..d.position()])?);
        }
        complete(bytes, &d)?;
        Ok(Self(items))
    }
    fn write(&self, e: &mut Writer<'_>) -> Result<()> {
        if self.0.len() > 16 {
            return Err(Error::InvalidRequest);
        }
        e.array(self.0.len() as u64)?;
        for item in &self.0 {
            item.write(e)?;
        }
        Ok(())
    }
}
