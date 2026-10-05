use base64::Engine;
use webauthn_rs::prelude::*;
use webauthn_rs_proto::*;
use wire::{Error, Result};
use wudo_protocol::v2 as wire;

/// Projects only the reviewed library option profile. No challenge is replaced.
pub(super) fn options(
    value: &CreationChallengeResponse,
    timeout: u64,
) -> Result<wire::CreationOptions<'_>> {
    let p = &value.public_key;
    let a = p
        .authenticator_selection
        .as_ref()
        .ok_or(Error::InternalError)?;
    let e = p.extensions.as_ref().ok_or(Error::InternalError)?;
    let protect = e.cred_protect.as_ref().ok_or(Error::InternalError)?;
    if a.authenticator_attachment.is_some()
        || a.require_resident_key
        || !matches!(
            a.resident_key,
            None | Some(ResidentKeyRequirement::Discouraged)
        )
        || a.user_verification != UserVerificationPolicy::Required
        || !matches!(p.attestation, Some(AttestationConveyancePreference::None))
        || p.hints.is_some()
        || p.attestation_formats.is_some()
        || protect.credential_protection_policy
            != CredentialProtectionPolicy::UserVerificationRequired
        || protect
            .enforce_credential_protection_policy
            .unwrap_or(false)
        || e.uvm != Some(true)
        || e.cred_props != Some(true)
        || e.min_pin_length.is_some()
        || e.hmac_create_secret.is_some()
        || p.pub_key_cred_params
            .iter()
            .any(|x| x.type_ != "public-key")
        || p.exclude_credentials.as_ref().is_some_and(|ids| {
            ids.iter()
                .any(|x| x.type_ != "public-key" || x.transports.is_some())
        })
        || p.timeout.is_none_or(|t| u64::from(t) < timeout)
    {
        return Err(Error::InternalError);
    }
    Ok(wire::CreationOptions {
        rp: wire::Rp {
            id: wire::Text(&p.rp.id),
            name: wire::Text(&p.rp.name),
        },
        user: wire::User {
            id: wire::UserId(
                p.user
                    .id
                    .as_ref()
                    .try_into()
                    .map_err(|_| Error::InternalError)?,
            ),
            name: wire::Name(&p.user.name),
            display_name: wire::Label(&p.user.display_name),
        },
        challenge: wire::Challenge(
            p.challenge
                .as_ref()
                .try_into()
                .map_err(|_| Error::InternalError)?,
        ),
        timeout_ms: wire::Number(timeout),
        algorithms: wire::Algorithms(p.pub_key_cred_params.iter().map(|x| x.alg).collect()),
        exclude_credentials: wire::CredentialList(
            p.exclude_credentials
                .iter()
                .flatten()
                .map(|x| wire::Blob(x.id.as_ref()))
                .collect(),
        ),
        user_verification: wire::Required::Required,
        resident_key: wire::Discouraged::Discouraged,
        attestation: wire::NoAttestation::None,
        extensions: wire::CreationExtensions {
            cred_protect: wire::Number(3),
            enforce_protect: false,
            uvm: true,
            cred_props: true,
        },
    })
}

pub(super) fn response(
    value: &wire::RegistrationFinish<'_>,
) -> Result<RegisterPublicKeyCredential> {
    let raw_id: Base64UrlSafeData = value.credential_id.0.to_vec().into();
    Ok(RegisterPublicKeyCredential {
        id: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw_id.as_ref()),
        raw_id,
        type_: "public-key".into(),
        response: AuthenticatorAttestationResponseRaw {
            client_data_json: value.client_data.0.to_vec().into(),
            attestation_object: value.attestation_object.0.to_vec().into(),
            transports: None,
        },
        extensions: RegistrationExtensionsClientOutputs {
            cred_props: value
                .client_extensions
                .resident_key
                .map(|rk| CredProps { rk: Some(rk) }),
            cred_protect: value
                .client_extensions
                .cred_protect
                .map(|v| {
                    CredentialProtectionPolicy::try_from(v.0 as u8)
                        .map_err(|_| Error::InvalidRequest)
                })
                .transpose()?,
            ..Default::default()
        },
    })
}
