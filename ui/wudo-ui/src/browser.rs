use js_sys::{Array, Object, Reflect, Uint8Array};
use wasm_bindgen::{JsCast, JsValue, prelude::*};
use wasm_bindgen_futures::{JsFuture, spawn_local};
use web_sys::{HtmlButtonElement, HtmlInputElement};
use wudo_protocol::v2 as v;

type Result<T> = std::result::Result<T, ()>;
fn window() -> Result<web_sys::Window> {
    web_sys::window().ok_or(())
}
fn element(id: &str) -> Result<web_sys::Element> {
    window()?
        .document()
        .ok_or(())?
        .get_element_by_id(id)
        .ok_or(())
}
fn text(id: &str, value: &str) {
    if let Ok(el) = element(id) {
        el.set_text_content(Some(value));
    }
}
fn set(o: &Object, key: &str, value: impl Into<JsValue>) -> Result<()> {
    Reflect::set(o, &key.into(), &value.into()).map_err(|_| ())?;
    Ok(())
}
fn object(fields: &[(&str, JsValue)]) -> Result<Object> {
    let o = Object::new();
    for (k, v) in fields {
        set(&o, k, v.clone())?;
    }
    Ok(o)
}
fn bytes(value: &[u8]) -> JsValue {
    Uint8Array::from(value).into()
}
fn hex(value: &[u8]) -> String {
    value.iter().map(|b| format!("{b:02x}")).collect()
}
fn ticket(value: &str) -> Result<[u8; 32]> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(());
    }
    let mut out = [0; 32];
    let digit = |b: u8| {
        if b.is_ascii_digit() {
            b - b'0'
        } else {
            b - b'a' + 10
        }
    };
    for (i, p) in value.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        out[i] = digit(p[0]) * 16 + digit(p[1]);
    }
    Ok(out)
}
fn options(o: &v::CreationOptions<'_>) -> Result<web_sys::CredentialCreationOptions> {
    let rp = object(&[("id", o.rp.id.0.into()), ("name", o.rp.name.0.into())])?;
    let user = object(&[
        ("id", bytes(&o.user.id.0)),
        ("name", o.user.name.0.into()),
        ("displayName", o.user.display_name.0.into()),
    ])?;
    let params = Array::new();
    for a in &o.algorithms.0 {
        params.push(&object(&[("type", "public-key".into()), ("alg", (*a as f64).into())])?.into());
    }
    let exclude = Array::new();
    for id in &o.exclude_credentials.0 {
        exclude.push(&object(&[("type", "public-key".into()), ("id", bytes(id.0))])?.into());
    }
    let selection = object(&[
        ("userVerification", "required".into()),
        ("residentKey", "discouraged".into()),
        ("requireResidentKey", false.into()),
    ])?;
    let protect = match o.extensions.cred_protect.0 {
        1 => "userVerificationOptional",
        2 => "userVerificationOptionalWithCredentialIDList",
        3 => "userVerificationRequired",
        _ => return Err(()),
    };
    let extensions = object(&[
        ("credentialProtectionPolicy", protect.into()),
        (
            "enforceCredentialProtectionPolicy",
            o.extensions.enforce_protect.into(),
        ),
        ("uvm", o.extensions.uvm.into()),
        ("credProps", o.extensions.cred_props.into()),
    ])?;
    let public = object(&[
        ("rp", rp.into()),
        ("user", user.into()),
        ("challenge", bytes(&o.challenge.0)),
        ("timeout", (o.timeout_ms.0 as f64).into()),
        ("pubKeyCredParams", params.into()),
        ("excludeCredentials", exclude.into()),
        ("authenticatorSelection", selection.into()),
        ("attestation", "none".into()),
        ("extensions", extensions.into()),
    ])?;
    Ok(object(&[("publicKey", public.into())])?.unchecked_into())
}
async fn post(q: &v::Request<'_>) -> Result<Vec<u8>> {
    let mut payload = vec![0; q.operation().request_limit()];
    let n = v::encode_request(&mut payload, q, v::Endpoint::Web).map_err(|_| ())?;
    let init = web_sys::RequestInit::new();
    init.set_method("POST");
    init.set_mode(web_sys::RequestMode::SameOrigin);
    init.set_credentials(web_sys::RequestCredentials::Omit);
    init.set_redirect(web_sys::RequestRedirect::Error);
    init.set_body(&bytes(&payload[..n]));
    payload.fill(0);
    let headers = web_sys::Headers::new().map_err(|_| ())?;
    headers
        .set("Content-Type", "application/cbor")
        .map_err(|_| ())?;
    init.set_headers(&headers);
    let controller = web_sys::AbortController::new().map_err(|_| ())?;
    init.set_signal(Some(&controller.signal()));
    let abort_controller = controller.clone();
    let abort = Closure::<dyn FnMut()>::new(move || abort_controller.abort());
    let w = window()?;
    let timer = w
        .set_timeout_with_callback_and_timeout_and_arguments_0(
            abort.as_ref().unchecked_ref(),
            10000,
        )
        .map_err(|_| ())?;
    let result = async {
        let response = JsFuture::from(w.fetch_with_str_and_init("/api/enroll", &init))
            .await
            .map_err(|_| ())?
            .dyn_into::<web_sys::Response>()
            .map_err(|_| ())?;
        if response.status() != 200
            || response
                .headers()
                .get("Content-Type")
                .map_err(|_| ())?
                .as_deref()
                != Some("application/cbor")
        {
            return Err(());
        }
        // Stream incrementally: never allocate an unbounded response body.
        let stream = Reflect::get(&response, &"body".into()).map_err(|_| ())?;
        let get = Reflect::get(&stream, &"getReader".into())
            .map_err(|_| ())?
            .dyn_into::<js_sys::Function>()
            .map_err(|_| ())?;
        let reader = get.call0(&stream).map_err(|_| ())?;
        let read = Reflect::get(&reader, &"read".into())
            .map_err(|_| ())?
            .dyn_into::<js_sys::Function>()
            .map_err(|_| ())?;
        let mut out = Vec::new();
        loop {
            let next = JsFuture::from(
                read.call0(&reader)
                    .map_err(|_| ())?
                    .dyn_into::<js_sys::Promise>()
                    .map_err(|_| ())?,
            )
            .await
            .map_err(|_| ())?;
            if Reflect::get(&next, &"done".into())
                .map_err(|_| ())?
                .as_bool()
                == Some(true)
            {
                break;
            }
            let chunk = Uint8Array::new(&Reflect::get(&next, &"value".into()).map_err(|_| ())?);
            if out.len() + chunk.length() as usize > q.operation().response_limit() {
                return Err(());
            }
            out.extend(chunk.to_vec());
        }
        v::decode_response(&out, q, v::Endpoint::Web).map_err(|_| ())?;
        Ok(out)
    }
    .await;
    controller.abort();
    w.clear_timeout_with_handle(timer);
    drop(abort);
    result
}
async fn enroll() -> Result<()> {
    let input = element("ticket")?
        .dyn_into::<HtmlInputElement>()
        .map_err(|_| ())?;
    let insecure = element("insecure")?
        .dyn_into::<HtmlInputElement>()
        .map_err(|_| ())?
        .checked();
    let q = if insecure {
        input.set_value("");
        v::Request::RegistrationBeginInsecure
    } else {
        let code = ticket(&input.value());
        input.set_value("");
        v::Request::RegistrationBegin(v::RegistrationBegin {
            ticket: v::Ticket(code?),
        })
    };
    text("status", "Requesting enrollment…");
    text("identity", "");
    let reply = post(&q).await?;
    let v::Response::RegistrationChallenge(challenge) =
        v::decode_response(&reply, &q, v::Endpoint::Web).map_err(|_| ())?
    else {
        return Err(());
    };
    text("status", "Create your passkey in the browser prompt.");
    let credential = JsFuture::from(
        window()?
            .navigator()
            .credentials()
            .create_with_options(&options(&challenge.options)?)
            .map_err(|_| ())?,
    )
    .await
    .map_err(|_| ())?
    .dyn_into::<web_sys::PublicKeyCredential>()
    .map_err(|_| ())?;
    let response = credential
        .response()
        .dyn_into::<web_sys::AuthenticatorAttestationResponse>()
        .map_err(|_| ())?;
    fn bounded(array: js_sys::ArrayBuffer, limit: u32) -> Result<Vec<u8>> {
        if array.byte_length() == 0 || array.byte_length() > limit {
            return Err(());
        }
        Ok(Uint8Array::new(&array).to_vec())
    }
    let id = bounded(credential.raw_id(), 1023)?;
    let data = bounded(response.client_data_json(), 4096)?;
    let attestation = bounded(response.attestation_object(), 32768)?;
    // Display the full public ID even if the finish reply is lost, for recovery.
    text("identity", &format!("Credential ID: {}", hex(&id)));
    text(
        "status",
        "Submitting registration. A lost reply may leave enrollment completed; ask your administrator to inspect this ID before retrying.",
    );
    let q = v::Request::RegistrationFinish(v::RegistrationFinish {
        ceremony_id: challenge.ceremony_id,
        credential_id: v::Blob(&id),
        client_data: v::Blob(&data),
        attestation_object: v::Blob(&attestation),
        client_extensions: v::RegistrationExtensions {
            resident_key: None,
            cred_protect: None,
        },
    });
    let reply = post(&q).await?;
    match v::decode_response(&reply, &q, v::Endpoint::Web).map_err(|_| ())? {
        v::Response::Registered(v::Registered {
            state: v::RegistrationState::PendingApproval,
        }) => text(
            "status",
            "Passkey submitted. Your administrator must inspect and approve the candidate locally before it becomes active.",
        ),
        v::Response::Registered(v::Registered {
            state: v::RegistrationState::Active,
        }) => text(
            "status",
            "Passkey enrolled. This does not grant new permissions or provision secrets.",
        ),
        _ => return Err(()),
    }
    Ok(())
}
#[wasm_bindgen(start)]
pub fn start() -> std::result::Result<(), JsValue> {
    if cfg!(test) {
        return Ok(());
    }
    setup().map_err(|_| JsValue::from_str("Enrollment UI unavailable"))
}
fn setup() -> Result<()> {
    let w = window()?;
    if !w.is_secure_context() || w.location().protocol().map_err(|_| ())? != "https:" {
        text(
            "status",
            "Enrollment requires the configured HTTPS address.",
        );
        return Ok(());
    }
    let button = element("enroll")?
        .dyn_into::<HtmlButtonElement>()
        .map_err(|_| ())?;
    let b = button.clone();
    let click = Closure::<dyn FnMut(web_sys::Event)>::new(move |_| {
        if b.disabled() {
            return;
        }
        b.set_disabled(true);
        let b = b.clone();
        spawn_local(async move {
            if enroll().await.is_err() {
                text(
                    "status",
                    "Enrollment did not complete or its result is unknown. If a credential ID is shown, ask your administrator to inspect it before trying again. Otherwise check the enrollment window and try again.",
                );
            }
            b.set_disabled(false);
        });
    });
    button
        .add_event_listener_with_callback("click", click.as_ref().unchecked_ref())
        .map_err(|_| ())?;
    click.forget();
    button.set_disabled(false);
    text(
        "status",
        "Ready. Enrollment must have been opened by your administrator.",
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use wasm_bindgen_test::wasm_bindgen_test;
    #[wasm_bindgen_test]
    fn browser_option_mapping_preserves_bytes_and_required_verification() {
        let source = v::CreationOptions {
            rp: v::Rp {
                id: v::Text("pi.lan"),
                name: v::Text("Wudo"),
            },
            user: v::User {
                id: v::UserId([7; 16]),
                name: v::Name("alice"),
                display_name: v::Label("Alice"),
            },
            challenge: v::Challenge([23; 32]),
            timeout_ms: v::Number(120000),
            algorithms: v::Algorithms(vec![-7, -257]),
            exclude_credentials: v::CredentialList(vec![v::Blob(&[1, 2, 255])]),
            user_verification: v::Required::Required,
            resident_key: v::Discouraged::Discouraged,
            attestation: v::NoAttestation::None,
            extensions: v::CreationExtensions {
                cred_protect: v::Number(3),
                enforce_protect: false,
                uvm: true,
                cred_props: true,
            },
        };
        let result = options(&source).unwrap();
        let get = |obj: &JsValue, key: &str| Reflect::get(obj, &key.into()).unwrap();
        let public = get(&result, "publicKey");
        assert_eq!(
            Uint8Array::new(&get(&public, "challenge")).to_vec(),
            vec![23; 32]
        );
        assert_eq!(
            Uint8Array::new(&get(&get(&public, "user"), "id")).to_vec(),
            vec![7; 16]
        );
        let excluded = Array::from(&get(&public, "excludeCredentials"));
        assert_eq!(
            Uint8Array::new(&get(&excluded.get(0), "id")).to_vec(),
            vec![1, 2, 255]
        );
        assert_eq!(
            get(&get(&public, "authenticatorSelection"), "userVerification")
                .as_string()
                .as_deref(),
            Some("required")
        );
        assert_eq!(
            get(&get(&public, "extensions"), "credentialProtectionPolicy")
                .as_string()
                .as_deref(),
            Some("userVerificationRequired")
        );
        assert_eq!(
            get(&public, "attestation").as_string().as_deref(),
            Some("none")
        );
    }
    #[wasm_bindgen_test]
    fn ticket_input_is_exact_and_never_a_url() {
        assert_eq!(ticket(&"ab".repeat(32)).unwrap(), [0xab; 32]);
        for value in [
            "",
            "https://pi.lan/?code=CANARY",
            &"A".repeat(64),
            &"0".repeat(63),
            &"0".repeat(65),
        ] {
            assert!(ticket(value).is_err());
        }
    }
}
