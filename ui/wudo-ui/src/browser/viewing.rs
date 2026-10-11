use super::*;
use std::{cell::RefCell, rc::Rc};
struct Session {
    name: String,
    token: v::ViewToken,
    expires: f64,
    after: Option<String>,
    next: Option<String>,
}
impl Drop for Session {
    fn drop(&mut self) {
        self.token.0.fill(0);
    }
}
#[derive(Default)]
struct State {
    session: Option<Session>,
    generation: u64,
    signing: bool,
    polling: bool,
    executing: bool,
}
type Shared = Rc<RefCell<State>>;
fn now() -> Result<f64> {
    Ok(window()?.performance().ok_or(())?.now())
}
fn hidden() -> bool {
    window()
        .ok()
        .and_then(|w| w.document())
        .is_none_or(|d| d.hidden())
}
fn button(id: &str) -> Result<HtmlButtonElement> {
    element(id)?.dyn_into().map_err(|_| ())
}
fn controls(state: &State) {
    for (id, disabled) in [
        ("sign-in", state.signing || state.session.is_some()),
        ("sign-out", !state.signing && state.session.is_none()),
        (
            "next-page",
            state.polling || state.session.as_ref().is_none_or(|s| s.next.is_none()),
        ),
        (
            "first-page",
            state.polling || state.session.as_ref().is_none_or(|s| s.after.is_none()),
        ),
    ] {
        if let Ok(b) = button(id) {
            b.set_disabled(disabled);
        }
    }
}
fn clear(state: &Shared, message: &str) {
    let mut s = state.borrow_mut();
    s.session = None;
    s.generation = s.generation.wrapping_add(1);
    s.signing = false;
    s.polling = false;
    s.executing = false;
    text("actions", "");
    text("view-status", message);
    controls(&s);
}
fn request_options(o: &v::RequestOptions<'_>) -> Result<web_sys::CredentialRequestOptions> {
    let allow = Array::new();
    for id in &o.allow_credentials.0 {
        allow.push(&object(&[("type", "public-key".into()), ("id", bytes(id.0))])?.into());
    }
    let public = object(&[
        ("challenge", bytes(&o.challenge.0)),
        ("rpId", o.rp_id.0.into()),
        ("timeout", (o.timeout_ms.0 as f64).into()),
        ("allowCredentials", allow.into()),
        ("userVerification", "required".into()),
    ])?;
    Ok(object(&[("publicKey", public.into())])?.unchecked_into())
}
fn bounded(b: js_sys::ArrayBuffer, min: usize, max: usize) -> Result<Vec<u8>> {
    if !(min..=max).contains(&(b.byte_length() as usize)) {
        return Err(());
    }
    Ok(Uint8Array::new(&b).to_vec())
}
struct Assertion {
    id: Vec<u8>,
    data: Vec<u8>,
    auth: Vec<u8>,
    signature: Vec<u8>,
    user: Option<v::UserId>,
}
impl Assertion {
    fn finish(&self, ceremony_id: v::CeremonyId) -> v::ActionFinish<'_> {
        v::ActionFinish {
            ceremony_id,
            credential_id: v::Blob(&self.id),
            client_data: v::Blob(&self.data),
            authenticator_data: v::Blob(&self.auth),
            signature: v::Blob(&self.signature),
            user_handle: self.user,
        }
    }
}
async fn assertion(options: &v::RequestOptions<'_>) -> Result<Assertion> {
    let credential = JsFuture::from(
        window()?
            .navigator()
            .credentials()
            .get_with_options(&request_options(options)?)
            .map_err(|_| ())?,
    )
    .await
    .map_err(|_| ())?
    .dyn_into::<web_sys::PublicKeyCredential>()
    .map_err(|_| ())?;
    let response = credential
        .response()
        .dyn_into::<web_sys::AuthenticatorAssertionResponse>()
        .map_err(|_| ())?;
    let id = bounded(credential.raw_id(), 1, 1023)?;
    let data = bounded(response.client_data_json(), 1, 4096)?;
    let auth = bounded(response.authenticator_data(), 37, 4096)?;
    let signature = bounded(response.signature(), 1, 1024)?;
    let user = response
        .user_handle()
        .map(|b| bounded(b, 16, 16).and_then(|b| Ok(v::UserId(b.try_into().map_err(|_| ())?))))
        .transpose()?;
    Ok(Assertion {
        id,
        data,
        auth,
        signature,
        user,
    })
}
async fn sign_in(name: String) -> Result<Session> {
    let q = v::Request::ViewBegin(v::ViewBegin {
        user_name: v::Name(&name),
    });
    let reply = post(&q).await?;
    let v::Response::ActionChallenge(c) =
        v::decode_response(&reply, &q, v::Endpoint::Web).map_err(|_| ())?
    else {
        return Err(());
    };
    let assertion = assertion(&c.options).await?;
    let q = v::Request::ViewFinish(assertion.finish(c.ceremony_id));
    let started = now()?;
    let mut reply = post(&q).await?;
    let session = match v::decode_response(&reply, &q, v::Endpoint::Web).map_err(|_| ())? {
        v::Response::ViewSession(s) => Session {
            name,
            token: s.token,
            expires: started + s.remaining_ms.0 as f64,
            after: None,
            next: None,
        },
        _ => {
            reply.fill(0);
            return Err(());
        }
    };
    reply.fill(0);
    Ok(session)
}
fn reason(a: v::Availability) -> &'static str {
    match a {
        v::Availability::Available => "Ready",
        v::Availability::AlreadyRunning => "Already running",
        v::Availability::AlreadyStopped => "Already stopped",
        v::Availability::Busy => "Busy",
        v::Availability::StateUnavailable => "Status unavailable",
        v::Availability::Unsupported => "Unavailable",
    }
}
fn render(page: &v::ViewPage<'_>) -> Result<()> {
    let root = element("actions")?;
    root.set_text_content(None);
    let doc = window()?.document().ok_or(())?;
    if page.actions.0.is_empty() {
        root.set_text_content(Some("No actions are currently authorized."));
    }
    for a in &page.actions.0 {
        let row = doc.create_element("li").map_err(|_| ())?;
        let label = doc.create_element("strong").map_err(|_| ())?;
        label.set_text_content(Some(a.description.0));
        let run = doc
            .create_element("button")
            .map_err(|_| ())?
            .dyn_into::<HtmlButtonElement>()
            .map_err(|_| ())?;
        run.set_text_content(Some("Run"));
        run.set_disabled(a.availability != v::Availability::Available);
        run.set_attribute("data-action", a.action_id.0)
            .map_err(|_| ())?;
        run.set_attribute("data-description", a.description.0)
            .map_err(|_| ())?;
        run.set_attribute("data-confirm", if a.confirmation { "yes" } else { "no" })
            .map_err(|_| ())?;
        let state = doc.create_element("span").map_err(|_| ())?;
        state.set_text_content(Some(reason(a.availability)));
        row.append_child(&label).map_err(|_| ())?;
        row.append_child(&state).map_err(|_| ())?;
        row.append_child(&run).map_err(|_| ())?;
        root.append_child(&row).map_err(|_| ())?;
    }
    Ok(())
}
fn poll(state: &Shared) {
    if state
        .borrow()
        .session
        .as_ref()
        .is_some_and(|s| now().map_or(true, |n| n >= s.expires))
    {
        clear(state, "Session expired. Sign in again.");
        return;
    }
    if hidden() {
        return;
    }
    let (token, after, generation) = {
        let mut s = state.borrow_mut();
        if s.polling || s.executing {
            return;
        }
        let Some(session) = s.session.as_ref() else {
            return;
        };
        if now().map_or(true, |n| n >= session.expires) {
            drop(s);
            clear(state, "Session expired. Sign in again.");
            return;
        }
        let values = (session.token, session.after.clone(), s.generation);
        s.polling = true;
        controls(&s);
        values
    };
    text("view-status", "Refreshing actions…");
    text("actions", "");
    let shared = state.clone();
    spawn_local(async move {
        let q = v::Request::ViewActions(v::ViewActions {
            token,
            after: after.as_deref().map(v::Name),
        });
        let started = now().unwrap_or(f64::INFINITY);
        let reply = post(&q).await;
        if shared.borrow().generation != generation {
            return;
        }
        shared.borrow_mut().polling = false;
        let result = reply
            .as_ref()
            .ok()
            .and_then(|b| v::decode_response(b, &q, v::Endpoint::Web).ok());
        match result {
            Some(v::Response::ViewPage(page)) => {
                let mut s = shared.borrow_mut();
                let Some(session) = s.session.as_mut() else {
                    return;
                };
                session.expires = session.expires.min(started + page.remaining_ms.0 as f64);
                if now().map_or(true, |n| n >= session.expires) {
                    drop(s);
                    clear(&shared, "Session expired. Sign in again.");
                    return;
                }
                session.next = page.next_after.map(|n| n.0.to_owned());
                if !hidden() {
                    if render(&page).is_err() {
                        drop(s);
                        clear(&shared, "Actions unavailable. Sign in again.");
                        return;
                    }
                    text(
                        "view-status",
                        "Signed in. Action status refreshes every five seconds.",
                    );
                }
                controls(&s);
            }
            Some(v::Response::Error(v::Error::Busy)) => {
                text("view-status", "Busy. Waiting for the next refresh.");
                controls(&shared.borrow());
            }
            _ => clear(&shared, "Viewing session unavailable. Sign in again."),
        }
    });
}
fn current(state: &Shared, generation: u64) -> bool {
    let s = state.borrow();
    s.generation == generation
        && s.session
            .as_ref()
            .is_some_and(|session| now().is_ok_and(|n| n < session.expires))
}
async fn invoke(state: &Shared, generation: u64, name: &str, action: &str) -> &'static str {
    // Failures before sending finish cannot have submitted an action.
    let prepared = async {
        let q = v::Request::ActionBegin(v::ActionBegin {
            user_name: v::Name(name),
            action_id: v::Name(action),
        });
        let reply = post(&q).await?;
        let v::Response::ActionChallenge(c) =
            v::decode_response(&reply, &q, v::Endpoint::Web).map_err(|_| ())?
        else {
            return Err(());
        };
        if !current(state, generation) {
            return Err(());
        }
        let assertion = assertion(&c.options).await?;
        if !current(state, generation) {
            return Err(());
        }
        Ok((assertion, c.ceremony_id))
    }
    .await;
    let Ok((assertion, id)) = prepared else {
        return "Action was not submitted. Refresh and try again when ready.";
    };
    text("action-status", "Submitting action…");
    let q = v::Request::ActionFinish(assertion.finish(id));
    let reply = post(&q).await;
    let response = reply
        .as_ref()
        .ok()
        .and_then(|b| v::decode_response(b, &q, v::Endpoint::Web).ok());
    match response {
        Some(v::Response::Admitted(v::Admitted {
            state: v::Accepted::Accepted,
            ..
        })) => {
            "Request accepted. Current unit state will refresh; acceptance does not mean completion."
        }
        Some(v::Response::Error(v::Error::Busy)) => {
            "Action was not submitted: busy. Refresh before trying again."
        }
        Some(v::Response::Error(_)) => {
            "Action unavailable or acceptance could not be confirmed. Check current state before trying again."
        }
        _ => {
            "Could not confirm acceptance. The action may have run. Check current state before deciding whether to try again."
        }
    }
}
fn action_click(state: &Shared, event: web_sys::Event) {
    let Some(button) = event
        .target()
        .and_then(|t| t.dyn_into::<HtmlButtonElement>().ok())
    else {
        return;
    };
    if button.disabled() || hidden() {
        return;
    }
    let Some(action) = button.get_attribute("data-action") else {
        return;
    };
    let (name, generation) = {
        let s = state.borrow();
        if s.polling || s.executing {
            return;
        }
        let Some(session) = s.session.as_ref() else {
            return;
        };
        (session.name.clone(), s.generation)
    };
    if !current(state, generation) {
        clear(state, "Session expired. Sign in again.");
        return;
    }
    if button.get_attribute("data-confirm").as_deref() == Some("yes") {
        let description = button.get_attribute("data-description").unwrap_or_default();
        if !window()
            .and_then(|w| {
                w.confirm_with_message(&format!("Run {description}?"))
                    .map_err(|_| ())
            })
            .unwrap_or(false)
        {
            return;
        }
    }
    state.borrow_mut().executing = true;
    text("actions", "");
    text(
        "action-status",
        "Use your passkey to authorize this action.",
    );
    let shared = state.clone();
    spawn_local(async move {
        let outcome = invoke(&shared, generation, &name, &action).await;
        if shared.borrow().generation != generation {
            return;
        }
        shared.borrow_mut().executing = false;
        text("action-status", outcome);
        poll(&shared);
    });
}
pub(super) fn setup() -> Result<()> {
    let state = Rc::new(RefCell::new(State::default()));
    controls(&state.borrow());
    let action_state = state.clone();
    let action =
        Closure::<dyn FnMut(web_sys::Event)>::new(move |event| action_click(&action_state, event));
    element("actions")?
        .add_event_listener_with_callback("click", action.as_ref().unchecked_ref())
        .map_err(|_| ())?;
    action.forget();
    let shared = state.clone();
    let click = Closure::<dyn FnMut(web_sys::Event)>::new(move |_| {
        if shared.borrow().signing || shared.borrow().session.is_some() {
            return;
        }
        let name = element("user-name")
            .ok()
            .and_then(|e| e.dyn_into::<HtmlInputElement>().ok())
            .map(|i| i.value())
            .unwrap_or_default();
        {
            let mut s = shared.borrow_mut();
            s.signing = true;
            controls(&s);
        }
        let generation = shared.borrow().generation;
        let state = shared.clone();
        text("view-status", "Use your passkey to sign in.");
        spawn_local(async move {
            let result = sign_in(name).await;
            if state.borrow().generation != generation {
                return;
            }
            match result {
                Ok(session) => {
                    let mut s = state.borrow_mut();
                    s.signing = false;
                    s.session = Some(session);
                    controls(&s);
                    drop(s);
                    poll(&state);
                }
                Err(()) => clear(&state, "Sign-in did not complete. Try again when ready."),
            }
        });
    });
    button("sign-in")?
        .add_event_listener_with_callback("click", click.as_ref().unchecked_ref())
        .map_err(|_| ())?;
    click.forget();
    let shared = state.clone();
    let click = Closure::<dyn FnMut(web_sys::Event)>::new(move |_| {
        clear(&shared, "Signed out. Sign in to view actions.")
    });
    button("sign-out")?
        .add_event_listener_with_callback("click", click.as_ref().unchecked_ref())
        .map_err(|_| ())?;
    click.forget();
    for (id, first) in [("first-page", true), ("next-page", false)] {
        let shared = state.clone();
        let click = Closure::<dyn FnMut(web_sys::Event)>::new(move |_| {
            let mut s = shared.borrow_mut();
            if s.polling || s.executing {
                return;
            }
            if let Some(session) = s.session.as_mut() {
                session.after = if first { None } else { session.next.clone() };
            }
            drop(s);
            poll(&shared);
        });
        button(id)?
            .add_event_listener_with_callback("click", click.as_ref().unchecked_ref())
            .map_err(|_| ())?;
        click.forget();
    }
    let shared = state.clone();
    let tick = Closure::<dyn FnMut()>::new(move || poll(&shared));
    window()?
        .set_interval_with_callback_and_timeout_and_arguments_0(tick.as_ref().unchecked_ref(), 5000)
        .map_err(|_| ())?;
    tick.forget();
    let shared = state.clone();
    let visibility = Closure::<dyn FnMut(web_sys::Event)>::new(move |_| {
        if hidden() {
            text("actions", "");
        } else {
            poll(&shared);
        }
    });
    window()?
        .document()
        .ok_or(())?
        .add_event_listener_with_callback("visibilitychange", visibility.as_ref().unchecked_ref())
        .map_err(|_| ())?;
    visibility.forget();
    // Clear memory-held authority on page navigation, including a back/forward cache entry.
    let leave = Closure::<dyn FnMut(web_sys::Event)>::new(move |_| {
        clear(&state, "Sign in to view actions.")
    });
    window()?
        .add_event_listener_with_callback("pagehide", leave.as_ref().unchecked_ref())
        .map_err(|_| ())?;
    leave.forget();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use wasm_bindgen_test::wasm_bindgen_test;
    #[wasm_bindgen_test]
    fn assertion_options_keep_rp_challenge_credentials_and_uv() {
        let o = v::RequestOptions {
            rp_id: v::Text("pi.lan"),
            challenge: v::Challenge([19; 32]),
            timeout_ms: v::Number(120000),
            allow_credentials: v::CredentialList(vec![v::Blob(&[0, 255, 3])]),
            user_verification: v::Required::Required,
        };
        let options = request_options(&o).unwrap();
        let public = Reflect::get(&options, &"publicKey".into()).unwrap();
        assert_eq!(
            Reflect::get(&public, &"rpId".into())
                .unwrap()
                .as_string()
                .as_deref(),
            Some("pi.lan")
        );
        assert_eq!(
            Reflect::get(&public, &"userVerification".into())
                .unwrap()
                .as_string()
                .as_deref(),
            Some("required")
        );
        assert_eq!(
            Uint8Array::new(&Reflect::get(&public, &"challenge".into()).unwrap()).to_vec(),
            vec![19; 32]
        );
        let allow = Array::from(&Reflect::get(&public, &"allowCredentials".into()).unwrap());
        assert_eq!(allow.length(), 1);
        assert_eq!(
            Uint8Array::new(&Reflect::get(&allow.get(0), &"id".into()).unwrap()).to_vec(),
            vec![0, 255, 3]
        );
        assert!(
            Reflect::get(&public, &"extensions".into())
                .unwrap()
                .is_undefined()
        );
    }
}
