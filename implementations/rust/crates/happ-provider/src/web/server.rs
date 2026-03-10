use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse, Redirect},
    routing::{get, post},
    Json, Router,
};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::json;
use tower_http::cors::CorsLayer;

use happ_core::{hash::intent_hash, level::PoHpLevel, signing_view::SigningView, types::IdentityMode};

use crate::adapters::IdentityAdapterOutcome;
use crate::provider::{Provider, SessionStatus};

#[derive(Clone)]
pub struct WebState {
    pub provider: Arc<Provider>,
    pub base_url: String,
    pub allow_mock_pohp: bool,
    pub allow_mock_identity: bool,
    pub pohp_attestation_secret: Option<String>,
}

pub async fn run_web_server(
    provider: Arc<Provider>,
    addr: SocketAddr,
    base_url: String,
    allow_mock_pohp: bool,
    allow_mock_identity: bool,
    pohp_attestation_secret: Option<String>,
) -> anyhow::Result<()> {
    let state = WebState {
        provider,
        base_url,
        allow_mock_pohp,
        allow_mock_identity,
        pohp_attestation_secret,
    };

    let app = Router::new()
        .route("/", get(index))
        .route("/session/:sid", get(session_page))
        .route("/session/:sid/pohp/mock", post(pohp_mock))
        .route("/api/session/:sid/pohp/attest", post(pohp_attest))
        .route("/session/:sid/identity/begin", get(identity_begin))
        .route(
            "/session/:sid/identity/entra_oidc/mock_complete",
            get(identity_entra_oidc_mock_complete),
        )
        .route(
            "/identity/entra_oidc/callback",
            get(identity_entra_oidc_callback),
        )
        .route("/session/:sid/approve", post(approve))
        .route("/session/:sid/deny", post(deny))
        .route("/api/session/:sid", get(api_session))
        .with_state(state.clone());

    let app = if state.allow_mock_pohp || state.allow_mock_identity {
        app.layer(CorsLayer::permissive())
    } else {
        app
    };

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

async fn index(State(st): State<WebState>) -> impl IntoResponse {
    let sessions = st.provider.list_sessions();
    let mut body = String::new();
    body.push_str("<html><body>");
    body.push_str("<h1>HAPP Provider (Reference)</h1>");
    body.push_str(
        "<p>This UI is provider-controlled. It shows the Signing View and collects consent.</p>",
    );
    body.push_str("<h2>Sessions</h2><ul>");
    for s in sessions {
        body.push_str(&format!(
            "<li><a href=\"/session/{sid}\">{sid}</a> — {status:?}</li>",
            sid = s.session_id,
            status = s.status
        ));
    }
    body.push_str("</ul>");
    body.push_str("</body></html>");
    Html(body)
}

async fn session_page(Path(sid): Path<String>, State(st): State<WebState>) -> impl IntoResponse {
    let session = match st.provider.get_session(&sid) {
        None => {
            return (StatusCode::NOT_FOUND, Html("session not found".to_string())).into_response()
        }
        Some(s) => s,
    };

    let ih = intent_hash(&session.intent);
    let view = SigningView::from_intent(&session.intent);

    let mut body = String::new();
    body.push_str("<html><body>");
    body.push_str(&format!("<h1>Session {}</h1>", sid));
    body.push_str(&format!("<p>Status: <b>{:?}</b></p>", session.status));
    body.push_str(&format!("<p>requestId: {}</p>", session.request_id));
    body.push_str(&format!("<p>aud: {}</p>", session.aud));
    body.push_str(&format!("<p>intent_hash: <code>{}</code></p>", ih));

    // identity status
    let idreq = session.requirements.identity.clone();
    if let Some(req) = idreq {
        body.push_str("<h2>Identity Binding</h2>");
        body.push_str(&format!("<p>mode: <b>{:?}</b></p>", req.mode));
        body.push_str(&format!(
            "<p>schemes: <code>{}</code></p>",
            req.schemes.join(", ")
        ));
        if let Some(id) = &session.identity {
            body.push_str("<p>Identity: ✅ completed</p>");
            body.push_str(&format!(
                "<pre>{}</pre>",
                html_escape(&serde_json::to_string_pretty(id).unwrap())
            ));
        } else {
            body.push_str("<p>Identity: ❌ not completed</p>");
            if !matches!(req.mode, IdentityMode::None) {
                body.push_str(&format!(
                    "<p><a href=\"/session/{}/identity/begin\">Begin identity binding</a></p>",
                    sid
                ));
            }
        }
    }

    // PoHP status
    body.push_str("<h2>Proof of Human Presence</h2>");
    if session.pohp_verified_at.is_some() {
        body.push_str(&format!(
            "<p>Presence: ✅ verified via <code>{}</code></p>",
            session.pohp_method.as_deref().unwrap_or("unknown")
        ));
    } else if st.allow_mock_pohp {
        body.push_str(&format!(
            "<form method=\"post\" action=\"/session/{}/pohp/mock\"><button type=\"submit\">Complete mock liveness</button></form>",
            sid
        ));
    } else {
        body.push_str("<p>Presence: pending. Complete PoHP through your external attestation service and POST to <code>/api/session/&lt;sessionId&gt;/pohp/attest</code>.</p>");
    }

    // signing view
    body.push_str("<h2>Signing View (what the human approves)</h2>");
    body.push_str(&format!(
        "<pre>{}</pre>",
        html_escape(&serde_json::to_string_pretty(&view).unwrap())
    ));

    // consent buttons
    body.push_str("<h2>Consent</h2>");
    body.push_str(&format!(
        "<form method=\"post\" action=\"/session/{}/approve\"><button type=\"submit\">Approve</button></form>",
        sid
    ));
    body.push_str(&format!(
        "<form method=\"post\" action=\"/session/{}/deny\"><button type=\"submit\">Deny</button></form>",
        sid
    ));

    body.push_str("<p><a href=\"/\">Back</a></p>");
    body.push_str("</body></html>");
    Html(body).into_response()
}

async fn pohp_mock(Path(sid): Path<String>, State(st): State<WebState>) -> impl IntoResponse {
    if !st.allow_mock_pohp {
        return (StatusCode::FORBIDDEN, Html("mock PoHP disabled".to_string())).into_response();
    }

    let session = match st.provider.get_session(&sid) {
        Some(session) => session,
        None => return Redirect::to("/").into_response(),
    };

    match st
        .provider
        .mark_pohp_verified(&sid, "mock-ui", session.requirements.pohp.min_level, None)
    {
        Ok(_) => Redirect::to(&format!("/session/{sid}")).into_response(),
        Err(_) => Redirect::to("/").into_response(),
    }
}

#[derive(Debug, Deserialize)]
struct PohpAttestationRequest {
    method: String,
    level: PoHpLevel,
    verified_at: Option<DateTime<Utc>>,
}

async fn pohp_attest(
    Path(sid): Path<String>,
    State(st): State<WebState>,
    headers: HeaderMap,
    Json(req): Json<PohpAttestationRequest>,
) -> impl IntoResponse {
    let Some(expected_secret) = st.pohp_attestation_secret.as_deref() else {
        return (StatusCode::NOT_FOUND, Json(json!({"error": "attestation_not_enabled"})));
    };

    if !authorize_attestation(&headers, expected_secret) {
        return (StatusCode::UNAUTHORIZED, Json(json!({"error": "unauthorized"})));
    }

    let method = req.method.trim();
    if method.is_empty() {
        return (StatusCode::BAD_REQUEST, Json(json!({"error": "missing_method"})));
    }
    if method.starts_with("mock") {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "mock_method_not_allowed"})),
        );
    }

    match st
        .provider
        .mark_pohp_verified(&sid, method.to_string(), req.level, req.verified_at)
    {
        Ok(_) => (StatusCode::OK, Json(json!({"ok": true}))),
        Err(err) => (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": err.to_string()})),
        ),
    }
}

async fn approve(Path(sid): Path<String>, State(st): State<WebState>) -> impl IntoResponse {
    let res = st.provider.approve(&sid);
    match res {
        Ok(_) => Redirect::to(&format!("/session/{sid}")).into_response(),
        Err(e) => {
            let body = format!(
                "<html><body><p>Approve failed: {}</p><p><a href=\"/session/{sid}\">Back</a></p></body></html>",
                html_escape(&e.to_string())
            );
            (StatusCode::UNAUTHORIZED, Html(body)).into_response()
        }
    }
}

async fn deny(Path(sid): Path<String>, State(st): State<WebState>) -> impl IntoResponse {
    let _ = st.provider.deny(&sid);
    Redirect::to(&format!("/session/{sid}"))
}

async fn identity_begin(Path(sid): Path<String>, State(st): State<WebState>) -> impl IntoResponse {
    match st.provider.identity_begin(&sid, &st.base_url).await {
        Ok(Some(outcome)) => match outcome {
            IdentityAdapterOutcome::Redirect { url } => Redirect::to(&url).into_response(),
            IdentityAdapterOutcome::LocalAction { url, .. } => Redirect::to(&url).into_response(),
            IdentityAdapterOutcome::Completed => {
                Redirect::to(&format!("/session/{sid}")).into_response()
            }
        },
        Ok(None) => Redirect::to(&format!("/session/{sid}")).into_response(),
        Err(e) => {
            let body = format!(
                "<html><body><p>Identity begin failed: {}</p><p><a href=\"/session/{sid}\">Back</a></p></body></html>",
                html_escape(&e.to_string())
            );
            (StatusCode::BAD_REQUEST, Html(body)).into_response()
        }
    }
}

async fn identity_entra_oidc_mock_complete(
    Path(sid): Path<String>,
    Query(q): Query<HashMap<String, String>>,
    State(st): State<WebState>,
) -> impl IntoResponse {
    if !st.allow_mock_identity {
        return (StatusCode::NOT_FOUND, Html("mock identity disabled".to_string())).into_response();
    }

    // Delegate to the adapter callback handler.
    let adapter = st
        .provider
        .adapters()
        .get("entra_oidc")
        .expect("entra_oidc adapter registered");

    match adapter
        .handle_callback(st.provider.clone(), &sid, &q, &st.base_url)
        .await
    {
        Ok(_) => Redirect::to(&format!("/session/{sid}")).into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, Html(e.to_string())).into_response(),
    }
}

async fn identity_entra_oidc_callback(
    Query(q): Query<HashMap<String, String>>,
    State(st): State<WebState>,
) -> impl IntoResponse {
    let adapter = st
        .provider
        .adapters()
        .get("entra_oidc")
        .expect("entra_oidc adapter registered");

    // session id is discovered via stored OIDC state.
    match adapter
        .handle_callback(st.provider.clone(), "", &q, &st.base_url)
        .await
    {
        Ok(_) => Redirect::to("/").into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, Html(e.to_string())).into_response(),
    }
}

async fn api_session(Path(sid): Path<String>, State(st): State<WebState>) -> impl IntoResponse {
    if st.pohp_attestation_secret.is_some() {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"error":"session_api_disabled_in_production"})),
        )
            .into_response();
    }

    if let Some(s) = st.provider.get_session(&sid) {
        let env = match s.status {
            SessionStatus::Approved => st.provider.issue_credential(&sid).ok(),
            _ => None,
        };
        Json(json!({
            "session": s,
            "issued": env
        }))
        .into_response()
    } else {
        (StatusCode::NOT_FOUND, Json(json!({"error":"not found"}))).into_response()
    }
}

/// Escape HTML without pulling in an extra crate.
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('\"', "&quot;")
        .replace('\'', "&#x27;")
}

fn authorize_attestation(headers: &HeaderMap, expected_secret: &str) -> bool {
    let bearer_ok = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .map(|value| value == expected_secret)
        .unwrap_or(false);

    let custom_ok = headers
        .get("x-happ-pohp-secret")
        .and_then(|value| value.to_str().ok())
        .map(|value| value == expected_secret)
        .unwrap_or(false);

    bearer_ok || custom_ok
}
