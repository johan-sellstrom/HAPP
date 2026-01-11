\
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{Html, IntoResponse, Redirect},
    routing::{get, post},
    Json, Router,
};
use serde_json::json;
use tower_http::cors::CorsLayer;

use happ_core::{hash::intent_hash, signing_view::SigningView, types::IdentityMode};

use crate::adapters::IdentityAdapterOutcome;
use crate::provider::{Provider, SessionStatus};

#[derive(Clone)]
pub struct WebState {
    pub provider: Arc<Provider>,
    pub base_url: String,
}

pub async fn run_web_server(provider: Arc<Provider>, addr: SocketAddr, base_url: String) -> anyhow::Result<()> {
    let state = WebState { provider, base_url };

    let app = Router::new()
        .route("/", get(index))
        .route("/session/:sid", get(session_page))
        .route("/session/:sid/pohp/mock", post(pohp_mock))
        .route("/session/:sid/identity/begin", get(identity_begin))
        .route("/session/:sid/identity/entra_oidc/mock_complete", get(identity_entra_oidc_mock_complete))
        .route("/identity/entra_oidc/callback", get(identity_entra_oidc_callback))
        .route("/session/:sid/approve", post(approve))
        .route("/session/:sid/deny", post(deny))
        .route("/api/session/:sid", get(api_session))
        .layer(CorsLayer::permissive())
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

async fn index(State(st): State<WebState>) -> impl IntoResponse {
    let sessions = st.provider.list_sessions();
    let mut body = String::new();
    body.push_str("<html><body>");
    body.push_str("<h1>HAPP Provider (Reference)</h1>");
    body.push_str("<p>This UI is provider-controlled. It shows the Signing View and collects consent.</p>");
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
        None => return (StatusCode::NOT_FOUND, Html("session not found".to_string())).into_response(),
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
        body.push_str(&format!("<p>schemes: <code>{}</code></p>", req.schemes.join(", ")));
        if let Some(id) = &session.identity {
            body.push_str("<p>Identity: ✅ completed</p>");
            body.push_str(&format!("<pre>{}</pre>", html_escape(&serde_json::to_string_pretty(id).unwrap())));
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
        body.push_str("<p>Presence: ✅ verified (mock)</p>");
    } else {
        body.push_str(&format!(
            "<form method=\"post\" action=\"/session/{}/pohp/mock\"><button type=\"submit\">Complete mock liveness</button></form>",
            sid
        ));
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
    Html(body)
}

async fn pohp_mock(Path(sid): Path<String>, State(st): State<WebState>) -> impl IntoResponse {
    match st.provider.mark_pohp_verified(&sid) {
        Ok(_) => Redirect::to(&format!("/session/{sid}")),
        Err(_) => Redirect::to("/"),
    }
}

async fn approve(Path(sid): Path<String>, State(st): State<WebState>) -> impl IntoResponse {
    let res = st.provider.approve(&sid);
    match res {
        Ok(_) => Redirect::to(&format!("/session/{sid}")),
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
            IdentityAdapterOutcome::Completed => Redirect::to(&format!("/session/{sid}")).into_response(),
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
