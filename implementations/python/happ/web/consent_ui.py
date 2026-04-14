from __future__ import annotations

import json
import os
import secrets
import traceback
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, Optional
from urllib.parse import parse_qs, urlparse

from happ.adapters.entra_mock import default_mock_issuer
from happ.adapters.entra_oidc_pkce import (
    build_authorize_url,
    derive_claims_request,
    env_config,
    exchange_code_for_tokens,
    fetch_jwks,
    fetch_openid_configuration,
    pkce_create_verifier,
    verify_id_token,
)
from happ.session_store import ConsentSession, STORE
from happ.util import now_utc, sha256_b64url


_POHP_ORDER = {"AAIF-PoHP-1": 1, "AAIF-PoHP-2": 2, "AAIF-PoHP-3": 3, "AAIF-PoHP-4": 4}


def _html_page(title: str, body: str) -> bytes:
    return f"""<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>{title}</title>
  <style>
    body {{ font-family: -apple-system, system-ui, Segoe UI, Roboto, Helvetica, Arial, sans-serif; padding: 24px; max-width: 960px; margin: 0 auto; background: #fafafa; color: #111; }}
    code, pre {{ background: #f2f2f2; padding: 2px 6px; border-radius: 4px; }}
    pre {{ padding: 12px; overflow-x: auto; }}
    .card {{ border: 1px solid #ddd; border-radius: 10px; padding: 16px; margin: 14px 0; background: #fff; }}
    .ok {{ color: #0a7; }}
    .bad {{ color: #b00; }}
    .warn {{ color: #9a6700; }}
    button {{ padding: 10px 14px; border-radius: 8px; border: 1px solid #ccc; background: #fff; cursor: pointer; }}
    button.primary {{ border-color: #0a7; }}
    form {{ margin: 0; }}
  </style>
</head>
<body>
{body}
</body>
</html>""".encode("utf-8")


def _post_form(handler: BaseHTTPRequestHandler) -> Dict[str, str]:
    length = int(handler.headers.get("Content-Length", "0"))
    data = handler.rfile.read(length).decode("utf-8")
    return {k: v[0] for k, v in parse_qs(data).items()}


def _runtime_mode() -> str:
    mode = os.environ.get("HAPP_RUNTIME_MODE", "development").strip().lower()
    return mode or "development"


def _production_mode() -> bool:
    return _runtime_mode() == "production"


def _allow_mock_identity() -> bool:
    return not _production_mode() and os.environ.get("HAPP_ENTRA_MODE", "mock").strip().lower() != "real"


def _allow_mock_pohp() -> bool:
    return not _production_mode()


def _pohp_rank(level: Optional[str]) -> int:
    if level is None:
        return 0
    if level not in _POHP_ORDER:
        raise ValueError(f"invalid PoHP level: {level}")
    return _POHP_ORDER[level]


def _required_pohp_level(requirements: Dict[str, Any]) -> str:
    return ((requirements.get("pohp") or {}).get("minLevel")) or "AAIF-PoHP-3"




def _entra_claims_request_from_requirements(requirements: Dict[str, Any]) -> Optional[str]:
    identity = requirements.get("identity") if isinstance(requirements, dict) else None
    if not isinstance(identity, dict):
        return None
    scheme_params = identity.get("schemeParams") or {}
    if not isinstance(scheme_params, dict):
        scheme_params = {}
    policy = identity.get("policy") or {}
    if not isinstance(policy, dict):
        policy = {}

    explicit = policy.get("entraClaimsChallenge")
    if explicit is None:
        explicit = scheme_params.get("entra_claims_challenge")

    contexts = policy.get("requiredAuthContexts")
    if not isinstance(contexts, list):
        contexts = []

    return derive_claims_request(
        required_auth_contexts=[c for c in contexts if isinstance(c, str)],
        require_mfa=bool(policy.get("requireMfa")),
        explicit_claims=explicit,
        include_cp1=True,
    )

def _parse_verified_at(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _action_form(action: str, label: str, sess: ConsentSession, *, css_class: str = "", disabled: bool = False) -> str:
    attrs = ' class="primary"' if css_class == "primary" else ""
    disabled_attr = " disabled" if disabled else ""
    return (
        f'<form method="POST" action="{action}">'
        f'<input type="hidden" name="csrfToken" value="{sess.csrf_token}" />'
        f'<button type="submit"{attrs}{disabled_attr}>{label}</button>'
        "</form>"
    )


class ConsentUIHandler(BaseHTTPRequestHandler):
    server_version = "HAPPConsentUI/0.3.4"

    def _send_security_headers(self) -> None:
        self.send_header("Cache-Control", "no-store")
        self.send_header("Pragma", "no-cache")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'none'; style-src 'unsafe-inline'; img-src 'self' data:; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
        )

    def _send(self, status: int, html: bytes, content_type: str = "text/html; charset=utf-8") -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(html)))
        self._send_security_headers()
        self.end_headers()
        self.wfile.write(html)

    def _send_json(self, status: int, obj: Any) -> None:
        body = json.dumps(obj, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self._send_security_headers()
        self.end_headers()
        self.wfile.write(body)

    def _redirect(self, url: str) -> None:
        self.send_response(302)
        self.send_header("Location", url)
        self._send_security_headers()
        self.end_headers()

    def _session_from_path(self, path: str) -> tuple[str, Optional[ConsentSession]]:
        elicitation_id = path.split("/")[2]
        return elicitation_id, STORE.get(elicitation_id)

    def _require_open_session(self, sess: ConsentSession) -> Optional[bytes]:
        if sess.approved or sess.denied:
            return _html_page("Session closed", "<h1>Session is already closed</h1>")
        return None

    def _require_csrf(self, sess: ConsentSession, form: Dict[str, str]) -> bool:
        return form.get("csrfToken") == sess.csrf_token

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/":
            body = """<h1>HAPP Consent UI (v0.3.4)</h1>
<p>This is a reference provider UI for URL-mode consent, presence attestation, and optional Entra identity binding.</p>
<p>When you receive an elicitation URL, open it here: <code>/session/&lt;elicitationId&gt;</code></p>
"""
            self._send(200, _html_page("HAPP Consent UI", body))
            return

        if path == "/entra/start":
            self._send(405, _html_page("Method not allowed", "<h1>Use POST to initiate identity binding</h1>"))
            return

        if path.startswith("/session/"):
            elicitation_id, sess = self._session_from_path(path)
            if sess is None:
                self._send(404, _html_page("Not found", f"<h1>Unknown session</h1><p>{elicitation_id}</p>"))
                return

            requirements = sess.requirements if isinstance(sess.requirements, dict) else {}
            identity_req = ((requirements.get("identity") or {}).get("mode")) or "none"
            identity_required = identity_req == "required"
            has_identity = sess.identity_binding is not None
            required_pohp_level = _required_pohp_level(requirements)
            pohp_pending = sess.pohp_verified_at is None
            pohp_satisfies = False
            if not pohp_pending:
                try:
                    pohp_satisfies = _pohp_rank(sess.pohp_level) >= _pohp_rank(required_pohp_level)
                except ValueError:
                    pohp_satisfies = False

            if sess.approved:
                status = "<span class='ok'>APPROVED</span>"
            elif sess.denied:
                status = "<span class='bad'>DENIED</span>"
            else:
                status = "PENDING"

            body = f"""<h1>Approve agent action</h1>
<p>Session: <code>{elicitation_id}</code></p>
<p>Status: {status}</p>

<div class="card">
  <h2>What you are approving</h2>
  <pre>{json.dumps(sess.action_intent.get("display") or sess.action_intent, indent=2)}</pre>
</div>

<div class="card">
  <h2>Presence attestation</h2>
  <p>Required level: <code>{required_pohp_level}</code></p>
"""

            if pohp_pending:
                body += "<p>Presence status: <span class='bad'>PENDING</span></p>"
                if _allow_mock_pohp():
                    body += _action_form(
                        f"/session/{elicitation_id}/pohp/mock",
                        "Complete mock presence check",
                        sess,
                        css_class="primary",
                    )
                else:
                    body += (
                        f"<p>Presence must be attested by your external verifier and POSTed to "
                        f"<code>/api/session/{elicitation_id}/pohp/attest</code>.</p>"
                    )
            else:
                level_class = "ok" if pohp_satisfies else "warn"
                body += (
                    f"<p>Presence status: <span class='{level_class}'>{sess.pohp_level or 'unknown'}</span></p>"
                    f"<p>Method: <code>{sess.pohp_method or 'unknown'}</code></p>"
                    f"<p>Verified at: <code>{sess.pohp_verified_at.isoformat().replace('+00:00', 'Z')}</code></p>"
                )
                if not pohp_satisfies:
                    body += "<p class='warn'>Presence level does not satisfy the requested minimum.</p>"

            body += "</div>"

            body += f"""<div class="card">
  <h2>Enterprise identity binding</h2>
  <p>Requirement: <code>{identity_req}</code></p>
  <p>Identity present: {"<span class='ok'>YES</span>" if has_identity else "<span class='bad'>NO</span>"}</p>
"""

            if identity_required and not has_identity:
                if os.environ.get("HAPP_ENTRA_MODE", "mock").strip().lower() == "real":
                    body += (
                        f'<form method="POST" action="/entra/start">'
                        f'<input type="hidden" name="session" value="{elicitation_id}" />'
                        f'<input type="hidden" name="csrfToken" value="{sess.csrf_token}" />'
                        '<button class="primary" type="submit">Sign in with Entra</button>'
                        "</form>"
                    )
                elif _allow_mock_identity():
                    body += _action_form(
                        f"/session/{elicitation_id}/mock_identity",
                        "Use mock Entra identity (offline)",
                        sess,
                        css_class="primary",
                    )
                else:
                    body += "<p class='warn'>Mock identity is disabled in production mode.</p>"
            elif has_identity:
                body += f"""<details><summary>Identity binding details</summary><pre>{json.dumps(sess.identity_binding, indent=2)}</pre></details>"""

            body += "</div>"

            approve_disabled = identity_required and not has_identity
            approve_disabled = approve_disabled or not pohp_satisfies

            if not (sess.approved or sess.denied):
                body += _action_form(
                    f"/session/{elicitation_id}/approve",
                    "Approve",
                    sess,
                    css_class="primary",
                    disabled=approve_disabled,
                )
                body += f'<div style="margin-top:10px;">{_action_form(f"/session/{elicitation_id}/deny", "Deny", sess)}</div>'

            self._send(200, _html_page("Approve", body))
            return

        if path == "/entra/callback":
            qs = parse_qs(parsed.query)
            code = (qs.get("code") or [""])[0]
            state = (qs.get("state") or [""])[0]
            if not code or not state:
                self._send(400, _html_page("Bad callback", "<h1>Missing code or state</h1>"))
                return
            target = STORE.consume_oidc_state(state)
            if target is None:
                self._send(400, _html_page("Bad state", "<h1>Unknown or expired state</h1>"))
                return
            closed = self._require_open_session(target)
            if closed is not None:
                self._send(409, closed)
                return

            cfg = env_config()
            try:
                tokens = exchange_code_for_tokens(cfg, code=code, code_verifier=target.code_verifier or "")
                id_token = tokens.get("id_token", "")
                metadata = fetch_openid_configuration(cfg)
                payload = verify_id_token(
                    id_token=id_token,
                    jwks=fetch_jwks(metadata["jwks_uri"]),
                    expected_issuer=str(metadata["issuer"]),
                    expected_audience=cfg.client_id,
                    expected_nonce=target.nonce or "",
                )

                tid = payload["tid"]
                oid = payload["oid"]
                identity_binding = {
                    "mode": "verified",
                    "scheme": "entra_oidc",
                    "idp": {"issuer": payload.get("iss"), "tenantId": tid},
                    "subject": {"type": "entra_oid_tid", "tid": tid, "oid": oid},
                    "assurance": {
                        "authTime": payload.get("auth_time"),
                        "amr": payload.get("amr"),
                        "acrs": payload.get("acrs"),
                    },
                    "evidence": {
                        "kind": "oidc_id_token",
                        "embedded": True,
                        "id_token": id_token,
                        "jwks": fetch_jwks(metadata["jwks_uri"]),
                        "tokenHash": "sha256:" + sha256_b64url(id_token.encode("utf-8")),
                        "nonceHash": "sha256:" + sha256_b64url((target.nonce or "").encode("utf-8")),
                    },
                }
                STORE.update(
                    target.elicitation_id,
                    code_verifier=None,
                    entra_tokens=tokens,
                    identity_binding=identity_binding,
                    debug={"entraPayload": payload},
                )
            except Exception as exc:
                debug: Dict[str, Any] = {"entraError": str(exc)}
                if not _production_mode():
                    debug["traceback"] = traceback.format_exc()
                STORE.update(target.elicitation_id, code_verifier=None, debug=debug)

            self._redirect(f"/session/{target.elicitation_id}")
            return

        self._send(404, _html_page("Not found", "<h1>Not found</h1>"))

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/entra/start":
            form = _post_form(self)
            session_id = form.get("session", "")
            sess = STORE.get(session_id)
            if sess is None:
                self._send(404, _html_page("Not found", "<h1>Unknown session</h1>"))
                return
            if not self._require_csrf(sess, form):
                self._send(403, _html_page("Forbidden", "<h1>Invalid CSRF token</h1>"))
                return
            closed = self._require_open_session(sess)
            if closed is not None:
                self._send(409, closed)
                return

            cfg = env_config()
            if not cfg.client_id:
                self._send(400, _html_page("Entra not configured", "<h1>Missing HAPP_ENTRA_CLIENT_ID</h1>"))
                return

            requirements = sess.requirements if isinstance(sess.requirements, dict) else {}
            claims_request = _entra_claims_request_from_requirements(requirements)

            state = secrets.token_urlsafe(24)
            nonce = secrets.token_urlsafe(24)
            verifier = pkce_create_verifier()
            STORE.begin_oidc_flow(session_id, state=state, nonce=nonce, code_verifier=verifier)
            STORE.update(session_id, debug={**(sess.debug or {}), "entraClaimsRequest": claims_request} if claims_request else dict(sess.debug or {}))
            self._redirect(build_authorize_url(cfg, state=state, nonce=nonce, code_verifier=verifier, claims_request=claims_request))
            return

        if path.startswith("/api/session/") and path.endswith("/pohp/attest"):
            elicitation_id = path.split("/")[3]
            sess = STORE.get(elicitation_id)
            if sess is None:
                self._send_json(404, {"error": "not_found"})
                return
            expected_secret = os.environ.get("HAPP_POHP_ATTESTATION_SECRET", "").strip()
            if not expected_secret:
                self._send_json(503, {"error": "server_not_configured"})
                return
            provided_secret = self.headers.get("x-happ-pohp-secret", "").strip()
            if provided_secret != expected_secret:
                self._send_json(401, {"error": "unauthorized"})
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
                payload = json.loads(self.rfile.read(length).decode("utf-8") or "{}")
                if not isinstance(payload, dict):
                    raise ValueError("request body must be a JSON object")
                level = payload.get("level")
                method = payload.get("method")
                if level not in _POHP_ORDER:
                    raise ValueError("invalid level")
                if not isinstance(method, str) or not method.strip() or method.startswith("mock"):
                    raise ValueError("invalid method")
                verified_at = _parse_verified_at(payload.get("verifiedAt"))
            except (ValueError, json.JSONDecodeError) as exc:
                self._send_json(400, {"error": "invalid_request", "detail": str(exc)})
                return

            STORE.mark_pohp_verified(elicitation_id, level=level, method=method, verified_at=verified_at)
            self._send_json(200, {"ok": True})
            return

        if path.startswith("/session/") and path.endswith("/approve"):
            form = _post_form(self)
            elicitation_id, sess = self._session_from_path(path)
            if sess is None:
                self._send(404, _html_page("Not found", "<h1>Unknown session</h1>"))
                return
            if not self._require_csrf(sess, form):
                self._send(403, _html_page("Forbidden", "<h1>Invalid CSRF token</h1>"))
                return
            closed = self._require_open_session(sess)
            if closed is not None:
                self._send(409, closed)
                return

            requirements = sess.requirements if isinstance(sess.requirements, dict) else {}
            identity_required = ((requirements.get("identity") or {}).get("mode")) == "required"
            if identity_required and sess.identity_binding is None:
                self._send(400, _html_page("Identity required", "<h1>Identity binding is required before approval.</h1>"))
                return
            required_pohp_level = _required_pohp_level(requirements)
            if sess.pohp_verified_at is None:
                self._send(400, _html_page("Presence required", "<h1>Presence verification is required before approval.</h1>"))
                return
            try:
                if _pohp_rank(sess.pohp_level) < _pohp_rank(required_pohp_level):
                    self._send(400, _html_page("Presence too weak", "<h1>Presence verification level is below the required minimum.</h1>"))
                    return
            except ValueError:
                self._send(400, _html_page("Presence invalid", "<h1>Presence verification level is invalid.</h1>"))
                return

            STORE.clear_oidc_state(elicitation_id)
            STORE.update(elicitation_id, approved=True, denied=False)
            self._redirect(f"/session/{elicitation_id}")
            return

        if path.startswith("/session/") and path.endswith("/deny"):
            form = _post_form(self)
            elicitation_id, sess = self._session_from_path(path)
            if sess is None:
                self._send(404, _html_page("Not found", "<h1>Unknown session</h1>"))
                return
            if not self._require_csrf(sess, form):
                self._send(403, _html_page("Forbidden", "<h1>Invalid CSRF token</h1>"))
                return
            closed = self._require_open_session(sess)
            if closed is not None:
                self._send(409, closed)
                return

            STORE.clear_oidc_state(elicitation_id)
            STORE.update(elicitation_id, denied=True, approved=False)
            self._redirect(f"/session/{elicitation_id}")
            return

        if path.startswith("/session/") and path.endswith("/pohp/mock"):
            form = _post_form(self)
            elicitation_id, sess = self._session_from_path(path)
            if sess is None:
                self._send(404, _html_page("Not found", "<h1>Unknown session</h1>"))
                return
            if not self._require_csrf(sess, form):
                self._send(403, _html_page("Forbidden", "<h1>Invalid CSRF token</h1>"))
                return
            if not _allow_mock_pohp():
                self._send(403, _html_page("Forbidden", "<h1>Mock presence verification is disabled</h1>"))
                return
            closed = self._require_open_session(sess)
            if closed is not None:
                self._send(409, closed)
                return

            STORE.mark_pohp_verified(
                elicitation_id,
                level=_required_pohp_level(sess.requirements if isinstance(sess.requirements, dict) else {}),
                method="mock-ui",
            )
            self._redirect(f"/session/{elicitation_id}")
            return

        if path.startswith("/session/") and path.endswith("/mock_identity"):
            form = _post_form(self)
            elicitation_id, sess = self._session_from_path(path)
            if sess is None:
                self._send(404, _html_page("Not found", "<h1>Unknown session</h1>"))
                return
            if not self._require_csrf(sess, form):
                self._send(403, _html_page("Forbidden", "<h1>Invalid CSRF token</h1>"))
                return
            if not _allow_mock_identity():
                self._send(403, _html_page("Forbidden", "<h1>Mock identity is disabled</h1>"))
                return
            closed = self._require_open_session(sess)
            if closed is not None:
                self._send(409, closed)
                return

            nonce = sess.nonce or secrets.token_urlsafe(24)
            STORE.clear_oidc_state(elicitation_id)
            STORE.update(elicitation_id, nonce=nonce)

            tenant_id = os.environ.get("HAPP_ENTRA_MOCK_TID", "00000000-0000-0000-0000-000000000000")
            oid = os.environ.get("HAPP_ENTRA_MOCK_OID", "11111111-1111-1111-1111-111111111111")
            client_id = os.environ.get("HAPP_ENTRA_CLIENT_ID", "mock-client")

            issuer = default_mock_issuer(client_id)
            id_token = issuer.issue_id_token(
                tenant_id=tenant_id,
                oid=oid,
                nonce=nonce,
                amr=["pwd", "mfa"],
                acrs=["c1"],
            )
            jwks = issuer.jwks()

            identity_binding = {
                "mode": "verified",
                "scheme": "entra_oidc",
                "idp": {"issuer": issuer.issuer, "tenantId": tenant_id},
                "subject": {"type": "entra_oid_tid", "tid": tenant_id, "oid": oid},
                "assurance": {"authTime": int(now_utc().timestamp()), "amr": ["pwd", "mfa"], "acrs": ["c1"]},
                "evidence": {
                    "kind": "oidc_id_token",
                    "embedded": True,
                    "id_token": id_token,
                    "jwks": jwks,
                    "tokenHash": "sha256:" + sha256_b64url(id_token.encode("utf-8")),
                    "nonceHash": "sha256:" + sha256_b64url(nonce.encode("utf-8")),
                },
            }
            STORE.update(elicitation_id, identity_binding=identity_binding)
            self._redirect(f"/session/{elicitation_id}")
            return

        self._send(404, _html_page("Not found", "<h1>Not found</h1>"))


def run_ui(port: int = 8787) -> ThreadingHTTPServer:
    return ThreadingHTTPServer(("127.0.0.1", port), ConsentUIHandler)
