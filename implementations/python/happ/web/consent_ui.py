from __future__ import annotations

import json
import os
import secrets
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, Optional
from urllib.parse import parse_qs, urlparse

from happ.adapters.entra_mock import default_mock_issuer
from happ.adapters.entra_oidc_pkce import env_config, pkce_create_verifier, build_authorize_url, exchange_code_for_tokens
from happ.session_store import STORE
from happ.util import sha256_b64url, b64url_decode, now_utc


def _html_page(title: str, body: str) -> bytes:
    return f"""<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <title>{title}</title>
  <style>
    body {{ font-family: -apple-system, system-ui, Segoe UI, Roboto, Helvetica, Arial, sans-serif; padding: 24px; max-width: 960px; margin: 0 auto; }}
    code, pre {{ background: #f5f5f5; padding: 2px 6px; border-radius: 4px; }}
    pre {{ padding: 12px; overflow-x: auto; }}
    .card {{ border: 1px solid #ddd; border-radius: 10px; padding: 16px; margin: 14px 0; }}
    .ok {{ color: #0a7; }}
    .bad {{ color: #b00; }}
    button {{ padding: 10px 14px; border-radius: 8px; border: 1px solid #ccc; background: #fff; cursor: pointer; }}
    button.primary {{ border-color: #0a7; }}
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


def _decode_jwt_payload(token: str) -> Dict[str, Any]:
    parts = token.split(".")
    if len(parts) < 2:
        return {}
    payload_b64 = parts[1]
    return json.loads(b64url_decode(payload_b64).decode("utf-8"))


class ConsentUIHandler(BaseHTTPRequestHandler):
    server_version = "HAPPConsentUI/0.3.4"

    def _send(self, status: int, html: bytes, content_type: str = "text/html; charset=utf-8") -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(html)))
        self.end_headers()
        self.wfile.write(html)

    def _redirect(self, url: str) -> None:
        self.send_response(302)
        self.send_header("Location", url)
        self.end_headers()

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/":
            body = """<h1>HAPP Consent UI (v0.3.4)</h1>
<p>This is a <b>demo</b> provider UI for URL-mode consent + (optional) Entra identity binding.</p>
<p>When you receive an elicitation URL, open it here: <code>/session/&lt;elicitationId&gt;</code></p>
"""
            self._send(200, _html_page("HAPP Consent UI", body))
            return

        if path.startswith("/session/"):
            elicitation_id = path.split("/")[2]
            sess = STORE.get(elicitation_id)
            if sess is None:
                self._send(404, _html_page("Not found", f"<h1>Unknown session</h1><p>{elicitation_id}</p>"))
                return

            identity_req = ((sess.requirements.get("identity") or {}).get("mode")) if isinstance(sess.requirements, dict) else None
            identity_required = identity_req == "required"
            has_identity = sess.identity_binding is not None

            status = "<span class='ok'>APPROVED</span>" if sess.approved else ("<span class='bad'>DENIED</span>" if sess.denied else "PENDING")
            body = f"""<h1>Approve agent action</h1>
<p>Session: <code>{elicitation_id}</code></p>
<p>Status: {status}</p>

<div class="card">
  <h2>What you are approving</h2>
  <pre>{json.dumps(sess.action_intent.get("display") or sess.action_intent, indent=2)}</pre>
</div>

<div class="card">
  <h2>Enterprise identity binding</h2>
  <p>Requirement: <code>{identity_req or "none"}</code></p>
  <p>Identity present: {"<span class='ok'>YES</span>" if has_identity else "<span class='bad'>NO</span>"}</p>
"""

            entra_mode = os.environ.get("HAPP_ENTRA_MODE", "mock").lower()
            if identity_required and not has_identity:
                if entra_mode == "real":
                    body += f"""<p><a href="/entra/start?session={elicitation_id}"><button class="primary">Sign in with Entra</button></a></p>"""
                else:
                    body += f"""<form method="POST" action="/session/{elicitation_id}/mock_identity">
  <button class="primary" type="submit">Use mock Entra identity (offline)</button>
</form>"""
            elif has_identity:
                body += f"""<details><summary>Identity binding details</summary><pre>{json.dumps(sess.identity_binding, indent=2)}</pre></details>"""

            body += """</div>"""

            disabled = "disabled" if (identity_required and not has_identity) else ""
            body += f"""<form method="POST" action="/session/{elicitation_id}/approve">
  <button class="primary" type="submit" {disabled}>Approve</button>
</form>
<form method="POST" action="/session/{elicitation_id}/deny" style="margin-top:10px;">
  <button type="submit">Deny</button>
</form>
"""
            self._send(200, _html_page("Approve", body))
            return

        if path == "/entra/start":
            qs = parse_qs(parsed.query)
            session_id = (qs.get("session") or [""])[0]
            sess = STORE.get(session_id)
            if sess is None:
                self._send(404, _html_page("Not found", "<h1>Unknown session</h1>"))
                return

            cfg = env_config()
            if not cfg.client_id:
                self._send(400, _html_page("Entra not configured", "<h1>Missing HAPP_ENTRA_CLIENT_ID</h1>"))
                return

            state = secrets.token_urlsafe(24)
            nonce = secrets.token_urlsafe(24)
            verifier = pkce_create_verifier()

            STORE.update(session_id, state=state, nonce=nonce, code_verifier=verifier)

            url = build_authorize_url(cfg, state=state, nonce=nonce, code_verifier=verifier)
            self._redirect(url)
            return

        if path == "/entra/callback":
            qs = parse_qs(parsed.query)
            code = (qs.get("code") or [""])[0]
            state = (qs.get("state") or [""])[0]

            # Find session by state
            target = None
            # brute force lookup (demo only)
            for sid in list(getattr(STORE, "_sessions", {}).keys()):
                sess = STORE.get(sid)
                if sess and sess.state == state:
                    target = sess
                    break
            if target is None:
                self._send(400, _html_page("Bad state", "<h1>Unknown or expired state</h1>"))
                return

            cfg = env_config()
            try:
                tokens = exchange_code_for_tokens(cfg, code=code, code_verifier=target.code_verifier or "")
                id_token = tokens.get("id_token", "")
                payload = _decode_jwt_payload(id_token)

                tid = payload.get("tid")
                oid = payload.get("oid")
                nonce = payload.get("nonce")
                if nonce != target.nonce:
                    raise ValueError("Nonce mismatch")

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
                        "note": "JWKS validation not implemented in this demo callback handler.",
                    },
                }
                STORE.update(target.elicitation_id, entra_tokens=tokens, identity_binding=identity_binding, debug={"entraPayload": payload})
            except Exception as e:
                tb = traceback.format_exc()
                STORE.update(target.elicitation_id, debug={"entraError": str(e), "traceback": tb})

            self._redirect(f"/session/{target.elicitation_id}")
            return

        self._send(404, _html_page("Not found", "<h1>Not found</h1>"))

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path

        if path.startswith("/session/") and path.endswith("/approve"):
            elicitation_id = path.split("/")[2]
            sess = STORE.get(elicitation_id)
            if sess is None:
                self._send(404, _html_page("Not found", "<h1>Unknown session</h1>"))
                return

            identity_req = ((sess.requirements.get("identity") or {}).get("mode")) if isinstance(sess.requirements, dict) else None
            identity_required = identity_req == "required"
            if identity_required and sess.identity_binding is None:
                self._send(400, _html_page("Identity required", "<h1>Identity binding is required before approval.</h1>"))
                return

            STORE.update(elicitation_id, approved=True, denied=False)
            self._redirect(f"/session/{elicitation_id}")
            return

        if path.startswith("/session/") and path.endswith("/deny"):
            elicitation_id = path.split("/")[2]
            if STORE.get(elicitation_id) is None:
                self._send(404, _html_page("Not found", "<h1>Unknown session</h1>"))
                return
            STORE.update(elicitation_id, denied=True, approved=False)
            self._redirect(f"/session/{elicitation_id}")
            return

        if path.startswith("/session/") and path.endswith("/mock_identity"):
            elicitation_id = path.split("/")[2]
            sess = STORE.get(elicitation_id)
            if sess is None:
                self._send(404, _html_page("Not found", "<h1>Unknown session</h1>"))
                return

            # ensure nonce exists
            nonce = sess.nonce or secrets.token_urlsafe(24)
            STORE.update(elicitation_id, nonce=nonce)

            # mock values
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
    server = ThreadingHTTPServer(("127.0.0.1", port), ConsentUIHandler)
    return server
