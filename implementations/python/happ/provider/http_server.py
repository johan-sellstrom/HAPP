from __future__ import annotations

import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, Optional
from urllib.parse import urlparse

from happ.identity import IdentityBindingResult
from happ.provider.issuer import SigningConfigurationError, issue_consent_credential


MAX_REQUEST_BYTES = 256 * 1024


def _env_flag(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in {"1", "true", "yes", "on"}


def _runtime_mode() -> str:
    mode = os.environ.get("HAPP_RUNTIME_MODE", "development").strip().lower()
    return mode or "development"


def _production_mode() -> bool:
    return _runtime_mode() == "production"


class RefProviderHandler(BaseHTTPRequestHandler):
    server_version = "HAPPRefProvider/0.3.4"

    def _read_json(self) -> Dict[str, Any]:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError as exc:
            raise ValueError("invalid Content-Length") from exc
        if length < 0 or length > MAX_REQUEST_BYTES:
            raise ValueError("request body too large")
        data = self.rfile.read(length)
        try:
            payload = json.loads(data.decode("utf-8") or "{}")
        except json.JSONDecodeError as exc:
            raise ValueError("invalid JSON body") from exc
        if not isinstance(payload, dict):
            raise ValueError("request body must be a JSON object")
        return payload

    def _send(self, status: int, obj: Any, content_type: str = "application/json") -> None:
        body = json.dumps(obj, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Pragma", "no-cache")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        if status == 401:
            self.send_header("WWW-Authenticate", 'Bearer realm="happ-ref-provider"')
        self.end_headers()
        self.wfile.write(body)

    def _authorize_issue_request(self) -> Optional[Dict[str, Any]]:
        token = os.environ.get("HAPP_HTTP_BEARER_TOKEN", "").strip()
        if not token and not _production_mode():
            return None
        if not token:
            return {"status": 503, "body": {"error": "server_not_configured", "detail": "HAPP_HTTP_BEARER_TOKEN is required in production mode"}}

        authz = self.headers.get("Authorization", "").strip()
        scheme, _, value = authz.partition(" ")
        if scheme.lower() != "bearer" or value != token:
            return {"status": 401, "body": {"error": "unauthorized"}}
        return None

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/capabilities":
            self._send(200, {
                "happ": "0.3.4",
                "tools": ["aaif.happ.request"],
                "identitySchemes": ["entra_oidc"],
                "pohpLevels": ["AAIF-PoHP-1", "AAIF-PoHP-2", "AAIF-PoHP-3", "AAIF-PoHP-4"],
            })
            return
        self._send(404, {"error": "not_found"})

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/issue":
            if _production_mode() and not _env_flag("HAPP_ALLOW_DIRECT_HTTP_ISSUE"):
                self._send(403, {
                    "error": "direct_issue_disabled",
                    "detail": "Production mode disables direct HTTP issuance by default",
                })
                return
            auth_error = self._authorize_issue_request()
            if auth_error is not None:
                self._send(auth_error["status"], auth_error["body"])
                return
            try:
                req = self._read_json()
            except ValueError as exc:
                self._send(400, {"error": "invalid_request", "detail": str(exc)})
                return
            action_intent = req.get("actionIntent") or (req.get("challenge") or {}).get("actionIntent")
            if not isinstance(action_intent, dict):
                self._send(400, {"error": "missing_actionIntent"})
                return

            audience = ((action_intent.get("audience") or {}).get("id")) or "did:web:rp.example"
            pohp_level = (req.get("requirements") or {}).get("pohp", {}).get("minLevel") or "AAIF-PoHP-3"
            identity_required = ((req.get("requirements") or {}).get("identity") or {}).get("mode") == "required"

            identity_obj = None
            identity = req.get("identityBinding")
            if _production_mode() and identity is not None and not _env_flag("HAPP_ALLOW_CALLER_IDENTITY_BINDING"):
                self._send(400, {
                    "error": "identity_binding_not_accepted",
                    "detail": "Production mode requires server-derived identity binding",
                })
                return
            if isinstance(identity, dict):
                identity_obj = IdentityBindingResult(
                    mode=identity.get("mode", "verified"),
                    scheme=identity.get("scheme", "entra_oidc"),
                    idp=identity.get("idp") or {},
                    subject=identity.get("subject") or {},
                    assurance=identity.get("assurance"),
                    evidence=identity.get("evidence"),
                )
            if identity_required and identity_obj is None:
                self._send(400, {"error": "identityBinding_required"})
                return

            try:
                ttl_seconds = int(req.get("ttlSeconds") or 120)
            except (TypeError, ValueError):
                self._send(400, {"error": "invalid_ttlSeconds"})
                return

            try:
                cred = issue_consent_credential(
                    issuer=os.environ.get("HAPP_ISSUER", "did:web:pp.example"),
                    action_intent=action_intent,
                    audience=audience,
                    pohp_level=pohp_level,
                    pohp_method=os.environ.get("HAPP_POHP_METHOD", "reference-http"),
                    identity=identity_obj,
                    ttl_seconds=ttl_seconds,
                    provider_cert_ref=os.environ.get("HAPP_PROVIDER_CERT_REF", "urn:aaif:happ:pcc:demo"),
                )
            except SigningConfigurationError as exc:
                self._send(503, {"error": "signing_not_configured", "detail": str(exc)})
                return
            except ValueError as exc:
                self._send(400, {"error": "invalid_request", "detail": str(exc)})
                return
            self._send(200, {"credential": cred})
            return

        self._send(404, {"error": "not_found"})


def run_http(port: int = 8766) -> None:
    server = ThreadingHTTPServer(("127.0.0.1", port), RefProviderHandler)
    print(f"[HAPP Ref Provider] listening on http://127.0.0.1:{port}")
    server.serve_forever()
