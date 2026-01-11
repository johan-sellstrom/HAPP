from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, Optional
from urllib.parse import urlparse

from happ.identity import IdentityBindingResult
from happ.provider.issuer import issue_consent_credential


class RefProviderHandler(BaseHTTPRequestHandler):
    server_version = "HAPPRefProvider/0.3.4"

    def _read_json(self) -> Dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0"))
        data = self.rfile.read(length)
        return json.loads(data.decode("utf-8") or "{}")

    def _send(self, status: int, obj: Any, content_type: str = "application/json") -> None:
        body = json.dumps(obj, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

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
            req = self._read_json()
            action_intent = req.get("actionIntent") or (req.get("challenge") or {}).get("actionIntent")
            if not isinstance(action_intent, dict):
                self._send(400, {"error": "missing_actionIntent"})
                return

            audience = ((action_intent.get("audience") or {}).get("id")) or req.get("aud") or "did:web:rp.example"
            pohp_level = (req.get("requirements") or {}).get("pohp", {}).get("minLevel") or "AAIF-PoHP-3"

            identity_obj = None
            identity = req.get("identityBinding")
            if isinstance(identity, dict):
                identity_obj = IdentityBindingResult(
                    mode=identity.get("mode", "verified"),
                    scheme=identity.get("scheme", "entra_oidc"),
                    idp=identity.get("idp") or {},
                    subject=identity.get("subject") or {},
                    assurance=identity.get("assurance"),
                    evidence=identity.get("evidence"),
                )

            cred = issue_consent_credential(
                issuer=req.get("issuer") or "did:web:pp.example",
                action_intent=action_intent,
                audience=audience,
                pohp_level=pohp_level,
                pohp_method=req.get("pohpMethod") or "demo",
                identity=identity_obj,
                ttl_seconds=int(req.get("ttlSeconds") or 120),
            )
            self._send(200, {"credential": cred})
            return

        self._send(404, {"error": "not_found"})


def run_http(port: int = 8766) -> None:
    server = ThreadingHTTPServer(("127.0.0.1", port), RefProviderHandler)
    print(f"[HAPP Ref Provider] listening on http://127.0.0.1:{port}")
    server.serve_forever()
