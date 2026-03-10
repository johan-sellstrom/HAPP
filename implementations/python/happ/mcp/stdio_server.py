from __future__ import annotations

import json
import os
import sys
import threading
import uuid
from typing import Any, Dict, Optional

from happ.identity import IdentityBindingResult
from happ.provider.issuer import SigningConfigurationError, issue_consent_credential
from happ.session_store import STORE
from happ.web.consent_ui import run_ui


URL_ELICITATION_REQUIRED = -32042


def _runtime_mode() -> str:
    mode = os.environ.get("HAPP_RUNTIME_MODE", "development").strip().lower()
    return mode or "development"


def _production_mode() -> bool:
    return _runtime_mode() == "production"


def _validate_runtime_config() -> None:
    if not _production_mode():
        return

    alg = os.environ.get("HAPP_SIGNING_ALG", "").strip().upper()
    if alg != "RS256":
        raise RuntimeError("production mode requires HAPP_SIGNING_ALG=RS256")
    if not (os.environ.get("HAPP_RS256_PRIVATE_KEY_PEM", "").strip() or os.environ.get("HAPP_RS256_PRIVATE_KEY_FILE", "").strip()):
        raise RuntimeError("production mode requires RS256 signing key configuration")

    provider_cert_ref = os.environ.get("HAPP_PROVIDER_CERT_REF", "").strip()
    if not provider_cert_ref or ":demo" in provider_cert_ref or "placeholder" in provider_cert_ref:
        raise RuntimeError("production mode requires a real HAPP_PROVIDER_CERT_REF")

    if not os.environ.get("HAPP_POHP_ATTESTATION_SECRET", "").strip():
        raise RuntimeError("production mode requires HAPP_POHP_ATTESTATION_SECRET")

    if os.environ.get("HAPP_ENTRA_MODE", "").strip().lower() != "real":
        raise RuntimeError("production mode requires HAPP_ENTRA_MODE=real")
    if not os.environ.get("HAPP_ENTRA_CLIENT_ID", "").strip():
        raise RuntimeError("production mode requires HAPP_ENTRA_CLIENT_ID")


def _jsonrpc_result(id_: Any, result: Any) -> Dict[str, Any]:
    return {"jsonrpc": "2.0", "id": id_, "result": result}


def _jsonrpc_error(id_: Any, code: int, message: str, data: Optional[Any] = None) -> Dict[str, Any]:
    err: Dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        err["data"] = data
    return {"jsonrpc": "2.0", "id": id_, "error": err}


class HappMcpServer:
    def __init__(self, ui_port: int = 8787) -> None:
        _validate_runtime_config()
        self._req_to_elicitation: Dict[str, str] = {}
        self._ui_server = run_ui(port=ui_port)
        self.ui_port = self._ui_server.server_port
        self._ui_thread = threading.Thread(target=self._ui_server.serve_forever, daemon=True)

    def start(self) -> None:
        self._ui_thread.start()
        print(f"[HAPP MCP] Consent UI: http://127.0.0.1:{self.ui_port}", file=sys.stderr)

    def handle(self, msg: Dict[str, Any]) -> Dict[str, Any]:
        method = msg.get("method")
        id_ = msg.get("id")

        if method == "initialize":
            return _jsonrpc_result(id_, {
                "serverInfo": {"name": "happ-demo-pp", "version": "0.3.4"},
                "capabilities": {"tools": {}},
            })

        if method == "tools/list":
            return _jsonrpc_result(id_, {
                "tools": [
                    {
                        "name": "aaif.happ.request",
                        "description": "Request a HAPP consent credential for an Action Intent or RP Challenge.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "requestId": {"type": "string"},
                                "actionIntent": {"type": "object"},
                                "challenge": {"type": "object"},
                                "requirements": {"type": "object"},
                                "return": {"type": "object"},
                            }
                        },
                    }
                ]
            })

        if method == "tools/call":
            params = msg.get("params") or {}
            name = params.get("name")
            args = params.get("arguments") or {}
            if name != "aaif.happ.request":
                return _jsonrpc_error(id_, -32601, "Unknown tool")

            return self._handle_happ_request(id_, args)

        return _jsonrpc_error(id_, -32601, f"Unknown method: {method}")

    def _handle_happ_request(self, id_: Any, args: Dict[str, Any]) -> Dict[str, Any]:
        request_id = args.get("requestId") or str(uuid.uuid4())

        challenge = args.get("challenge")
        action_intent = args.get("actionIntent")
        requirements = args.get("requirements") or {}

        if isinstance(challenge, dict):
            action_intent = challenge.get("actionIntent")
            requirements = (challenge.get("requirements") or {}) | requirements

        if not isinstance(action_intent, dict):
            return _jsonrpc_error(id_, -32602, "Missing actionIntent (or challenge.actionIntent)")

        # Determine audience
        audience = ((action_intent.get("audience") or {}).get("id")) or "did:web:rp.example"

        # Find or create session
        elicitation_id = self._req_to_elicitation.get(request_id)
        sess = STORE.get(elicitation_id) if elicitation_id else None

        if sess is None:
            elicitation_id = str(uuid.uuid4())
            self._req_to_elicitation[request_id] = elicitation_id
            # Seed nonce early for Entra flows (mock or real)
            requirements_norm = requirements if isinstance(requirements, dict) else {}
            STORE.create(elicitation_id, action_intent=action_intent, requirements=requirements_norm)
            # For Entra binding, store a nonce so mock tokens can be minted before approval
            STORE.update(elicitation_id, nonce=str(uuid.uuid4()))
            url = f"http://127.0.0.1:{self.ui_port}/session/{elicitation_id}"
            return _jsonrpc_error(
                id_,
                URL_ELICITATION_REQUIRED,
                "User interaction required.",
                data={
                    "elicitations": [
                        {
                            "mode": "url",
                            "elicitationId": elicitation_id,
                            "url": url,
                            "message": "Verify presence and approve the action.",
                        }
                    ]
                },
            )

        if sess.denied:
            return _jsonrpc_error(id_, -32001, "User denied the request.")

        if not sess.approved:
            url = f"http://127.0.0.1:{self.ui_port}/session/{sess.elicitation_id}"
            return _jsonrpc_error(
                id_,
                URL_ELICITATION_REQUIRED,
                "User interaction required.",
                data={
                    "elicitations": [
                        {
                            "mode": "url",
                            "elicitationId": sess.elicitation_id,
                            "url": url,
                            "message": "Complete approval in the provider UI.",
                        }
                    ]
                },
            )

        if isinstance(sess.issued_credential, dict):
            cred = sess.issued_credential
            return _jsonrpc_result(
                id_,
                {
                    "content": [{"type": "text", "text": "Consent credential already issued."}],
                    "structuredContent": cred,
                    "isError": False,
                },
            )

        # Build identity binding if present
        identity_obj: Optional[IdentityBindingResult] = None
        if isinstance(sess.identity_binding, dict):
            ib = sess.identity_binding
            identity_obj = IdentityBindingResult(
                mode=ib.get("mode", "verified"),
                scheme=ib.get("scheme", ""),
                idp=ib.get("idp") or {},
                subject=ib.get("subject") or {},
                assurance=ib.get("assurance"),
                evidence=ib.get("evidence"),
            )

        identity_required = ((sess.requirements.get("identity") or {}).get("mode") == "required") if isinstance(sess.requirements, dict) else False
        if identity_required and identity_obj is None:
            return _jsonrpc_error(id_, -32602, "identityBinding is required before issuing a credential")

        if not sess.pohp_verified_at or not sess.pohp_level or not sess.pohp_method:
            return _jsonrpc_error(id_, -32602, "presence verification is required before issuing a credential")

        try:
            cred = issue_consent_credential(
                issuer=os.environ.get("HAPP_ISSUER", "did:web:pp.local"),
                action_intent=sess.action_intent,
                audience=audience,
                pohp_level=sess.pohp_level,
                pohp_method=sess.pohp_method,
                identity=identity_obj,
                ttl_seconds=int((sess.requirements.get("pohp") or {}).get("maxCredentialAgeSeconds") or 120),
                provider_cert_ref=os.environ.get("HAPP_PROVIDER_CERT_REF", "urn:aaif:happ:pcc:demo"),
            )
        except SigningConfigurationError as exc:
            return _jsonrpc_error(id_, -32050, f"Credential signing is not configured: {exc}")
        except ValueError as exc:
            return _jsonrpc_error(id_, -32602, str(exc))

        STORE.store_issued_credential(sess.elicitation_id, cred)

        return _jsonrpc_result(
            id_,
            {
                "content": [{"type": "text", "text": "Consent credential issued."}],
                "structuredContent": cred,
                "isError": False,
            },
        )


def run_stdio(ui_port: int = 8787) -> None:
    server = HappMcpServer(ui_port=ui_port)
    server.start()

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
            resp = server.handle(msg)
        except Exception as e:
            resp = {"jsonrpc": "2.0", "id": None, "error": {"code": -32099, "message": f"Server error: {e}"}}
        sys.stdout.write(json.dumps(resp) + "\n")
        sys.stdout.flush()
