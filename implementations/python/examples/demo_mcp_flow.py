#!/usr/bin/env python3
from __future__ import annotations

import os, sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import argparse
import json
import sys
import time
import uuid

from happ.mcp.stdio_server import HappMcpServer, URL_ELICITATION_REQUIRED
from happ.session_store import STORE


SAMPLE_INTENT = {
  "version": "0.3",
  "intentId": "550e8400-e29b-41d4-a716-446655440000",
  "issuedAt": "2026-01-09T12:00:00Z",
  "profile": "aaif.happ.profile.payment.transfer/v0.3",
  "audience": {"id": "did:web:bank.example", "name": "Example Bank"},
  "agent": {"id": "did:web:agent.example", "name": "Finance Agent", "software": {"name": "ExampleAgent", "version": "1.0.0"}},
  "action": {"type": "payment.transfer", "parameters": {"amount": {"currency": "GBP", "value": "250.00"}, "to": {"iban": "GB00TEST"}, "reference": "Invoice 18372"}},
  "constraints": {"expiresAt": "2026-01-09T12:02:00Z", "oneTime": True},
  "display": {"language": "en", "title": "Approve payment", "summary": "Approve a £250 transfer to GB00TEST (Invoice 18372).", "riskNotice": "Money will move immediately."}
}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--ui-port", type=int, default=8787)
    ap.add_argument("--auto-approve", action="store_true")
    ap.add_argument("--require-identity", action="store_true")
    args = ap.parse_args()

    server = HappMcpServer(ui_port=args.ui_port)
    server.start()

    req_id = str(uuid.uuid4())
    requirements = {"pohp": {"minLevel": "AAIF-PoHP-3", "maxCredentialAgeSeconds": 120}}
    if args.require_identity:
        requirements["identity"] = {"mode": "required", "schemes": ["entra_oidc"], "policy": {"requireEmbeddedEvidence": True}}

    msg1 = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "aaif.happ.request", "arguments": {"requestId": req_id, "actionIntent": SAMPLE_INTENT, "requirements": requirements}}}
    resp1 = server.handle(msg1)

    if "error" in resp1 and resp1["error"]["code"] == URL_ELICITATION_REQUIRED:
        el = resp1["error"]["data"]["elicitations"][0]
        url = el["url"]
        eid = el["elicitationId"]
        print("\nURL elicitation required. Open this in your browser and approve:\n")
        print(url)
        print()

        if args.auto_approve:
            # auto approve (and auto mock identity if required)
            sess = STORE.get(eid)
            if sess and args.require_identity:
                # simulate clicking mock identity + approve
                from happ.adapters.entra_mock import default_mock_issuer
                from happ.util import sha256_b64url, now_utc
                tenant_id = "00000000-0000-0000-0000-000000000000"
                oid = "11111111-1111-1111-1111-111111111111"
                client_id = "mock-client"
                issuer = default_mock_issuer(client_id)
                nonce = sess.nonce or "nonce"
                id_token = issuer.issue_id_token(tenant_id=tenant_id, oid=oid, nonce=nonce, amr=["pwd","mfa"], acrs=["c1"])
                jwks = issuer.jwks()
                sess.identity_binding = {
                    "mode":"verified",
                    "scheme":"entra_oidc",
                    "idp":{"issuer":issuer.issuer,"tenantId":tenant_id},
                    "subject":{"type":"entra_oid_tid","tid":tenant_id,"oid":oid},
                    "assurance":{"authTime":int(now_utc().timestamp()),"amr":["pwd","mfa"],"acrs":["c1"]},
                    "evidence":{"kind":"oidc_id_token","embedded":True,"id_token":id_token,"jwks":jwks,
                               "tokenHash":"sha256:"+sha256_b64url(id_token.encode("utf-8")),
                               "nonceHash":"sha256:"+sha256_b64url(nonce.encode("utf-8"))}
                }
            STORE.update(eid, approved=True, denied=False)
        else:
            input("Press Enter after approval...")

        msg2 = {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "aaif.happ.request", "arguments": {"requestId": req_id, "actionIntent": SAMPLE_INTENT, "requirements": requirements}}}
        resp2 = server.handle(msg2)
        print("\nSecond call response:\n")
        print(json.dumps(resp2, indent=2))
        return

    print(json.dumps(resp1, indent=2))


if __name__ == "__main__":
    main()
