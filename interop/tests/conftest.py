from __future__ import annotations

import sys
from pathlib import Path
sys.path.insert(0, str((Path(__file__).resolve().parents[2] / 'implementations' / 'python')))


import json
import os
from pathlib import Path
from typing import Any, Dict, Tuple

import pytest

from happ.adapters.entra_mock import default_mock_issuer
from happ.provider.issuer import issue_consent_credential, DEFAULT_SECRET
from happ.identity import IdentityBindingResult
from happ.util import sha256_b64url, now_utc


SAMPLE_ACTION_INTENT = {
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


def _generate_reference_case() -> Dict[str, Any]:
    tenant_id = "00000000-0000-0000-0000-000000000000"
    oid = "11111111-1111-1111-1111-111111111111"
    client_id = "mock-client"
    nonce = "nonce-123"

    issuer = default_mock_issuer(client_id)
    id_token = issuer.issue_id_token(tenant_id=tenant_id, oid=oid, nonce=nonce, amr=["pwd","mfa"], acrs=["c1"])
    jwks = issuer.jwks()

    identity = IdentityBindingResult(
        mode="verified",
        scheme="entra_oidc",
        idp={"issuer": issuer.issuer, "tenantId": tenant_id},
        subject={"type": "entra_oid_tid", "tid": tenant_id, "oid": oid},
        assurance={"authTime": int(now_utc().timestamp()), "amr": ["pwd","mfa"], "acrs": ["c1"]},
        evidence={
            "kind": "oidc_id_token",
            "embedded": True,
            "id_token": id_token,
            "jwks": jwks,
            "tokenHash": "sha256:" + sha256_b64url(id_token.encode("utf-8")),
            "nonceHash": "sha256:" + sha256_b64url(nonce.encode("utf-8")),
        },
    )

    cred = issue_consent_credential(
        issuer="did:web:pp.example",
        action_intent=SAMPLE_ACTION_INTENT,
        audience=SAMPLE_ACTION_INTENT["audience"]["id"],
        pohp_level="AAIF-PoHP-3",
        pohp_method="demo",
        identity=identity,
        ttl_seconds=120,
    )
    return {"actionIntent": SAMPLE_ACTION_INTENT, "credential": cred}


@pytest.fixture(scope="session")
def happ_case() -> Dict[str, Any]:
    sut_file = os.environ.get("HAPP_SUT_FILE", "")
    if sut_file:
        data = json.loads(Path(sut_file).read_text(encoding="utf-8"))
        return data
    return _generate_reference_case()


@pytest.fixture(scope="session")
def happ_secret() -> bytes:
    return DEFAULT_SECRET
