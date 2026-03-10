from __future__ import annotations

import json
import threading
import uuid
from pathlib import Path

import pytest
import requests
from http.server import ThreadingHTTPServer

from happ.adapters.entra_mock import default_mock_issuer
from happ.adapters.entra_oidc_pkce import verify_id_token
from happ.crypto.jws import generate_rsa_keypair
from happ.core.intent import compute_intent_hash, compute_presentation_hash, derive_signing_view
from happ.mcp.stdio_server import HappMcpServer, URL_ELICITATION_REQUIRED
from happ.provider.http_server import RefProviderHandler
from happ.provider.issuer import (
    SigningConfigurationError,
    issue_consent_credential,
    rs256_signing_config,
)
from happ.rp_verifier import verify_happ_cc
from happ.session_store import STORE, SessionStore

def test_issue_requires_explicit_signing_config_when_env_missing(monkeypatch, happ_case):
    monkeypatch.delenv("HAPP_HS256_SECRET", raising=False)
    monkeypatch.delenv("HAPP_DEMO_HS256_SECRET", raising=False)
    monkeypatch.delenv("HAPP_SIGNING_ALG", raising=False)
    action_intent = happ_case["actionIntent"]

    with pytest.raises(SigningConfigurationError):
        issue_consent_credential(
            issuer="did:web:pp.example",
            action_intent=action_intent,
            audience=action_intent["audience"]["id"],
            pohp_level="AAIF-PoHP-3",
            pohp_method="demo",
            identity=None,
            ttl_seconds=120,
        )


def test_verify_happ_cc_accepts_rs256_credentials(happ_case):
    action_intent = happ_case["actionIntent"]
    signing_key = generate_rsa_keypair(kid="rp-test")
    cred = issue_consent_credential(
        issuer="did:web:pp.example",
        action_intent=action_intent,
        audience=action_intent["audience"]["id"],
        pohp_level="AAIF-PoHP-3",
        pohp_method="demo",
        identity=None,
        ttl_seconds=120,
        signing_config=rs256_signing_config(signing_key),
    )

    claims = verify_happ_cc(
        happ_jws=cred["credential"],
        action_intent=action_intent,
        expected_aud=action_intent["audience"]["id"],
        issuer_jwks=cred["verification"]["jwks"],
        expected_issuer="did:web:pp.example",
    )
    assert claims["iss"] == "did:web:pp.example"


def test_session_store_consumes_oidc_state_once(happ_case):
    action_intent = happ_case["actionIntent"]
    store = SessionStore()
    sess = store.create("elic-1", action_intent=action_intent, requirements={})
    assert sess.state is None

    store.begin_oidc_flow("elic-1", state="state-1", nonce="nonce-1", code_verifier="verifier-1")
    first = store.consume_oidc_state("state-1")
    second = store.consume_oidc_state("state-1")

    assert first is not None
    assert first.elicitation_id == "elic-1"
    assert first.state is None
    assert first.code_verifier == "verifier-1"
    assert second is None


@pytest.fixture
def ref_provider_server(monkeypatch):
    monkeypatch.setenv("HAPP_SIGNING_ALG", "HS256")
    monkeypatch.setenv("HAPP_HS256_SECRET", "0123456789abcdef0123456789abcdef")
    server = ThreadingHTTPServer(("127.0.0.1", 0), RefProviderHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


def test_http_issue_is_disabled_by_default_in_production(monkeypatch, ref_provider_server, happ_case):
    monkeypatch.setenv("HAPP_RUNTIME_MODE", "production")
    monkeypatch.setenv("HAPP_HTTP_BEARER_TOKEN", "prod-token")

    response = requests.post(
        f"{ref_provider_server}/issue",
        json={"actionIntent": happ_case["actionIntent"]},
        timeout=5,
    )

    assert response.status_code == 403
    assert response.json()["error"] == "direct_issue_disabled"


def test_http_issue_requires_bearer_token_in_production_when_enabled(monkeypatch, ref_provider_server, happ_case):
    monkeypatch.setenv("HAPP_RUNTIME_MODE", "production")
    monkeypatch.setenv("HAPP_HTTP_BEARER_TOKEN", "prod-token")
    monkeypatch.setenv("HAPP_ALLOW_DIRECT_HTTP_ISSUE", "1")

    response = requests.post(
        f"{ref_provider_server}/issue",
        json={"actionIntent": happ_case["actionIntent"]},
        timeout=5,
    )

    assert response.status_code == 401
    assert response.json()["error"] == "unauthorized"


def test_http_issue_rejects_caller_identity_binding_in_production(monkeypatch, ref_provider_server, happ_case):
    monkeypatch.setenv("HAPP_RUNTIME_MODE", "production")
    monkeypatch.setenv("HAPP_HTTP_BEARER_TOKEN", "prod-token")
    monkeypatch.setenv("HAPP_ALLOW_DIRECT_HTTP_ISSUE", "1")

    response = requests.post(
        f"{ref_provider_server}/issue",
        headers={"Authorization": "Bearer prod-token"},
        json={
            "actionIntent": happ_case["actionIntent"],
            "identityBinding": {
                "mode": "verified",
                "scheme": "entra_oidc",
                "idp": {"issuer": "https://login.microsoftonline.com/mock/v2.0"},
                "subject": {"type": "entra_oid_tid", "tid": "t", "oid": "o"},
            },
        },
        timeout=5,
    )

    assert response.status_code == 400
    assert response.json()["error"] == "identity_binding_not_accepted"


def test_python_impl_hashes_match_reference_vectors():
    vectors_dir = Path(__file__).resolve().parents[2] / "test_vectors" / "v0.3"
    action_intent = json.loads((vectors_dir / "action-intent.payment.transfer.sample.json").read_text(encoding="utf-8"))
    expected_signing_view = json.loads((vectors_dir / "signing-view.payment.transfer.sample.json").read_text(encoding="utf-8"))
    expected_intent_hash = (vectors_dir / "expected_intent_hash.txt").read_text(encoding="utf-8").strip()
    expected_presentation_hash = (vectors_dir / "expected_presentation_hash.txt").read_text(encoding="utf-8").strip()

    signing_view = derive_signing_view(action_intent)

    assert signing_view == expected_signing_view
    assert compute_intent_hash(action_intent) == expected_intent_hash
    assert compute_presentation_hash(signing_view) == expected_presentation_hash


def test_verify_id_token_accepts_signed_mock_token():
    issuer = default_mock_issuer("mock-client")
    token = issuer.issue_id_token(
        tenant_id="00000000-0000-0000-0000-000000000000",
        oid="11111111-1111-1111-1111-111111111111",
        nonce="nonce-123",
        amr=["pwd", "mfa"],
        acrs=["c1"],
    )

    payload = verify_id_token(
        id_token=token,
        jwks=issuer.jwks(),
        expected_issuer=issuer.issuer,
        expected_audience="mock-client",
        expected_nonce="nonce-123",
    )

    assert payload["tid"] == "00000000-0000-0000-0000-000000000000"
    assert payload["oid"] == "11111111-1111-1111-1111-111111111111"


def test_mcp_issuance_is_idempotent(monkeypatch):
    monkeypatch.setenv("HAPP_SIGNING_ALG", "HS256")
    monkeypatch.setenv("HAPP_HS256_SECRET", "0123456789abcdef0123456789abcdef")
    monkeypatch.delenv("HAPP_RUNTIME_MODE", raising=False)
    server = HappMcpServer(ui_port=0)

    request_id = str(uuid.uuid4())
    msg = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "aaif.happ.request",
            "arguments": {
                "requestId": request_id,
                "actionIntent": {
                    "intentId": str(uuid.uuid4()),
                    "audience": {"id": "did:web:bank.example"},
                    "action": {"type": "payment.transfer", "parameters": {"amount": {"currency": "GBP", "value": "1.00"}}},
                },
                "requirements": {"pohp": {"minLevel": "AAIF-PoHP-3", "maxCredentialAgeSeconds": 120}},
            },
        },
    }
    first = server.handle(msg)
    assert first["error"]["code"] == URL_ELICITATION_REQUIRED
    elicitation_id = first["error"]["data"]["elicitations"][0]["elicitationId"]

    STORE.mark_pohp_verified(elicitation_id, level="AAIF-PoHP-3", method="test")
    STORE.update(elicitation_id, approved=True, denied=False)

    second = server.handle(msg)
    third = server.handle(msg)

    second_cred = second["result"]["structuredContent"]["credential"]
    third_cred = third["result"]["structuredContent"]["credential"]
    assert second_cred == third_cred
