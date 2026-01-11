from __future__ import annotations

# ENTRA-RP-02: if embedded evidence required, it must be present and verifiable (basic)

def test_REQ_ENTRA_RP_02__embedded_evidence_present(happ_case):
    cred = happ_case["credential"]
    claims = cred.get("claims") or {}
    ib = claims.get("identityBinding") or {}
    ev = ib.get("evidence") or {}
    assert ev.get("embedded") is True
    assert "id_token" in ev
    assert "jwks" in ev
