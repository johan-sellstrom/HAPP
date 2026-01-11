from __future__ import annotations

# PP-IDB-02 (MUST): If identity.mode=required, provider MUST NOT issue credential without identityBinding.

def test_REQ_PP_IDB_02__identity_required_has_identityBinding(happ_case):
    cred = happ_case["credential"]
    claims = cred.get("claims") or {}
    assert "identityBinding" in claims, "identityBinding missing when identity is required"
