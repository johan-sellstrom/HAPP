from __future__ import annotations

from happ.rp_verifier import verify_happ_cc

# RP-CORE-04 / RP-CORE-05: intent_hash + presentation_hash binding

def test_REQ_RP_CORE_04_05__hash_bindings_verify(happ_case, happ_secret):
    action_intent = happ_case["actionIntent"]
    cred = happ_case["credential"]
    claims = verify_happ_cc(
        happ_jws=cred["credential"],
        hs256_secret=happ_secret,
        action_intent=action_intent,
        expected_aud=action_intent["audience"]["id"],
        min_pohp_level="AAIF-PoHP-3",
        identity_required=True,
        allowed_identity_schemes=["entra_oidc"],
        require_embedded_identity_evidence=True,
        expected_entra_subject={"tid":"00000000-0000-0000-0000-000000000000","oid":"11111111-1111-1111-1111-111111111111"},
    )
    assert claims["intent_hash"].startswith("sha256:")
    assert claims["presentation_hash"].startswith("sha256:")
