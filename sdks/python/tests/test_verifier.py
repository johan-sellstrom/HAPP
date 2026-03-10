from __future__ import annotations

import unittest

from happ_sdk import compute_intent_hash, compute_presentation_hash, derive_signing_view, verify_claims
from happ_sdk.verifier import VerificationError


ACTION_INTENT = {
    "profile": "aaif.happ.profile.generic/v0.3",
    "audience": {"id": "did:web:rp.example", "name": "RP"},
    "agent": {"id": "agent:1", "name": "Agent"},
    "action": {"type": "consent"},
}


def make_claims(**overrides):
    signing_view = derive_signing_view(ACTION_INTENT)
    claims = {
        "aud": "did:web:rp.example",
        "exp": 4_102_444_800,
        "intent_hash": compute_intent_hash(ACTION_INTENT),
        "presentation_hash": compute_presentation_hash(signing_view),
        "assurance": {"level": "AAIF-PoHP-3"},
    }
    claims.update(overrides)
    return claims


class VerifyClaimsTests(unittest.TestCase):
    def test_verify_claims_accepts_valid_claims(self):
        claims = make_claims()
        out = verify_claims(
            claims,
            ACTION_INTENT,
            expected_aud="did:web:rp.example",
            min_pohp_level="AAIF-PoHP-2",
            now_epoch_seconds=1_700_000_000,
        )
        self.assertEqual(out["aud"], "did:web:rp.example")

    def test_verify_claims_rejects_expired_claims(self):
        claims = make_claims(exp=10)
        with self.assertRaises(VerificationError):
            verify_claims(
                claims,
                ACTION_INTENT,
                expected_aud="did:web:rp.example",
                now_epoch_seconds=100,
            )

    def test_verify_claims_rejects_invalid_policy_pohp_level(self):
        claims = make_claims()
        with self.assertRaisesRegex(VerificationError, "invalid PoHP level"):
            verify_claims(
                claims,
                ACTION_INTENT,
                expected_aud="did:web:rp.example",
                min_pohp_level="NOT-A-REAL-LEVEL",
            )


if __name__ == "__main__":
    unittest.main()
