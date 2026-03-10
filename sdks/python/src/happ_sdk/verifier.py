from __future__ import annotations

import time
from typing import Any, Dict, Optional

from .hash import compute_intent_hash, compute_presentation_hash, derive_signing_view


class VerificationError(Exception):
    pass


_POHP_ORDER = {
    "AAIF-PoHP-1": 1,
    "AAIF-PoHP-2": 2,
    "AAIF-PoHP-3": 3,
    "AAIF-PoHP-4": 4,
}


def _pohp_rank(level: Optional[str]) -> int:
    if level is None:
        return 0
    if level not in _POHP_ORDER:
        raise VerificationError(f"invalid PoHP level: {level}")
    return _POHP_ORDER[level]


def verify_claims(
    claims: Dict[str, Any],
    action_intent: Dict[str, Any],
    *,
    expected_aud: str,
    now_epoch_seconds: Optional[int] = None,
    min_pohp_level: Optional[str] = None,
    identity_required: bool = False,
    allowed_identity_schemes: Optional[list[str]] = None,
    expected_challenge_id: Optional[str] = None,
) -> Dict[str, Any]:
    now = now_epoch_seconds if now_epoch_seconds is not None else int(time.time())

    if claims.get("aud") != expected_aud:
        raise VerificationError("aud mismatch")

    exp = claims.get("exp")
    if not isinstance(exp, int) or exp < now:
        raise VerificationError("expired")

    expected_intent_hash = compute_intent_hash(action_intent)
    if claims.get("intent_hash") != expected_intent_hash:
        raise VerificationError("intent_hash mismatch")

    signing_view = derive_signing_view(action_intent)
    expected_presentation_hash = compute_presentation_hash(signing_view)
    if claims.get("presentation_hash") != expected_presentation_hash:
        raise VerificationError("presentation_hash mismatch")

    if min_pohp_level:
        got = ((claims.get("assurance") or {}).get("level"))
        if _pohp_rank(got) < _pohp_rank(min_pohp_level):
            raise VerificationError("PoHP level too low")

    identity_binding = claims.get("identityBinding")
    if identity_required and not identity_binding:
        raise VerificationError("identityBinding required")

    if identity_binding and allowed_identity_schemes:
        scheme = identity_binding.get("scheme")
        if scheme and scheme not in allowed_identity_schemes:
            raise VerificationError("identity scheme not allowed")

    if expected_challenge_id and claims.get("challengeId") != expected_challenge_id:
        raise VerificationError("challengeId mismatch")

    return claims
