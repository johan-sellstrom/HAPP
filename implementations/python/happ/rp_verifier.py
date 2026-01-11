from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

from happ.core.intent import compute_intent_hash, derive_signing_view, compute_presentation_hash
from happ.crypto.jws import jws_verify_hs256, jws_verify_rs256
from happ.util import sha256_b64url, b64url_decode


class VerificationError(Exception):
    pass


def _now() -> int:
    return int(time.time())


def verify_happ_cc(
    *,
    happ_jws: str,
    hs256_secret: bytes,
    action_intent: Dict[str, Any],
    expected_aud: str,
    min_pohp_level: Optional[str] = None,
    identity_required: bool = False,
    allowed_identity_schemes: Optional[list[str]] = None,
    require_embedded_identity_evidence: bool = False,
    expected_entra_subject: Optional[Dict[str, str]] = None,  # {tid, oid}
) -> Dict[str, Any]:
    """
    Verify a HAPP Consent Credential (demo verifier).

    NOTE: Production RPs should verify provider trust, certification evidence, revocation, etc.
    """
    claims = jws_verify_hs256(happ_jws, hs256_secret)

    if claims.get("aud") != expected_aud:
        raise VerificationError("aud mismatch")

    now = _now()
    if int(claims.get("exp", 0)) < now:
        raise VerificationError("expired")

    # intent hash binding
    expected_intent_hash = compute_intent_hash(action_intent)
    if claims.get("intent_hash") != expected_intent_hash:
        raise VerificationError("intent_hash mismatch")

    # presentation hash binding
    signing_view = derive_signing_view(action_intent)
    expected_presentation_hash = compute_presentation_hash(signing_view)
    if claims.get("presentation_hash") != expected_presentation_hash:
        raise VerificationError("presentation_hash mismatch")

    # PoHP policy (simple lexical mapping)
    if min_pohp_level:
        order = {"AAIF-PoHP-1": 1, "AAIF-PoHP-2": 2, "AAIF-PoHP-3": 3, "AAIF-PoHP-4": 4}
        got = (claims.get("assurance") or {}).get("level")
        if order.get(got, 0) < order.get(min_pohp_level, 0):
            raise VerificationError("PoHP level too low")

    ib = claims.get("identityBinding")
    if identity_required and not ib:
        raise VerificationError("identityBinding required")

    if ib:
        scheme = ib.get("scheme")
        if allowed_identity_schemes and scheme not in allowed_identity_schemes:
            raise VerificationError("identity scheme not allowed")

        if expected_entra_subject:
            subj = ib.get("subject") or {}
            if subj.get("tid") != expected_entra_subject.get("tid") or subj.get("oid") != expected_entra_subject.get("oid"):
                raise VerificationError("Entra subject mismatch")

        if require_embedded_identity_evidence:
            ev = ib.get("evidence") or {}
            if not ev.get("embedded"):
                raise VerificationError("embedded identity evidence required")
            if scheme == "entra_oidc":
                id_token = ev.get("id_token")
                jwks = ev.get("jwks")
                if not id_token or not jwks:
                    raise VerificationError("missing id_token or jwks")
                payload = jws_verify_rs256(id_token, jwks)
                # basic nonce binding if hashes provided
                nonce_hash = ev.get("nonceHash")
                if nonce_hash and payload.get("nonce"):
                    expected = "sha256:" + sha256_b64url(payload["nonce"].encode("utf-8"))
                    if nonce_hash != expected:
                        raise VerificationError("nonceHash mismatch")
                token_hash = ev.get("tokenHash")
                if token_hash:
                    expected = "sha256:" + sha256_b64url(id_token.encode("utf-8"))
                    if token_hash != expected:
                        raise VerificationError("tokenHash mismatch")
            else:
                raise VerificationError("embedded evidence verification not implemented for scheme")

    return claims
