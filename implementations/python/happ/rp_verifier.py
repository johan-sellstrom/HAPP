from __future__ import annotations

import time
from typing import Any, Dict, Optional

from happ.core.intent import compute_intent_hash, derive_signing_view, compute_presentation_hash
from happ.crypto.jws import jws_get_unverified_header, jws_verify_hs256, jws_verify_rs256
from happ.util import sha256_b64url


class VerificationError(Exception):
    pass


_POHP_ORDER = {"AAIF-PoHP-1": 1, "AAIF-PoHP-2": 2, "AAIF-PoHP-3": 3, "AAIF-PoHP-4": 4}
_VALID_IDENTITY_MODES = {"verified", "asserted"}


def _now() -> int:
    return int(time.time())


def _require_int(value: Any, *, field_name: str) -> int:
    try:
        return int(value)
    except (TypeError, ValueError) as exc:
        raise VerificationError(f"{field_name} missing or invalid") from exc


def _validate_temporal_claims(claims: Dict[str, Any], *, clock_skew_seconds: int) -> None:
    now = _now()
    exp = _require_int(claims.get("exp"), field_name="exp")
    iat = _require_int(claims.get("iat"), field_name="iat")
    nbf = _require_int(claims.get("nbf", iat), field_name="nbf")
    if exp <= iat:
        raise VerificationError("exp must be after iat")
    if iat > now + clock_skew_seconds:
        raise VerificationError("token issued in the future")
    if nbf > now + clock_skew_seconds:
        raise VerificationError("token not yet valid")
    if exp < now - clock_skew_seconds:
        raise VerificationError("expired")


def _verify_outer_signature(
    *,
    happ_jws: str,
    hs256_secret: Optional[bytes],
    issuer_jwks: Optional[Dict[str, Any]],
) -> tuple[Dict[str, Any], Dict[str, Any]]:
    header = jws_get_unverified_header(happ_jws)
    if header.get("typ") != "HAPP-CC":
        raise VerificationError("unexpected token typ")

    alg = header.get("alg")
    try:
        if alg == "HS256":
            if hs256_secret is None:
                raise VerificationError("HS256 verification secret required")
            return jws_verify_hs256(happ_jws, hs256_secret), header
        if alg == "RS256":
            if issuer_jwks is None:
                raise VerificationError("issuer_jwks required for RS256 verification")
            return jws_verify_rs256(happ_jws, issuer_jwks), header
    except ValueError as exc:
        raise VerificationError(str(exc)) from exc

    raise VerificationError(f"unsupported token alg: {alg}")


def _validate_identity_binding(ib: Dict[str, Any]) -> None:
    if ib.get("mode") not in _VALID_IDENTITY_MODES:
        raise VerificationError("identityBinding.mode invalid")
    if not isinstance(ib.get("scheme"), str) or not ib["scheme"]:
        raise VerificationError("identityBinding.scheme missing")
    if not isinstance(ib.get("idp"), dict) or not ib["idp"]:
        raise VerificationError("identityBinding.idp missing")
    if not isinstance(ib.get("subject"), dict) or not ib["subject"]:
        raise VerificationError("identityBinding.subject missing")


def _pohp_rank(level: Optional[str]) -> int:
    if level is None:
        return 0
    if level not in _POHP_ORDER:
        raise VerificationError(f"invalid PoHP level: {level}")
    return _POHP_ORDER[level]


def verify_happ_cc(
    *,
    happ_jws: str,
    action_intent: Dict[str, Any],
    expected_aud: str,
    hs256_secret: Optional[bytes] = None,
    issuer_jwks: Optional[Dict[str, Any]] = None,
    expected_issuer: Optional[str] = None,
    clock_skew_seconds: int = 30,
    min_pohp_level: Optional[str] = None,
    identity_required: bool = False,
    allowed_identity_schemes: Optional[list[str]] = None,
    require_embedded_identity_evidence: bool = False,
    expected_entra_subject: Optional[Dict[str, str]] = None,
    expected_entra_audience: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Verify a HAPP Consent Credential.

    This reference verifier validates the outer signature, token timing, the action
    intent hash bindings, and optional embedded Entra evidence.
    """
    claims, _ = _verify_outer_signature(
        happ_jws=happ_jws,
        hs256_secret=hs256_secret,
        issuer_jwks=issuer_jwks,
    )

    issuer = claims.get("iss") or claims.get("issuer")
    if not isinstance(issuer, str) or not issuer:
        raise VerificationError("issuer missing")
    if claims.get("iss") and claims.get("issuer") and claims["iss"] != claims["issuer"]:
        raise VerificationError("issuer claim mismatch")
    if expected_issuer is not None and issuer != expected_issuer:
        raise VerificationError("issuer mismatch")

    if claims.get("aud") != expected_aud:
        raise VerificationError("aud mismatch")

    if not isinstance(claims.get("jti"), str) or not claims["jti"]:
        raise VerificationError("jti missing")

    _validate_temporal_claims(claims, clock_skew_seconds=clock_skew_seconds)

    expected_intent_hash = compute_intent_hash(action_intent)
    if claims.get("intent_hash") != expected_intent_hash:
        raise VerificationError("intent_hash mismatch")

    signing_view = derive_signing_view(action_intent)
    expected_presentation_hash = compute_presentation_hash(signing_view)
    if claims.get("presentation_hash") != expected_presentation_hash:
        raise VerificationError("presentation_hash mismatch")

    if min_pohp_level:
        got = (claims.get("assurance") or {}).get("level")
        if _pohp_rank(got) < _pohp_rank(min_pohp_level):
            raise VerificationError("PoHP level too low")

    ib = claims.get("identityBinding")
    if identity_required and not ib:
        raise VerificationError("identityBinding required")

    if ib:
        if not isinstance(ib, dict):
            raise VerificationError("identityBinding invalid")
        _validate_identity_binding(ib)

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
                try:
                    payload = jws_verify_rs256(id_token, jwks, expected_aud=expected_entra_audience)
                except ValueError as exc:
                    raise VerificationError(str(exc)) from exc
                _validate_temporal_claims(payload, clock_skew_seconds=clock_skew_seconds)
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
                idp = ib.get("idp") or {}
                subj = ib.get("subject") or {}
                if idp.get("issuer") and payload.get("iss") != idp.get("issuer"):
                    raise VerificationError("Entra issuer mismatch")
                if idp.get("tenantId") and payload.get("tid") != idp.get("tenantId"):
                    raise VerificationError("Entra tenant mismatch")
                if subj.get("tid") and payload.get("tid") != subj.get("tid"):
                    raise VerificationError("Entra tid mismatch")
                if subj.get("oid") and payload.get("oid") != subj.get("oid"):
                    raise VerificationError("Entra oid mismatch")
            else:
                raise VerificationError("embedded evidence verification not implemented for scheme")

    return claims
