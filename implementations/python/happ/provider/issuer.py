from __future__ import annotations

import os
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

from happ.core.intent import compute_intent_hash, derive_signing_view, compute_presentation_hash
from happ.crypto.jws import jws_sign_hs256
from happ.identity import IdentityBindingResult
from happ.util import now_utc


DEFAULT_SECRET = os.environ.get("HAPP_DEMO_HS256_SECRET", "dev-secret").encode("utf-8")


def issue_consent_credential(
    *,
    issuer: str,
    action_intent: Dict[str, Any],
    audience: str,
    pohp_level: str,
    pohp_method: str,
    identity: Optional[IdentityBindingResult],
    ttl_seconds: int = 120,
    provider_cert_ref: str = "urn:aaif:happ:pcc:demo",
) -> Dict[str, Any]:
    """
    Issue a HAPP Consent Credential envelope.

    NOTE: The outer credential is HS256-signed for demo purposes.
    Production implementations should use asymmetric keys + DID/JWKS discovery.
    """
    intent_hash = compute_intent_hash(action_intent)
    signing_view = derive_signing_view(action_intent)
    presentation_hash = compute_presentation_hash(signing_view)

    now = now_utc()
    exp = now + timedelta(seconds=ttl_seconds)
    jti = str(uuid.uuid4())

    claims: Dict[str, Any] = {
        "issuer": issuer,
        "intent_hash": intent_hash,
        "presentation_hash": presentation_hash,
        "aud": audience,
        "jti": jti,
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
        "assurance": {
            "level": pohp_level,
            "verifiedAt": now.isoformat().replace("+00:00", "Z"),
            "method": pohp_method,
        },
        "providerCertification": {"ref": provider_cert_ref},
    }

    if identity is not None:
        claims["identityBinding"] = {
            "mode": identity.mode,
            "scheme": identity.scheme,
            "idp": identity.idp,
            "subject": identity.subject,
        }
        if identity.assurance is not None:
            claims["identityBinding"]["assurance"] = identity.assurance
        if identity.evidence is not None:
            claims["identityBinding"]["evidence"] = identity.evidence

    token = jws_sign_hs256(claims, DEFAULT_SECRET, header={"typ": "HAPP-CC"})
    return {
        "format": "jwt",
        "credential": token,
        "claims": claims,
    }
