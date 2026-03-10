from __future__ import annotations

import os
import uuid
from dataclasses import dataclass
from pathlib import Path
from datetime import timedelta
from typing import Any, Dict, Optional

from happ.core.intent import compute_intent_hash, derive_signing_view, compute_presentation_hash
from happ.crypto.jws import RsaKeyPair, jws_sign_hs256, jws_sign_rs256, load_rsa_keypair, rsa_public_jwk
from happ.identity import IdentityBindingResult
from happ.util import now_utc


MIN_HS256_SECRET_BYTES = 32
MAX_CREDENTIAL_TTL_SECONDS = 3600
DEFAULT_RS256_KID = "happ-ref-provider"
_VALID_POHP_LEVELS = {"AAIF-PoHP-1", "AAIF-PoHP-2", "AAIF-PoHP-3", "AAIF-PoHP-4"}
_VALID_IDENTITY_MODES = {"verified", "asserted"}


class SigningConfigurationError(ValueError):
    pass


@dataclass(frozen=True)
class IssuerSigningConfig:
    alg: str
    hs256_secret: Optional[bytes] = None
    rsa_keypair: Optional[RsaKeyPair] = None

    def public_jwks(self) -> Optional[Dict[str, Any]]:
        if self.alg != "RS256" or self.rsa_keypair is None:
            return None
        return {"keys": [rsa_public_jwk(self.rsa_keypair.public_key, self.rsa_keypair.kid)]}


def _env_flag(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in {"1", "true", "yes", "on"}


def _non_empty_str(value: Any, *, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field_name} must be a non-empty string")
    return value


def _validate_hs256_secret(secret: bytes) -> bytes:
    if not secret:
        raise SigningConfigurationError("HS256 signing secret is empty")
    if secret == b"dev-secret" and not _env_flag("HAPP_ALLOW_INSECURE_DEV_SECRET"):
        raise SigningConfigurationError("Refusing insecure HS256 secret 'dev-secret' without HAPP_ALLOW_INSECURE_DEV_SECRET=1")
    if len(secret) < MIN_HS256_SECRET_BYTES:
        raise SigningConfigurationError(f"HS256 signing secret must be at least {MIN_HS256_SECRET_BYTES} bytes")
    return secret


def hs256_signing_config(secret: bytes) -> IssuerSigningConfig:
    return IssuerSigningConfig(alg="HS256", hs256_secret=_validate_hs256_secret(secret))


def rs256_signing_config(keypair: RsaKeyPair) -> IssuerSigningConfig:
    return IssuerSigningConfig(alg="RS256", rsa_keypair=keypair)


def load_signing_config_from_env() -> IssuerSigningConfig:
    alg = os.environ.get("HAPP_SIGNING_ALG", "HS256").strip().upper() or "HS256"
    if alg == "HS256":
        secret_value = os.environ.get("HAPP_HS256_SECRET") or os.environ.get("HAPP_DEMO_HS256_SECRET")
        if not secret_value:
            raise SigningConfigurationError(
                "HS256 signing is not configured. Set HAPP_HS256_SECRET to a random secret "
                f"of at least {MIN_HS256_SECRET_BYTES} bytes, or configure HAPP_SIGNING_ALG=RS256."
            )
        return hs256_signing_config(secret_value.encode("utf-8"))

    if alg == "RS256":
        pem_text = os.environ.get("HAPP_RS256_PRIVATE_KEY_PEM", "").strip()
        pem_file = os.environ.get("HAPP_RS256_PRIVATE_KEY_FILE", "").strip()
        if pem_text and pem_file:
            raise SigningConfigurationError("Set only one of HAPP_RS256_PRIVATE_KEY_PEM or HAPP_RS256_PRIVATE_KEY_FILE")
        if pem_file:
            pem_bytes = Path(pem_file).read_bytes()
        elif pem_text:
            pem_bytes = pem_text.replace("\\n", "\n").encode("utf-8")
        else:
            raise SigningConfigurationError(
                "RS256 signing is not configured. Set HAPP_RS256_PRIVATE_KEY_PEM or HAPP_RS256_PRIVATE_KEY_FILE."
            )
        kid = os.environ.get("HAPP_RS256_KID", DEFAULT_RS256_KID).strip() or DEFAULT_RS256_KID
        return rs256_signing_config(load_rsa_keypair(pem_bytes, kid=kid))

    raise SigningConfigurationError(f"Unsupported HAPP_SIGNING_ALG: {alg}")


def _validate_identity(identity: IdentityBindingResult) -> None:
    if identity.mode not in _VALID_IDENTITY_MODES:
        raise ValueError("identity.mode must be 'verified' or 'asserted'")
    _non_empty_str(identity.scheme, field_name="identity.scheme")
    if not isinstance(identity.idp, dict) or not identity.idp:
        raise ValueError("identity.idp must be a non-empty object")
    if not isinstance(identity.subject, dict) or not identity.subject:
        raise ValueError("identity.subject must be a non-empty object")
    if identity.assurance is not None and not isinstance(identity.assurance, dict):
        raise ValueError("identity.assurance must be an object when present")
    if identity.evidence is not None and not isinstance(identity.evidence, dict):
        raise ValueError("identity.evidence must be an object when present")


def _sign_claims(claims: Dict[str, Any], signing_config: IssuerSigningConfig) -> tuple[str, Dict[str, str]]:
    protected_header: Dict[str, str] = {"alg": signing_config.alg, "typ": "HAPP-CC"}
    if signing_config.alg == "HS256":
        if signing_config.hs256_secret is None:
            raise SigningConfigurationError("HS256 signing secret missing")
        return jws_sign_hs256(claims, signing_config.hs256_secret, header={"typ": "HAPP-CC"}), protected_header

    if signing_config.alg == "RS256":
        if signing_config.rsa_keypair is None:
            raise SigningConfigurationError("RS256 signing key missing")
        protected_header["kid"] = signing_config.rsa_keypair.kid
        return jws_sign_rs256(claims, signing_config.rsa_keypair, header={"typ": "HAPP-CC"}), protected_header

    raise SigningConfigurationError(f"Unsupported signing alg: {signing_config.alg}")


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
    signing_config: Optional[IssuerSigningConfig] = None,
) -> Dict[str, Any]:
    """
    Issue a HAPP Consent Credential envelope.

    By default this loads signing configuration from the environment and fails closed if
    signing is not explicitly configured.
    """
    issuer = _non_empty_str(issuer, field_name="issuer")
    audience = _non_empty_str(audience, field_name="audience")
    pohp_method = _non_empty_str(pohp_method, field_name="pohp_method")
    provider_cert_ref = _non_empty_str(provider_cert_ref, field_name="provider_cert_ref")
    if not isinstance(action_intent, dict) or not action_intent:
        raise ValueError("action_intent must be a non-empty object")
    if pohp_level not in _VALID_POHP_LEVELS:
        raise ValueError(f"Unsupported pohp_level: {pohp_level}")
    if ttl_seconds <= 0 or ttl_seconds > MAX_CREDENTIAL_TTL_SECONDS:
        raise ValueError(f"ttl_seconds must be between 1 and {MAX_CREDENTIAL_TTL_SECONDS}")
    if identity is not None:
        _validate_identity(identity)

    resolved_signing_config = signing_config or load_signing_config_from_env()

    intent_hash = compute_intent_hash(action_intent)
    signing_view = derive_signing_view(action_intent)
    presentation_hash = compute_presentation_hash(signing_view)

    now = now_utc()
    iat = int(now.timestamp())
    exp = now + timedelta(seconds=ttl_seconds)
    jti = str(uuid.uuid4())

    claims: Dict[str, Any] = {
        "iss": issuer,
        "issuer": issuer,
        "intent_hash": intent_hash,
        "presentation_hash": presentation_hash,
        "aud": audience,
        "jti": jti,
        "iat": iat,
        "nbf": iat,
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

    token, protected_header = _sign_claims(claims, resolved_signing_config)

    envelope: Dict[str, Any] = {
        "format": "jwt",
        "credential": token,
        "claims": claims,
        "protectedHeader": protected_header,
        "verification": {"alg": resolved_signing_config.alg},
    }
    public_jwks = resolved_signing_config.public_jwks()
    if public_jwks is not None:
        envelope["verification"]["jwks"] = public_jwks
    return envelope
