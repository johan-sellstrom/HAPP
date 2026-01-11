from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional, Tuple
import uuid

from happ.crypto.jws import RsaKeyPair, generate_rsa_keypair, rsa_public_jwk, jws_sign_rs256
from happ.util import sha256_b64url


@dataclass
class MockEntraIssuer:
    keypair: RsaKeyPair
    issuer: str
    audience: str

    def jwks(self) -> Dict[str, Any]:
        return {"keys": [rsa_public_jwk(self.keypair.public_key, self.keypair.kid)]}

    def issue_id_token(
        self,
        tenant_id: str,
        oid: str,
        nonce: str,
        amr: Optional[list[str]] = None,
        acrs: Optional[list[str]] = None,
        lifetime_seconds: int = 600,
    ) -> str:
        now = datetime.now(timezone.utc)
        exp = now + timedelta(seconds=lifetime_seconds)
        payload: Dict[str, Any] = {
            "iss": self.issuer,
            "aud": self.audience,
            "iat": int(now.timestamp()),
            "nbf": int(now.timestamp()),
            "exp": int(exp.timestamp()),
            "nonce": nonce,
            "tid": tenant_id,
            "oid": oid,
            "sub": oid,
            "auth_time": int(now.timestamp()),
        }
        if amr is not None:
            payload["amr"] = amr
        if acrs is not None:
            payload["acrs"] = acrs
        return jws_sign_rs256(payload, self.keypair)


def default_mock_issuer(client_id: str) -> MockEntraIssuer:
    # Issuer is Entra-like but local.
    keypair = generate_rsa_keypair(kid="mock-entra")
    return MockEntraIssuer(
        keypair=keypair,
        issuer="https://login.microsoftonline.com/mock/v2.0",
        audience=client_id or "mock-client",
    )
