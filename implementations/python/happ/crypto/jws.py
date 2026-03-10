from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass
from typing import Any, Dict, Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from happ.util import b64url_encode, b64url_decode


@dataclass
class RsaKeyPair:
    private_key: rsa.RSAPrivateKey
    kid: str

    @property
    def public_key(self) -> rsa.RSAPublicKey:
        return self.private_key.public_key()


def generate_rsa_keypair(kid: str = "test") -> RsaKeyPair:
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return RsaKeyPair(private_key=private, kid=kid)


def load_rsa_keypair(pem: bytes, kid: str) -> RsaKeyPair:
    private_key = load_pem_private_key(pem, password=None)
    if not isinstance(private_key, rsa.RSAPrivateKey):
        raise ValueError("PEM does not contain an RSA private key")
    return RsaKeyPair(private_key=private_key, kid=kid)


def rsa_public_jwk(key: rsa.RSAPublicKey, kid: str) -> Dict[str, Any]:
    numbers = key.public_numbers()
    n = numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")
    e = numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big")
    return {
        "kty": "RSA",
        "kid": kid,
        "use": "sig",
        "alg": "RS256",
        "n": b64url_encode(n),
        "e": b64url_encode(e),
    }


def _split_jws(token: str) -> tuple[str, str, str]:
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("Invalid JWS")
    return parts[0], parts[1], parts[2]


def jws_get_unverified_header(token: str) -> Dict[str, Any]:
    header_b64, _, _ = _split_jws(token)
    return json.loads(b64url_decode(header_b64).decode("utf-8"))


def jws_sign_hs256(payload: Dict[str, Any], secret: bytes, header: Optional[Dict[str, Any]] = None) -> str:
    hdr = {"alg": "HS256", "typ": "JWT"}
    if header:
        hdr.update(header)
    header_b64 = b64url_encode(json.dumps(hdr, separators=(",", ":"), sort_keys=True).encode("utf-8"))
    payload_b64 = b64url_encode(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8"))
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    sig = hmac.new(secret, signing_input, hashlib.sha256).digest()
    sig_b64 = b64url_encode(sig)
    return f"{header_b64}.{payload_b64}.{sig_b64}"


def jws_verify_hs256(token: str, secret: bytes) -> Dict[str, Any]:
    header_b64, payload_b64, sig_b64 = _split_jws(token)
    header = json.loads(b64url_decode(header_b64).decode("utf-8"))
    if header.get("alg") != "HS256":
        raise ValueError("Unexpected alg")
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    expected = hmac.new(secret, signing_input, hashlib.sha256).digest()
    if not hmac.compare_digest(expected, b64url_decode(sig_b64)):
        raise ValueError("Bad signature")
    payload = json.loads(b64url_decode(payload_b64).decode("utf-8"))
    return payload


def jws_sign_rs256(payload: Dict[str, Any], keypair: RsaKeyPair, header: Optional[Dict[str, Any]] = None) -> str:
    hdr = {"alg": "RS256", "typ": "JWT", "kid": keypair.kid}
    if header:
        hdr.update(header)
    header_b64 = b64url_encode(json.dumps(hdr, separators=(",", ":"), sort_keys=True).encode("utf-8"))
    payload_b64 = b64url_encode(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8"))
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    sig = keypair.private_key.sign(
        signing_input,
        padding.PKCS1v15(),
        hashes.SHA256(),
    )
    sig_b64 = b64url_encode(sig)
    return f"{header_b64}.{payload_b64}.{sig_b64}"


def jws_verify_rs256(token: str, jwks: Dict[str, Any], expected_aud: Optional[str] = None) -> Dict[str, Any]:
    header_b64, payload_b64, sig_b64 = _split_jws(token)
    header = json.loads(b64url_decode(header_b64).decode("utf-8"))
    if header.get("alg") != "RS256":
        raise ValueError("Unexpected alg")
    kid = header.get("kid")
    if not kid:
        raise ValueError("Missing kid")
    keys = jwks.get("keys", [])
    jwk = next((k for k in keys if k.get("kid") == kid), None)
    if jwk is None:
        raise ValueError("Unknown kid")
    if jwk.get("kty") != "RSA":
        raise ValueError("Unsupported kty")
    if jwk.get("use") not in (None, "sig"):
        raise ValueError("Unsupported key use")
    if jwk.get("alg") not in (None, "RS256"):
        raise ValueError("Unexpected JWK alg")
    n = int.from_bytes(b64url_decode(jwk["n"]), "big")
    e = int.from_bytes(b64url_decode(jwk["e"]), "big")
    pub = rsa.RSAPublicNumbers(e=e, n=n).public_key()
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    sig = b64url_decode(sig_b64)
    pub.verify(sig, signing_input, padding.PKCS1v15(), hashes.SHA256())
    payload = json.loads(b64url_decode(payload_b64).decode("utf-8"))
    if expected_aud is not None:
        aud = payload.get("aud")
        if aud != expected_aud:
            raise ValueError("Bad aud")
    return payload
