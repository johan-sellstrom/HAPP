from __future__ import annotations

import os
import secrets
import time
import urllib.parse
from dataclasses import dataclass
from typing import Any, Dict, Optional

import requests

from happ.crypto.jws import jws_verify_rs256
from happ.util import b64url_encode, sha256_b64url


_CACHE_TTL_SECONDS = 300
_DISCOVERY_CACHE: Dict[str, tuple[float, Dict[str, Any]]] = {}
_JWKS_CACHE: Dict[str, tuple[float, Dict[str, Any]]] = {}


@dataclass(frozen=True)
class EntraOidcConfig:
    tenant_id: str
    client_id: str
    redirect_uri: str
    scope: str = "openid profile email"
    authorize_base: str = "https://login.microsoftonline.com"
    token_base: str = "https://login.microsoftonline.com"


def pkce_create_verifier() -> str:
    # 43-128 chars. Use 64 bytes urlsafe.
    return b64url_encode(secrets.token_bytes(64))


def pkce_challenge(verifier: str) -> str:
    return sha256_b64url(verifier.encode("ascii"))


def build_authorize_url(
    cfg: EntraOidcConfig,
    state: str,
    nonce: str,
    code_verifier: str,
    prompt: Optional[str] = None,
    login_hint: Optional[str] = None,
    domain_hint: Optional[str] = None,
    extra_params: Optional[Dict[str, str]] = None,
) -> str:
    endpoint = f"{cfg.authorize_base}/{cfg.tenant_id}/oauth2/v2.0/authorize"
    params = {
        "client_id": cfg.client_id,
        "response_type": "code",
        "redirect_uri": cfg.redirect_uri,
        "response_mode": "query",
        "scope": cfg.scope,
        "state": state,
        "nonce": nonce,
        "code_challenge": pkce_challenge(code_verifier),
        "code_challenge_method": "S256",
    }
    if prompt:
        params["prompt"] = prompt
    if login_hint:
        params["login_hint"] = login_hint
    if domain_hint:
        params["domain_hint"] = domain_hint
    if extra_params:
        params.update(extra_params)
    return endpoint + "?" + urllib.parse.urlencode(params)


def exchange_code_for_tokens(
    cfg: EntraOidcConfig,
    code: str,
    code_verifier: str,
    client_secret: Optional[str] = None,
    timeout_seconds: int = 15,
) -> Dict[str, Any]:
    """
    Exchange an auth code for tokens.

    NOTE: This performs a live network call to Entra. It will fail in offline environments.
    """
    endpoint = f"{cfg.token_base}/{cfg.tenant_id}/oauth2/v2.0/token"
    data = {
        "client_id": cfg.client_id,
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": cfg.redirect_uri,
        "code_verifier": code_verifier,
    }
    if client_secret:
        data["client_secret"] = client_secret
    resp = requests.post(endpoint, data=data, timeout=timeout_seconds)
    resp.raise_for_status()
    return resp.json()


def _cached_get(cache: Dict[str, tuple[float, Dict[str, Any]]], key: str) -> Optional[Dict[str, Any]]:
    entry = cache.get(key)
    if entry is None:
        return None
    expires_at, value = entry
    if expires_at <= time.time():
        cache.pop(key, None)
        return None
    return value


def _cached_put(cache: Dict[str, tuple[float, Dict[str, Any]]], key: str, value: Dict[str, Any]) -> Dict[str, Any]:
    cache[key] = (time.time() + _CACHE_TTL_SECONDS, value)
    return value


def fetch_openid_configuration(cfg: EntraOidcConfig, timeout_seconds: int = 10) -> Dict[str, Any]:
    url = os.environ.get(
        "HAPP_ENTRA_OPENID_CONFIG_URL",
        f"{cfg.authorize_base}/{cfg.tenant_id}/v2.0/.well-known/openid-configuration",
    )
    cached = _cached_get(_DISCOVERY_CACHE, url)
    if cached is not None:
        return cached

    resp = requests.get(url, timeout=timeout_seconds)
    resp.raise_for_status()
    metadata = resp.json()
    if not isinstance(metadata, dict):
        raise ValueError("OpenID configuration response must be a JSON object")
    if not metadata.get("issuer") or not metadata.get("jwks_uri"):
        raise ValueError("OpenID configuration missing issuer or jwks_uri")
    return _cached_put(_DISCOVERY_CACHE, url, metadata)


def fetch_jwks(jwks_url: str, timeout_seconds: int = 10) -> Dict[str, Any]:
    override = os.environ.get("HAPP_ENTRA_JWKS_URL", "").strip()
    url = override or jwks_url
    cached = _cached_get(_JWKS_CACHE, url)
    if cached is not None:
        return cached

    resp = requests.get(url, timeout=timeout_seconds)
    resp.raise_for_status()
    jwks = resp.json()
    if not isinstance(jwks, dict):
        raise ValueError("JWKS response must be a JSON object")
    if not isinstance(jwks.get("keys"), list):
        raise ValueError("JWKS missing keys array")
    return _cached_put(_JWKS_CACHE, url, jwks)


def verify_id_token(
    *,
    id_token: str,
    jwks: Dict[str, Any],
    expected_issuer: str,
    expected_audience: str,
    expected_nonce: str,
    clock_skew_seconds: int = 30,
) -> Dict[str, Any]:
    payload = jws_verify_rs256(id_token, jwks, expected_aud=expected_audience)
    now = int(time.time())

    iss = payload.get("iss")
    if iss != expected_issuer:
        raise ValueError("ID token issuer mismatch")
    nonce = payload.get("nonce")
    if nonce != expected_nonce:
        raise ValueError("ID token nonce mismatch")

    for field_name in ("exp", "iat", "nbf"):
        value = payload.get(field_name)
        try:
            payload[field_name] = int(value)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"ID token {field_name} missing or invalid") from exc

    if payload["exp"] < now - clock_skew_seconds:
        raise ValueError("ID token expired")
    if payload["iat"] > now + clock_skew_seconds:
        raise ValueError("ID token issued in the future")
    if payload["nbf"] > now + clock_skew_seconds:
        raise ValueError("ID token not yet valid")
    if not payload.get("tid") or not payload.get("oid"):
        raise ValueError("ID token missing tid or oid")
    return payload


def env_config() -> EntraOidcConfig:
    tenant_id = os.environ.get("HAPP_ENTRA_TENANT_ID", "common")
    client_id = os.environ.get("HAPP_ENTRA_CLIENT_ID", "")
    redirect_uri = os.environ.get("HAPP_ENTRA_REDIRECT_URI", "http://127.0.0.1:8787/entra/callback")
    scope = os.environ.get("HAPP_ENTRA_SCOPE", "openid profile email")
    return EntraOidcConfig(tenant_id=tenant_id, client_id=client_id, redirect_uri=redirect_uri, scope=scope)
