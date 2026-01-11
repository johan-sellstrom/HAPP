from __future__ import annotations

import os
import secrets
import urllib.parse
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

import requests

from happ.util import b64url_encode, sha256_b64url


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


def env_config() -> EntraOidcConfig:
    tenant_id = os.environ.get("HAPP_ENTRA_TENANT_ID", "common")
    client_id = os.environ.get("HAPP_ENTRA_CLIENT_ID", "")
    redirect_uri = os.environ.get("HAPP_ENTRA_REDIRECT_URI", "http://127.0.0.1:8787/entra/callback")
    scope = os.environ.get("HAPP_ENTRA_SCOPE", "openid profile email")
    return EntraOidcConfig(tenant_id=tenant_id, client_id=client_id, redirect_uri=redirect_uri, scope=scope)
