from __future__ import annotations

import base64
import hashlib
import json
from typing import Any, Dict, Optional


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _sha256_b64url(data: bytes) -> str:
    return _b64url_encode(hashlib.sha256(data).digest())


def canonical_json(value: Any) -> str:
    # Pragmatic deterministic JSON for SDK interop in this repository.
    # The protocol spec requires RFC 8785 JCS for strict conformance.
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_prefixed(value: Any) -> str:
    return "sha256:" + _sha256_b64url(canonical_json(value).encode("utf-8"))


def compute_intent_hash(action_intent: Dict[str, Any]) -> str:
    return sha256_prefixed(action_intent)


def derive_signing_view(action_intent: Dict[str, Any]) -> Dict[str, Any]:
    audience = action_intent.get("audience") or {}
    agent = action_intent.get("agent") or {}
    action = action_intent.get("action") or {}
    constraints = action_intent.get("constraints") or {}
    display = action_intent.get("display") or {}

    return {
        "profile": action_intent.get("profile") or "aaif.happ.profile.generic/v0.3",
        "audience": {
            "id": audience.get("id"),
            "name": audience.get("name"),
        },
        "agent": {
            "id": agent.get("id"),
            "name": agent.get("name"),
            "software": agent.get("software"),
        },
        "action": {
            "type": action.get("type"),
            "parameters": action.get("parameters"),
        },
        "constraints": {
            "expiresAt": constraints.get("expiresAt"),
            "oneTime": constraints.get("oneTime"),
            "maxUses": constraints.get("maxUses"),
            "envelope": constraints.get("envelope"),
        },
        "display": {
            "title": display.get("title"),
            "summary": display.get("summary"),
            "riskNotice": display.get("riskNotice"),
            "language": display.get("language"),
        },
    }


def compute_presentation_hash(signing_view: Dict[str, Any]) -> str:
    return sha256_prefixed(signing_view)
