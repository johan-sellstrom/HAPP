from __future__ import annotations

from typing import Any, Dict, Tuple, Optional

from happ.util import sha256_prefixed


def compute_intent_hash(action_intent: Dict[str, Any]) -> str:
    # Spec requires RFC8785 JCS. Here we use deterministic JSON encoding for demo.
    return sha256_prefixed(action_intent)


def normalize_profile(profile: Optional[str]) -> str:
    return profile or "aaif.happ.profile.generic/v0.3"


def derive_signing_view(action_intent: Dict[str, Any]) -> Dict[str, Any]:
    """
    Deterministic 'Signing View' derived from the Action Intent.

    NOTE: This is a conservative generic rendering. Profile-specific renderers can be added later.
    """
    profile = normalize_profile(action_intent.get("profile"))

    audience = action_intent.get("audience", {})
    agent = action_intent.get("agent", {})
    action = action_intent.get("action", {})
    constraints = action_intent.get("constraints", {})

    signing_view: Dict[str, Any] = {
        "profile": profile,
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
            # display hints are included but MUST NOT be treated as sole truth
            "title": (action_intent.get("display") or {}).get("title"),
            "summary": (action_intent.get("display") or {}).get("summary"),
            "riskNotice": (action_intent.get("display") or {}).get("riskNotice"),
            "language": (action_intent.get("display") or {}).get("language"),
        },
    }

    return signing_view


def compute_presentation_hash(signing_view: Dict[str, Any]) -> str:
    return sha256_prefixed(signing_view)
