from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional


JsonDict = Dict[str, Any]


@dataclass(frozen=True)
class VerifyOptions:
    expected_aud: str
    now_epoch_seconds: Optional[int] = None
    min_pohp_level: Optional[str] = None
    identity_required: bool = False
    allowed_identity_schemes: Optional[list[str]] = None
    expected_challenge_id: Optional[str] = None
