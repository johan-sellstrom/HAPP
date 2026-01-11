from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional


@dataclass
class IdentityBindingResult:
    mode: str  # "verified" or "asserted"
    scheme: str
    idp: Dict[str, Any]
    subject: Dict[str, Any]
    assurance: Optional[Dict[str, Any]] = None
    evidence: Optional[Dict[str, Any]] = None
