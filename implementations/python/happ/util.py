from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode((data + padding).encode("ascii"))


def sha256_b64url(data: bytes) -> str:
    return b64url_encode(hashlib.sha256(data).digest())


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def json_canonical(obj: Any) -> str:
    # NOTE: This is a pragmatic deterministic encoding for the reference implementation.
    # The spec requires RFC 8785 (JCS). Implementers should use a true JCS library.
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_prefixed(obj: Any) -> str:
    canon = json_canonical(obj).encode("utf-8")
    return "sha256:" + sha256_b64url(canon)


@dataclass(frozen=True)
class PohpAssurance:
    level: str
    verified_at: str  # RFC3339
    method: str
