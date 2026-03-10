from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict

import rfc8785


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
    return rfc8785.dumps(obj).decode("utf-8")


def sha256_prefixed(obj: Any) -> str:
    return "sha256:" + sha256_b64url(rfc8785.dumps(obj))


@dataclass(frozen=True)
class PohpAssurance:
    level: str
    verified_at: str  # RFC3339
    method: str
