from __future__ import annotations

import os
import secrets
import threading
from dataclasses import dataclass, field, fields
from datetime import datetime, timedelta
from typing import Any, Dict, Optional

from happ.util import now_utc


def _int_env(name: str, default: int) -> int:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    value = int(raw)
    if value <= 0:
        raise ValueError(f"{name} must be > 0")
    return value


@dataclass
class ConsentSession:
    elicitation_id: str
    action_intent: Dict[str, Any]
    requirements: Dict[str, Any]
    approved: bool = False
    denied: bool = False
    identity_binding: Optional[Dict[str, Any]] = None
    csrf_token: str = field(default_factory=lambda: secrets.token_urlsafe(24))
    nonce: Optional[str] = None
    state: Optional[str] = None
    state_expires_at: Optional[datetime] = None
    code_verifier: Optional[str] = None
    entra_tokens: Optional[Dict[str, Any]] = None
    pohp_verified_at: Optional[datetime] = None
    pohp_level: Optional[str] = None
    pohp_method: Optional[str] = None
    issued_credential: Optional[Dict[str, Any]] = None
    debug: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=now_utc)
    updated_at: datetime = field(default_factory=now_utc)
    expires_at: Optional[datetime] = None


class SessionStore:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._sessions: Dict[str, ConsentSession] = {}
        self._state_index: Dict[str, str] = {}
        self._session_ttl_seconds = _int_env("HAPP_SESSION_TTL_SECONDS", 900)
        self._oidc_state_ttl_seconds = _int_env("HAPP_OIDC_STATE_TTL_SECONDS", 300)
        self._mutable_fields = {f.name for f in fields(ConsentSession)} - {"elicitation_id", "created_at"}

    def _drop_session_locked(self, elicitation_id: str) -> None:
        sess = self._sessions.pop(elicitation_id, None)
        if sess and sess.state:
            self._state_index.pop(sess.state, None)

    def _prune_locked(self) -> None:
        now = now_utc()
        expired = [
            elicitation_id
            for elicitation_id, sess in self._sessions.items()
            if sess.expires_at is not None and sess.expires_at <= now
        ]
        for elicitation_id in expired:
            self._drop_session_locked(elicitation_id)

        stale_states = [
            state
            for state, elicitation_id in self._state_index.items()
            if (
                elicitation_id not in self._sessions
                or self._sessions[elicitation_id].state != state
                or self._sessions[elicitation_id].state_expires_at is None
                or self._sessions[elicitation_id].state_expires_at <= now
            )
        ]
        for state in stale_states:
            self._state_index.pop(state, None)

    def create(self, elicitation_id: str, action_intent: Dict[str, Any], requirements: Dict[str, Any]) -> ConsentSession:
        with self._lock:
            self._prune_locked()
            now = now_utc()
            sess = ConsentSession(
                elicitation_id=elicitation_id,
                action_intent=action_intent,
                requirements=requirements,
                created_at=now,
                updated_at=now,
                expires_at=now + timedelta(seconds=self._session_ttl_seconds),
            )
            self._sessions[elicitation_id] = sess
            return sess

    def get(self, elicitation_id: Optional[str]) -> Optional[ConsentSession]:
        if not elicitation_id:
            return None
        with self._lock:
            self._prune_locked()
            return self._sessions.get(elicitation_id)

    def update(self, elicitation_id: str, **kwargs: Any) -> Optional[ConsentSession]:
        with self._lock:
            self._prune_locked()
            sess = self._sessions.get(elicitation_id)
            if sess is None:
                return None

            unknown = set(kwargs) - self._mutable_fields
            if unknown:
                raise ValueError(f"Unknown session fields: {', '.join(sorted(unknown))}")

            if "state" in kwargs:
                old_state = sess.state
                new_state = kwargs["state"]
                if old_state and old_state != new_state:
                    self._state_index.pop(old_state, None)
                if new_state:
                    self._state_index[str(new_state)] = elicitation_id
                    kwargs.setdefault(
                        "state_expires_at",
                        now_utc() + timedelta(seconds=self._oidc_state_ttl_seconds),
                    )
                else:
                    kwargs.setdefault("state_expires_at", None)

            for key, value in kwargs.items():
                setattr(sess, key, value)
            sess.updated_at = now_utc()
            return sess

    def begin_oidc_flow(self, elicitation_id: str, *, state: str, nonce: str, code_verifier: str) -> Optional[ConsentSession]:
        return self.update(
            elicitation_id,
            state=state,
            nonce=nonce,
            code_verifier=code_verifier,
            entra_tokens=None,
        )

    def consume_oidc_state(self, state: str) -> Optional[ConsentSession]:
        with self._lock:
            self._prune_locked()
            elicitation_id = self._state_index.pop(state, None)
            if not elicitation_id:
                return None
            sess = self._sessions.get(elicitation_id)
            if sess is None or sess.state != state:
                return None
            if sess.state_expires_at is None or sess.state_expires_at <= now_utc():
                sess.state = None
                sess.state_expires_at = None
                sess.updated_at = now_utc()
                return None
            sess.state = None
            sess.state_expires_at = None
            sess.updated_at = now_utc()
            return sess

    def clear_oidc_state(self, elicitation_id: str) -> Optional[ConsentSession]:
        with self._lock:
            self._prune_locked()
            sess = self._sessions.get(elicitation_id)
            if sess is None:
                return None
            if sess.state:
                self._state_index.pop(sess.state, None)
            sess.state = None
            sess.state_expires_at = None
            sess.code_verifier = None
            sess.updated_at = now_utc()
            return sess

    def mark_pohp_verified(
        self,
        elicitation_id: str,
        *,
        level: str,
        method: str,
        verified_at: Optional[datetime] = None,
    ) -> Optional[ConsentSession]:
        return self.update(
            elicitation_id,
            pohp_level=level,
            pohp_method=method,
            pohp_verified_at=verified_at or now_utc(),
        )

    def store_issued_credential(self, elicitation_id: str, credential: Dict[str, Any]) -> Optional[ConsentSession]:
        return self.update(elicitation_id, issued_credential=credential)


STORE = SessionStore()
