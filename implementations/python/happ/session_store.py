from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Any, Dict, Optional


@dataclass
class ConsentSession:
    elicitation_id: str
    action_intent: Dict[str, Any]
    requirements: Dict[str, Any]
    approved: bool = False
    denied: bool = False
    identity_binding: Optional[Dict[str, Any]] = None
    nonce: Optional[str] = None
    state: Optional[str] = None
    code_verifier: Optional[str] = None
    entra_tokens: Optional[Dict[str, Any]] = None  # raw token response
    debug: Dict[str, Any] = field(default_factory=dict)


class SessionStore:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._sessions: Dict[str, ConsentSession] = {}

    def create(self, elicitation_id: str, action_intent: Dict[str, Any], requirements: Dict[str, Any]) -> ConsentSession:
        with self._lock:
            sess = ConsentSession(elicitation_id=elicitation_id, action_intent=action_intent, requirements=requirements)
            self._sessions[elicitation_id] = sess
            return sess

    def get(self, elicitation_id: str) -> Optional[ConsentSession]:
        with self._lock:
            return self._sessions.get(elicitation_id)

    def update(self, elicitation_id: str, **kwargs: Any) -> Optional[ConsentSession]:
        with self._lock:
            sess = self._sessions.get(elicitation_id)
            if sess is None:
                return None
            for k, v in kwargs.items():
                setattr(sess, k, v)
            return sess


STORE = SessionStore()
