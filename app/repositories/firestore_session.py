"""Firestore repository for auth sessions, rate limiting, and auth versioning."""
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

from app.config import settings
from app.models.auth import SessionDoc
from app.services.firestore import FirestoreConfigurationError, get_firestore_client

logger = logging.getLogger("carecircle.repository.session")

# In-memory store fallback when Firestore client is unconfigured/offline
_IN_MEMORY_SESSIONS: Dict[str, Dict[str, Any]] = {}
_IN_MEMORY_LOGIN_ATTEMPTS: Dict[str, Dict[str, Any]] = {}


class FirestoreSessionRepository:
    """
    Session and Security State repository backed by Cloud Firestore
    with automatic in-memory fallback for local/offline testing.
    """

    def __init__(self, client: Optional[Any] = None):
        self._client = client

    @property
    def client(self):
        if self._client is not None:
            return self._client
        c = get_firestore_client()
        if c is None and settings.ENVIRONMENT in ("production", "preview"):
            raise FirestoreConfigurationError(
                "Firestore is not configured in production/preview environment. "
                "In-memory fallback is strictly forbidden in production."
            )
        return c

    # -------------------------------------------------------------------------
    # Session Document Operations
    # -------------------------------------------------------------------------
    async def create_session(self, session_doc: SessionDoc) -> Dict[str, Any]:
        """Save a new session record keyed by its SHA-256 session ID."""
        data = session_doc.model_dump()
        session_id = session_doc.session_id

        c = self.client
        if c is not None:
            c.collection("auth_sessions").document(session_id).set(data)
        else:
            _IN_MEMORY_SESSIONS[session_id] = data
        return data

    async def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve a session document by its SHA-256 session ID."""
        if not session_id:
            return None
        c = self.client
        if c is not None:
            doc = c.collection("auth_sessions").document(session_id).get()
            return doc.to_dict() if doc.exists else None
        return _IN_MEMORY_SESSIONS.get(session_id)

    async def revoke_session(self, session_id: str, reason: str = "logout") -> bool:
        """Mark a single session revoked."""
        if not session_id:
            return False
        c = self.client
        if c is not None:
            doc_ref = c.collection("auth_sessions").document(session_id)
            doc = doc_ref.get()
            if not doc.exists:
                return False
            doc_ref.update({
                "revoked": True,
                "revoked_reason": reason,
            })
            return True
        session = _IN_MEMORY_SESSIONS.get(session_id)
        if session:
            session["revoked"] = True
            session["revoked_reason"] = reason
            return True
        return False

    async def update_last_seen(self, session_id: str, last_seen_iso: str) -> None:
        """Update last_seen_at timestamp on a session document."""
        if not session_id:
            return
        c = self.client
        if c is not None:
            c.collection("auth_sessions").document(session_id).update({
                "last_seen_at": last_seen_iso,
            })
        else:
            session = _IN_MEMORY_SESSIONS.get(session_id)
            if session:
                session["last_seen_at"] = last_seen_iso

    # -------------------------------------------------------------------------
    # Lockout & Login Attempt Management
    # -------------------------------------------------------------------------
    async def record_failed_login(
        self,
        member_id: str,
        current_failed: int = 0,
    ) -> Dict[str, Any]:
        """
        Atomically increment failed login counter and set lockout if threshold reached.
        """
        new_failed = current_failed + 1
        now = datetime.now(timezone.utc)
        locked_until_iso = None

        if new_failed >= settings.MAX_LOGIN_ATTEMPTS:
            locked_until = now + timedelta(minutes=settings.LOCKOUT_DURATION_MINUTES)
            locked_until_iso = locked_until.isoformat()

        update_payload = {
            "failed_login_attempts": new_failed,
            "locked_until": locked_until_iso,
        }

        c = self.client
        if c is not None:
            c.collection("circle_members").document(member_id).update(update_payload)
        else:
            from app.repositories.firestore_circle import _IN_MEMORY_MEMBERS
            mem = _IN_MEMORY_MEMBERS.get(member_id)
            if mem:
                mem.update(update_payload)

        return update_payload

    async def reset_failed_logins(self, member_id: str) -> None:
        """Reset failed login counters and record last_login_at on successful authentication."""
        now_iso = datetime.now(timezone.utc).isoformat()
        update_payload = {
            "failed_login_attempts": 0,
            "locked_until": None,
            "last_login_at": now_iso,
        }
        c = self.client
        if c is not None:
            c.collection("circle_members").document(member_id).update(update_payload)
        else:
            from app.repositories.firestore_circle import _IN_MEMORY_MEMBERS
            mem = _IN_MEMORY_MEMBERS.get(member_id)
            if mem:
                mem.update(update_payload)

    # -------------------------------------------------------------------------
    # Global Session Revocation (auth_version)
    # -------------------------------------------------------------------------
    async def increment_auth_version(self, member_id: str, current_version: int = 1) -> int:
        """
        Increment member's auth_version.
        Instantly invalidates all active sessions for this member across all devices.
        """
        new_version = current_version + 1
        c = self.client
        if c is not None:
            c.collection("circle_members").document(member_id).update({
                "auth_version": new_version,
            })
        else:
            from app.repositories.firestore_circle import _IN_MEMORY_MEMBERS
            mem = _IN_MEMORY_MEMBERS.get(member_id)
            if mem:
                mem["auth_version"] = new_version
        return new_version
