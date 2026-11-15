"""Session Management Service enforcing dual-tier timeouts, revocation, and invariants."""
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple

from app.config import settings
from app.models.auth import MemberDoc, MemberRole, SessionData, SessionDoc
from app.repositories.firestore_circle import FirestoreCircleRepository
from app.repositories.firestore_session import FirestoreSessionRepository
from app.services.auth import generate_session_token, hash_session_token

logger = logging.getLogger("carecircle.service.session")


class SessionService:
    """Service orchestrating stateful session lifecycle and authentication policies."""

    def __init__(
        self,
        session_repo: Optional[FirestoreSessionRepository] = None,
        circle_repo: Optional[FirestoreCircleRepository] = None,
    ):
        self.session_repo = session_repo or FirestoreSessionRepository()
        self.circle_repo = circle_repo or FirestoreCircleRepository()

    async def create_session(
        self,
        member: MemberDoc,
        client_ip: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> Tuple[str, SessionDoc]:
        """
        Create a new opaque session for an authenticated member.
        Returns (raw_session_token, session_doc).
        The raw token must only be sent to the user in an HttpOnly cookie.
        """
        raw_token = generate_session_token()
        session_id = hash_session_token(raw_token)

        now = datetime.now(timezone.utc)
        # Determine absolute timeout based on member role
        if member.role == MemberRole.ELDER:
            absolute_lifespan = timedelta(seconds=settings.ELDER_ABSOLUTE_TIMEOUT_SECONDS)
        else:
            absolute_lifespan = timedelta(seconds=settings.CAREGIVER_ABSOLUTE_TIMEOUT_SECONDS)

        expires_at = now + absolute_lifespan

        session_doc = SessionDoc(
            session_id=session_id,
            member_id=member.member_id,
            circle_id=member.circle_id,
            role=member.role,
            username=member.username,
            display_name=member.display_name,
            auth_version=member.auth_version,
            revoked=False,
            created_at=now.isoformat(),
            expires_at=expires_at.isoformat(),
            last_seen_at=now.isoformat(),
            client_ip=client_ip,
            user_agent=user_agent,
        )

        await self.session_repo.create_session(session_doc)
        return raw_token, session_doc

    async def validate_session(self, raw_token: Optional[str]) -> Optional[SessionData]:
        """
        Authoritatively validate a session token on each authenticated request:
        1. Checks token hash exists in auth_sessions.
        2. Validates not revoked.
        3. Validates not expired (idle and absolute timeouts).
        4. Validates authoritative member status and circle membership.
        5. Validates session auth_version matches member auth_version.
        6. Updates last_seen_at if throttle window has elapsed.
        """
        if not raw_token or not isinstance(raw_token, str):
            return None

        try:
            token_hash = hash_session_token(raw_token)
        except ValueError:
            return None

        session_dict = await self.session_repo.get_session(token_hash)
        if not session_dict:
            return None

        # Check explicit revocation
        if session_dict.get("revoked", False):
            return None

        now = datetime.now(timezone.utc)
        try:
            created_at = datetime.fromisoformat(session_dict["created_at"])
            expires_at = datetime.fromisoformat(session_dict["expires_at"])
            last_seen_at = datetime.fromisoformat(session_dict["last_seen_at"])
        except Exception:
            return None

        # Check absolute expiration
        if now > expires_at:
            await self.session_repo.revoke_session(token_hash, reason="expired_absolute")
            return None

        # Check idle timeout
        role_str = session_dict.get("role", MemberRole.CAREGIVER.value)
        if role_str == MemberRole.ELDER.value:
            idle_limit = timedelta(seconds=settings.ELDER_IDLE_TIMEOUT_SECONDS)
        else:
            idle_limit = timedelta(seconds=settings.CAREGIVER_IDLE_TIMEOUT_SECONDS)

        if now - last_seen_at > idle_limit:
            await self.session_repo.revoke_session(token_hash, reason="expired_idle")
            return None

        # Retrieve authoritative member document
        member_id = session_dict.get("member_id")
        member_dict = await self.circle_repo.get_member_by_id_only(member_id)
        if not member_dict:
            return None

        # Verify member active status
        if not member_dict.get("is_active", True):
            return None

        # Verify auth_version (global invalidation check)
        current_auth_version = member_dict.get("auth_version", 1)
        session_auth_version = session_dict.get("auth_version", 1)
        if session_auth_version < current_auth_version:
            # Session invalidated due to password/PIN change or recovery
            return None

        # Maintain invariant: created_at <= last_seen_at <= expires_at
        # Throttled update of last_seen_at (at most once every 15 minutes)
        if (now - last_seen_at).total_seconds() >= settings.SESSION_TOUCH_THROTTLE_SECONDS:
            new_last_seen = min(now, expires_at)
            await self.session_repo.update_last_seen(token_hash, new_last_seen.isoformat())
            last_seen_at = new_last_seen

        return SessionData(
            session_id=token_hash,
            member_id=member_dict["member_id"],
            circle_id=member_dict["circle_id"],
            role=MemberRole(member_dict["role"]),
            username=member_dict["username"],
            display_name=member_dict["display_name"],
            auth_version=current_auth_version,
            created_at=created_at,
            expires_at=expires_at,
            last_seen_at=last_seen_at,
        )

    async def revoke_current_session(self, raw_token: Optional[str], reason: str = "logout") -> bool:
        """Revoke a single active session by raw token (e.g. user logout)."""
        if not raw_token:
            return False
        try:
            token_hash = hash_session_token(raw_token)
        except ValueError:
            return False
        return await self.session_repo.revoke_session(token_hash, reason=reason)

    async def revoke_all_member_sessions(self, member_id: str, current_version: int = 1) -> int:
        """
        Global revocation: increment member's auth_version.
        Instantly invalidates all sessions for this member across all devices in O(1).
        """
        return await self.session_repo.increment_auth_version(member_id, current_version)
