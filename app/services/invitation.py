"""Care Circle invitation management service for Phase 4."""
from datetime import datetime, timedelta, timezone
import hashlib
import logging
import secrets
from typing import Any, Dict, List, Optional
import uuid

from fastapi import HTTPException, Request, Response, status

from app.config import settings
from app.models.auth import AuthType, MemberDoc, MemberJoinRequest, MemberRole
from app.models.circle import (
    InvitationCreateRequest,
    InvitationCreateResponse,
    InvitationDoc,
    InvitationInspectResponse,
    InvitationPublicResponse,
)
from app.repositories.firestore_circle import FirestoreCircleRepository
from app.repositories.firestore_invitation import FirestoreInvitationRepository
from app.services.auth import hash_credential
from app.services.session import SessionService

logger = logging.getLogger("carecircle.service.invitation")


def hash_invitation_token(raw_token: str) -> str:
    """Compute SHA-256 hash of raw invitation token for safe storage and lookups."""
    if not raw_token or not isinstance(raw_token, str):
        raise ValueError("Invalid invitation token.")
    return hashlib.sha256(raw_token.strip().encode("utf-8")).hexdigest()


class InvitationService:
    """Service orchestrating circle invitations, copy links, and secure redemption."""

    def __init__(
        self,
        invitation_repo: Optional[FirestoreInvitationRepository] = None,
        circle_repo: Optional[FirestoreCircleRepository] = None,
        session_service: Optional[SessionService] = None,
    ):
        self.invitation_repo = invitation_repo or FirestoreInvitationRepository()
        self.circle_repo = circle_repo or FirestoreCircleRepository()
        self.session_service = session_service or SessionService(circle_repo=self.circle_repo)

    async def create_invitation(
        self,
        circle_id: str,
        creator: MemberDoc,
        payload: InvitationCreateRequest,
        base_url: str = "",
    ) -> InvitationCreateResponse:
        """
        Generate a 48-hour single-use invitation token.
        - Stores only SHA-256 hash in Firestore.
        - Returns raw token only once in InvitationCreateResponse.
        """
        circle = await self.circle_repo.get_circle(circle_id)
        if not circle or not circle.get("is_active", True):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Care circle not found.",
            )

        # Generate 32-byte cryptographically secure URL-safe token
        raw_token = secrets.token_urlsafe(32)
        token_hash = hash_invitation_token(raw_token)

        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(hours=48)
        invitation_id = str(uuid.uuid4())

        invitation_doc = InvitationDoc(
            invitation_id=invitation_id,
            circle_id=circle_id,
            circle_name=circle.get("name", "Care Circle"),
            role=payload.role,
            invited_name=payload.invited_name,
            invited_email=payload.invited_email,
            token_hash=token_hash,
            created_by=creator.member_id,
            created_by_name=creator.display_name,
            created_at=now.isoformat(),
            expires_at=expires_at.isoformat(),
            status="pending",
        )

        await self.invitation_repo.create_invitation(invitation_doc.model_dump())

        clean_base = base_url.rstrip("/") if base_url else ""
        invite_url = f"{clean_base}/invite/accept?token={raw_token}"

        public_resp = InvitationPublicResponse(
            invitation_id=invitation_id,
            circle_id=circle_id,
            role=payload.role,
            invited_name=payload.invited_name,
            invited_email=payload.invited_email,
            status="pending",
            created_at=invitation_doc.created_at,
            expires_at=invitation_doc.expires_at,
        )

        return InvitationCreateResponse(
            invitation=public_resp,
            raw_token=raw_token,
            invite_url=invite_url,
            expires_at=invitation_doc.expires_at,
        )

    async def list_invitations(
        self, circle_id: str, status_filter: Optional[str] = None
    ) -> List[InvitationPublicResponse]:
        """List invitations for a circle, with dynamic expiration check."""
        invitations = await self.invitation_repo.list_invitations_for_circle(
            circle_id, status_filter=status_filter
        )
        now_iso = datetime.now(timezone.utc).isoformat()
        results: List[InvitationPublicResponse] = []

        for inv in invitations:
            # Check if pending invitation has expired
            status_val = inv.get("status", "pending")
            if status_val == "pending" and inv.get("expires_at", "") < now_iso:
                status_val = "expired"

            results.append(
                InvitationPublicResponse(
                    invitation_id=inv["invitation_id"],
                    circle_id=inv["circle_id"],
                    role=MemberRole(inv["role"]),
                    invited_name=inv.get("invited_name"),
                    invited_email=inv.get("invited_email"),
                    status=status_val,
                    created_at=inv["created_at"],
                    expires_at=inv["expires_at"],
                    accepted_at=inv.get("accepted_at"),
                )
            )

        # Sort newest first
        results.sort(key=lambda x: x.created_at, reverse=True)
        return results

    async def revoke_invitation(
        self, circle_id: str, invitation_id: str, revoked_by: str
    ) -> InvitationPublicResponse:
        """Revoke a pending invitation link."""
        inv = await self.invitation_repo.get_invitation_by_id(circle_id, invitation_id)
        if not inv:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Invitation not found in care circle.",
            )

        updated = await self.invitation_repo.revoke_invitation(
            circle_id=circle_id,
            invitation_id=invitation_id,
            revoked_by=revoked_by,
        )
        if not updated:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Failed to revoke invitation.",
            )

        return InvitationPublicResponse(
            invitation_id=updated["invitation_id"],
            circle_id=updated["circle_id"],
            role=MemberRole(updated["role"]),
            invited_name=updated.get("invited_name"),
            invited_email=updated.get("invited_email"),
            status=updated.get("status", "revoked"),
            created_at=updated["created_at"],
            expires_at=updated["expires_at"],
            accepted_at=updated.get("accepted_at"),
        )

    async def inspect_invitation(self, raw_token: str) -> InvitationInspectResponse:
        """Publicly inspect an invitation token for recipient registration view."""
        if not raw_token or not isinstance(raw_token, str):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid invitation token.",
            )

        token_hash = hash_invitation_token(raw_token)
        inv = await self.invitation_repo.get_invitation_by_token_hash(token_hash)
        if not inv:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Invitation link not found or invalid.",
            )

        now_iso = datetime.now(timezone.utc).isoformat()
        status_val = inv.get("status", "pending")

        if status_val == "accepted":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="This invitation link has already been used.",
            )
        if status_val == "revoked":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="This invitation link has been revoked by the circle administrator.",
            )
        if status_val == "expired" or inv.get("expires_at", "") < now_iso:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="This invitation link has expired (links are valid for 48 hours).",
            )

        return InvitationInspectResponse(
            valid=True,
            circle_name=inv.get("circle_name", "Care Circle"),
            role=MemberRole(inv["role"]),
            invited_name=inv.get("invited_name"),
            expires_at=inv["expires_at"],
            status="pending",
        )

    async def accept_invitation(
        self,
        payload: MemberJoinRequest,
        request: Request,
        response: Response,
    ) -> Dict[str, Any]:
        """
        Accept an invitation and register a new caregiver or family member:
        1. Validates invitation token status and expiration.
        2. Validates unique username.
        3. Computes Argon2id password hash outside atomic transaction.
        4. Runs single-use atomic redemption in Firestore / memory lock.
        5. Creates active session and sets HttpOnly cookie.
        """
        token_hash = hash_invitation_token(payload.invite_token)
        inv = await self.invitation_repo.get_invitation_by_token_hash(token_hash)
        if not inv:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Invalid or expired invitation token.",
            )

        now_iso = datetime.now(timezone.utc).isoformat()
        if inv.get("status") == "accepted":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="This invitation link has already been used.",
            )
        if inv.get("status") == "revoked":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="This invitation link has been revoked.",
            )
        if inv.get("status") == "expired" or inv.get("expires_at", "") < now_iso:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="This invitation link has expired.",
            )

        # Check unique username across system
        clean_username = payload.username.strip().lower()
        existing_user = await self.circle_repo.get_member_by_username(clean_username)
        if existing_user:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Username is already taken. Please choose another username.",
            )

        # Hash password with Argon2id outside the transaction
        password_hash = hash_credential(payload.password)

        new_member_id = str(uuid.uuid4())
        circle_id = inv["circle_id"]
        role_val = inv["role"]

        new_member_doc = {
            "member_id": new_member_id,
            "circle_id": circle_id,
            "username": clean_username,
            "display_name": payload.display_name.strip(),
            "role": role_val,
            "auth_type": AuthType.PASSWORD.value,
            "is_active": True,
            "is_primary": False,
            "password_hash": password_hash,
            "auth_version": 1,
            "created_at": now_iso,
            "failed_login_attempts": 0,
        }

        # Atomic redemption
        try:
            updated_inv, created_member = await self.invitation_repo.redeem_invitation_atomically(
                token_hash=token_hash,
                new_member_data=new_member_doc,
            )
        except ValueError as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=str(e),
            )

        # Create session for new member
        client_ip = request.client.host if request.client else None
        user_agent = request.headers.get("user-agent")
        member_obj = MemberDoc(**created_member)

        raw_session_token, session_doc = await self.session_service.create_session(
            member=member_obj,
            client_ip=client_ip,
            user_agent=user_agent,
        )

        # Set session cookie
        response.set_cookie(
            key=settings.SESSION_COOKIE_NAME,
            value=raw_session_token,
            max_age=settings.CAREGIVER_ABSOLUTE_TIMEOUT_SECONDS,
            httponly=True,
            secure=settings.COOKIE_SECURE,
            samesite="lax",
            path="/",
        )

        return {
            "status": "success",
            "message": "Invitation accepted successfully. Welcome to the care circle!",
            "member": member_obj.to_public_response().model_dump(),
        }
