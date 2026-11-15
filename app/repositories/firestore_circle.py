"""Firestore repository implementation for Care Circles and Circle Members."""
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import uuid

from app.config import settings
from app.models.auth import MemberRole, AuthType
from app.repositories.circle import CircleRepositoryInterface
from app.services.firestore import (
    CircleIsolationViolation,
    CircleSecurityContext,
    FirestoreConfigurationError,
    get_firestore_client,
)

logger = logging.getLogger("carecircle.repository.circle")

# In-memory store fallback when Firestore client is unconfigured/offline
_IN_MEMORY_CIRCLES: Dict[str, Dict[str, Any]] = {}
_IN_MEMORY_MEMBERS: Dict[str, Dict[str, Any]] = {}
_IN_MEMORY_METADATA: Dict[str, Dict[str, Any]] = {}


class FirestoreCircleRepository(CircleRepositoryInterface):
    """
    Concrete implementation of CircleRepositoryInterface backed by Cloud Firestore
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
    # System Provisioning Check
    # -------------------------------------------------------------------------
    def is_provisioned(self) -> bool:
        """Check whether the initial system care circle has already been provisioned."""
        c = self.client
        if c is not None:
            doc = c.collection("system_metadata").document("provisioning").get()
            if doc.exists:
                return bool(doc.to_dict().get("initialized", False))
            return False
        return bool(_IN_MEMORY_METADATA.get("provisioning", {}).get("initialized", False))

    def mark_provisioned(self, data: Optional[Dict[str, Any]] = None) -> None:
        """Mark system provisioning complete."""
        payload = data or {}
        payload["initialized"] = True
        payload["provisioned_at"] = datetime.now(timezone.utc).isoformat()
        c = self.client
        if c is not None:
            c.collection("system_metadata").document("provisioning").set(payload, merge=True)
        else:
            _IN_MEMORY_METADATA["provisioning"] = payload

    # -------------------------------------------------------------------------
    # Circle Operations
    # -------------------------------------------------------------------------
    async def get_circle(self, circle_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve circle document by circle ID."""
        if not circle_id:
            return None
        c = self.client
        if c is not None:
            doc = c.collection("care_circles").document(circle_id).get()
            return doc.to_dict() if doc.exists else None
        return _IN_MEMORY_CIRCLES.get(circle_id)

    async def get_circle_by_code(self, circle_code: str) -> Optional[Dict[str, Any]]:
        """Retrieve circle document by its 6-character Circle Code."""
        if not circle_code:
            return None
        code_upper = circle_code.strip().upper()
        c = self.client
        if c is not None:
            docs = c.collection("care_circles").where("circle_code", "==", code_upper).limit(1).get()
            for doc in docs:
                return doc.to_dict()
            return None
        for circle in _IN_MEMORY_CIRCLES.values():
            if circle.get("circle_code") == code_upper:
                return circle
        return None

    async def create_circle(
        self,
        circle_id: str,
        circle_name: str,
        elder_profile: Dict[str, Any],
        circle_code: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Create a new Care Circle with elder profile."""
        now = datetime.now(timezone.utc).isoformat()
        circle_data = {
            "circle_id": circle_id,
            "circle_code": circle_code or "",
            "name": circle_name,
            "elder_profile": elder_profile,
            "is_active": True,
            "created_at": now,
        }
        c = self.client
        if c is not None:
            c.collection("care_circles").document(circle_id).set(circle_data)
        else:
            _IN_MEMORY_CIRCLES[circle_id] = circle_data
        return circle_data

    async def update_elder_profile(self, circle_id: str, profile_data: Dict[str, Any]) -> Dict[str, Any]:
        """Update elder medical and emergency profile."""
        circle = await self.get_circle(circle_id)
        if not circle:
            raise ValueError(f"Circle {circle_id} not found.")
        circle["elder_profile"] = profile_data
        circle["updated_at"] = datetime.now(timezone.utc).isoformat()
        c = self.client
        if c is not None:
            c.collection("care_circles").document(circle_id).set(circle, merge=True)
        else:
            _IN_MEMORY_CIRCLES[circle_id] = circle
        return circle

    # -------------------------------------------------------------------------
    # Member Operations
    # -------------------------------------------------------------------------
    async def add_member(self, circle_id: str, member_data: Dict[str, Any]) -> Dict[str, Any]:
        """Add a member to a circle with hashed credentials."""
        context = CircleSecurityContext(circle_id)
        validated = context.validate_payload(member_data.copy())
        member_id = validated.get("member_id") or str(uuid.uuid4())
        validated["member_id"] = member_id

        c = self.client
        if c is not None:
            c.collection("circle_members").document(member_id).set(validated)
        else:
            _IN_MEMORY_MEMBERS[member_id] = validated
        return validated

    async def get_member(self, circle_id: str, member_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve member record with circle isolation."""
        if not circle_id or not member_id:
            return None
        context = CircleSecurityContext(circle_id)
        c = self.client
        if c is not None:
            doc = c.collection("circle_members").document(member_id).get()
            if not doc.exists:
                return None
            data = doc.to_dict()
            return context.validate_document(data)
        mem = _IN_MEMORY_MEMBERS.get(member_id)
        if mem:
            return context.validate_document(mem)
        return None

    async def get_member_by_id_only(self, member_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve member record by ID without prior circle knowledge (e.g. session lookup)."""
        if not member_id:
            return None
        c = self.client
        if c is not None:
            doc = c.collection("circle_members").document(member_id).get()
            return doc.to_dict() if doc.exists else None
        return _IN_MEMORY_MEMBERS.get(member_id)

    async def get_member_by_username(self, username: str) -> Optional[Dict[str, Any]]:
        """Lookup member by normalized username across all circles."""
        if not username:
            return None
        clean_user = username.strip().lower()
        c = self.client
        if c is not None:
            docs = c.collection("circle_members").where("username", "==", clean_user).limit(1).get()
            for doc in docs:
                return doc.to_dict()
            return None
        for mem in _IN_MEMORY_MEMBERS.values():
            if mem.get("username") == clean_user:
                return mem
        return None

    async def get_elder_by_name(self, circle_id: str, elder_name: str) -> Optional[Dict[str, Any]]:
        """
        Lookup elder in a specific circle by display name (Option B elder login).
        Normalizes spaces and matches case-insensitively.
        """
        if not circle_id or not elder_name:
            return None
        target_name = elder_name.strip().lower()
        c = self.client
        if c is not None:
            # Query members in circle with role elder
            docs = (
                c.collection("circle_members")
                .where("circle_id", "==", circle_id)
                .where("role", "==", MemberRole.ELDER.value)
                .get()
            )
            for doc in docs:
                data = doc.to_dict()
                disp_name = str(data.get("display_name", "")).strip().lower()
                username = str(data.get("username", "")).strip().lower()
                if disp_name == target_name or username == target_name:
                    return data
            return None

        for mem in _IN_MEMORY_MEMBERS.values():
            if mem.get("circle_id") == circle_id and mem.get("role") == MemberRole.ELDER.value:
                disp_name = str(mem.get("display_name", "")).strip().lower()
                username = str(mem.get("username", "")).strip().lower()
                if disp_name == target_name or username == target_name:
                    return mem
        return None

    async def list_members(self, circle_id: str) -> List[Dict[str, Any]]:
        """List all members belonging to a circle."""
        context = CircleSecurityContext(circle_id)
        c = self.client
        if c is not None:
            query = context.scope_query(c.collection("circle_members"))
            docs = query.get()
            return [doc.to_dict() for doc in docs]
        return [
            mem for mem in _IN_MEMORY_MEMBERS.values()
            if mem.get("circle_id") == circle_id
        ]

    async def update_member(self, circle_id: str, member_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Update a member document preserving circle isolation."""
        existing = await self.get_member(circle_id, member_id)
        if not existing:
            raise ValueError(f"Member {member_id} not found in circle {circle_id}.")
        context = CircleSecurityContext(circle_id)
        clean_update = context.validate_payload(data.copy())
        clean_update["member_id"] = member_id
        existing.update(clean_update)

        c = self.client
        if c is not None:
            c.collection("circle_members").document(member_id).set(existing, merge=True)
        else:
            _IN_MEMORY_MEMBERS[member_id] = existing
        return existing
