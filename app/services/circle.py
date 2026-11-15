"""Care Circle management service for Phase 4."""
import logging
from typing import Any, Dict, List, Optional
from fastapi import HTTPException, status

from app.models.auth import MemberDoc, MemberRole
from app.models.circle import (
    CircleDetailResponse,
    CircleMemberDetailResponse,
    CircleUpdateRequest,
)
from app.repositories.firestore_circle import FirestoreCircleRepository

logger = logging.getLogger("carecircle.service.circle")


class CircleService:
    """Service handling Care Circle metadata, elder profile updates, and membership roster."""

    def __init__(self, circle_repo: Optional[FirestoreCircleRepository] = None):
        self.circle_repo = circle_repo or FirestoreCircleRepository()

    async def get_circle_detail(self, circle_id: str) -> CircleDetailResponse:
        """Retrieve care circle details including active member count."""
        if not circle_id:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="circle_id is required.")

        circle = await self.circle_repo.get_circle(circle_id)
        if not circle or not circle.get("is_active", True):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Care circle not found or has been deactivated.",
            )

        members = await self.circle_repo.list_members(circle_id)
        active_count = sum(1 for m in members if m.get("is_active", True))

        return CircleDetailResponse(
            circle_id=circle["circle_id"],
            circle_code=circle.get("circle_code", ""),
            name=circle.get("name", "Care Circle"),
            elder_profile=circle.get("elder_profile", {}),
            active_member_count=active_count,
            is_active=circle.get("is_active", True),
            created_at=circle.get("created_at", ""),
            updated_at=circle.get("updated_at"),
            timezone=circle.get("timezone", "UTC"),
        )

    async def update_circle_metadata(
        self, circle_id: str, payload: CircleUpdateRequest
    ) -> CircleDetailResponse:
        """Update care circle metadata and/or elder healthcare profile."""
        circle = await self.circle_repo.get_circle(circle_id)
        if not circle or not circle.get("is_active", True):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Care circle not found or has been deactivated.",
            )

        update_dict: Dict[str, Any] = {}
        if payload.circle_name is not None:
            update_dict["name"] = payload.circle_name
        if payload.timezone is not None:
            update_dict["timezone"] = payload.timezone

        # Elder healthcare profile sub-fields
        elder_profile_updates: Dict[str, Any] = {}
        if payload.elder_name is not None:
            elder_profile_updates["name"] = payload.elder_name
            elder_profile_updates["elder_name"] = payload.elder_name
        if payload.elder_dob is not None:
            elder_profile_updates["dob"] = payload.elder_dob
            elder_profile_updates["elder_dob"] = payload.elder_dob
        if payload.primary_condition is not None:
            elder_profile_updates["primary_condition"] = payload.primary_condition
        if payload.emergency_phone is not None:
            elder_profile_updates["emergency_phone"] = payload.emergency_phone

        if elder_profile_updates:
            update_dict["elder_profile"] = elder_profile_updates

        await self.circle_repo.update_circle(circle_id, update_dict)

        # If elder name was updated, synchronize elder member's display_name
        if payload.elder_name is not None:
            members = await self.circle_repo.list_members(circle_id)
            for m in members:
                if m.get("role") == MemberRole.ELDER.value:
                    await self.circle_repo.update_member(
                        circle_id,
                        m["member_id"],
                        {"display_name": payload.elder_name},
                    )

        return await self.get_circle_detail(circle_id)

    async def list_circle_members(self, circle_id: str) -> List[CircleMemberDetailResponse]:
        """List all members belonging to a care circle, sanitized of credential hashes."""
        members = await self.circle_repo.list_members(circle_id)

        # Priority role sorting: primary caregiver first, caregivers, elders, family
        def role_sort_key(m: Dict[str, Any]) -> int:
            is_active = m.get("is_active", True)
            is_primary = m.get("is_primary", False)
            role = m.get("role", "")
            base = 0 if is_active else 100
            if is_primary:
                return base + 1
            if role == MemberRole.CAREGIVER.value:
                return base + 2
            if role == MemberRole.ELDER.value:
                return base + 3
            if role == MemberRole.FAMILY.value:
                return base + 4
            return base + 5

        sorted_members = sorted(members, key=role_sort_key)
        return [CircleMemberDetailResponse(**m) for m in sorted_members]

    async def get_circle_member(self, circle_id: str, member_id: str) -> CircleMemberDetailResponse:
        """Retrieve a single member document ensuring circle isolation."""
        from app.services.firestore import CircleIsolationViolation
        try:
            member = await self.circle_repo.get_member(circle_id, member_id)
        except CircleIsolationViolation:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Member {member_id} not found in care circle.",
            )
        if not member:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Member {member_id} not found in care circle.",
            )
        return CircleMemberDetailResponse(**member)

    async def deactivate_member(
        self,
        circle_id: str,
        requesting_member: MemberDoc,
        target_member_id: str,
    ) -> CircleMemberDetailResponse:
        """
        Deactivate a member within the circle.
        Enforces:
        - Circle isolation: target must belong to requesting member's circle.
        - Sole active primary caregiver invariant: cannot deactivate the last active primary caregiver.
        - Soft deactivation: preserves historical records, sets is_active=False.
        - Increments auth_version to invalidate target's active sessions immediately.
        """
        if requesting_member.circle_id != circle_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Security violation: member circle does not match requested circle.",
            )

        from app.services.firestore import CircleIsolationViolation
        try:
            target = await self.circle_repo.get_member(circle_id, target_member_id)
        except CircleIsolationViolation:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Member {target_member_id} not found in care circle.",
            )
        if not target:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Member {target_member_id} not found in care circle.",
            )

        # Check sole active primary caregiver invariant
        if target.get("is_primary") and target.get("is_active", True):
            active_primaries = await self.circle_repo.count_active_primary_caregivers(circle_id)
            if active_primaries <= 1:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Cannot deactivate the only active primary caregiver in the care circle.",
                )

        updated = await self.circle_repo.deactivate_member(circle_id, target_member_id)
        return CircleMemberDetailResponse(**updated)
