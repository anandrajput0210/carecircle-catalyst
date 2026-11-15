"""Care Circle invitation repository interface."""
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Tuple


class InvitationRepositoryInterface(ABC):
    """Repository contract for Care Circle invitations."""

    @abstractmethod
    async def create_invitation(self, invitation_data: Dict[str, Any]) -> Dict[str, Any]:
        """Store a new invitation document."""
        pass

    @abstractmethod
    async def get_invitation_by_token_hash(self, token_hash: str) -> Optional[Dict[str, Any]]:
        """Retrieve an invitation by the SHA-256 hash of its token."""
        pass

    @abstractmethod
    async def get_invitation_by_id(self, circle_id: str, invitation_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve an invitation by ID ensuring circle isolation."""
        pass

    @abstractmethod
    async def list_invitations_for_circle(
        self, circle_id: str, status_filter: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """List invitations for a care circle with optional status filter."""
        pass

    @abstractmethod
    async def revoke_invitation(
        self, circle_id: str, invitation_id: str, revoked_by: str
    ) -> Optional[Dict[str, Any]]:
        """Mark an invitation as revoked."""
        pass

    @abstractmethod
    async def redeem_invitation_atomically(
        self, token_hash: str, new_member_data: Dict[str, Any]
    ) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        """
        Atomically redeem an invitation and create the new circle member.
        Preconditions:
        - Password hashing must be completed beforehand.
        - Must verify invitation is pending and not expired.
        Returns:
            Tuple of (updated_invitation_dict, created_member_dict).
        """
        pass
