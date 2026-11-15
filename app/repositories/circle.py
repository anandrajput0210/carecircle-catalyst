"""Circle and Elder Healthcare Profile repository interface."""
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional


class CircleRepositoryInterface(ABC):
    """Repository contract for Care Circles, Elder Profiles, and Circle Members."""

    @abstractmethod
    async def get_circle(self, circle_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve circle document by circle ID."""
        pass

    @abstractmethod
    async def create_circle(self, circle_id: str, circle_name: str, elder_profile: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new Care Circle with elder healthcare profile."""
        pass

    @abstractmethod
    async def update_elder_profile(self, circle_id: str, profile_data: Dict[str, Any]) -> Dict[str, Any]:
        """Update elder medical and emergency profile."""
        pass

    @abstractmethod
    async def add_member(self, circle_id: str, member_data: Dict[str, Any]) -> Dict[str, Any]:
        """Add a member (elder, caregiver, family) with hashed credentials."""
        pass

    @abstractmethod
    async def get_member(self, circle_id: str, member_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve member record with circle isolation."""
        pass

    @abstractmethod
    async def list_members(self, circle_id: str) -> List[Dict[str, Any]]:
        """List all members belonging to a circle."""
        pass
