"""Medication repository interface."""
from abc import abstractmethod
from typing import Any, Dict, List, Optional
from app.repositories.base import BaseRepositoryInterface


class MedicationRepositoryInterface(BaseRepositoryInterface):
    """Repository contract for Medication Regimens and Schedules."""

    @property
    def collection_name(self) -> str:
        return "medications"

    @abstractmethod
    async def list_active_medications(self) -> List[Dict[str, Any]]:
        """List active medications for the circle."""
        pass

    @abstractmethod
    async def set_active_status(
        self, med_id: str, is_active: bool, circle_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """Activate or deactivate a medication regimen."""
        pass

    @abstractmethod
    async def set_paused_status(
        self, med_id: str, is_paused: bool, circle_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """Pause or resume a medication regimen."""
        pass
