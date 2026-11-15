"""Doctor appointment repository interface."""
from abc import abstractmethod
from typing import Any, Dict, List
from app.repositories.base import BaseRepositoryInterface


class AppointmentRepositoryInterface(BaseRepositoryInterface):
    """Repository contract for Doctor Visits and Medical Appointments."""

    @property
    def collection_name(self) -> str:
        return "appointments"

    @abstractmethod
    async def list_upcoming_appointments(self, from_timestamp_iso: str) -> List[Dict[str, Any]]:
        """List upcoming scheduled doctor appointments."""
        pass

    @abstractmethod
    async def mark_appointment_status(self, appointment_id: str, status: str) -> Dict[str, Any]:
        """Update appointment status (scheduled, completed, cancelled)."""
        pass
