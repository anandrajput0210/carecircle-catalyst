"""Caregiver escalation repository interface."""
from abc import abstractmethod
from typing import Any, Dict, List
from app.repositories.base import BaseRepositoryInterface


class EscalationRepositoryInterface(BaseRepositoryInterface):
    """Repository contract for Missed-Dose Caregiver Escalation records."""

    @property
    def collection_name(self) -> str:
        return "escalations"

    @abstractmethod
    async def create_escalation_idempotent(
        self,
        dose_id: str,
        med_name: str,
        scheduled_time_iso: str,
        elapsed_minutes: int,
        delivery_channel: str = "IN_APP_ONLY",
        email_status: str = "UNCONFIGURED",
    ) -> Dict[str, Any]:
        """Idempotently create or update an escalation alert."""
        pass

    @abstractmethod
    async def list_active_escalations(self) -> List[Dict[str, Any]]:
        """List unacknowledged or pending escalations for the circle."""
        pass

    @abstractmethod
    async def acknowledge_escalation(self, escalation_id: str, acknowledged_by_member_id: str) -> Dict[str, Any]:
        """Acknowledge and mark an escalation as resolved."""
        pass
