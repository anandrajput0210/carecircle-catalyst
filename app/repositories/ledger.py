"""Dose Ledger repository interface."""
from abc import abstractmethod
from typing import Any, Dict, List, Optional
from app.repositories.base import BaseRepositoryInterface


class DoseLedgerRepositoryInterface(BaseRepositoryInterface):
    """Repository contract for Shared Dose Ledger records."""

    @property
    def collection_name(self) -> str:
        return "dose_ledger"

    @abstractmethod
    async def get_dose(self, dose_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve dose record by deterministic dose ID."""
        pass

    @abstractmethod
    async def confirm_dose_atomic(
        self,
        dose_id: str,
        logged_by_member_id: str,
        logged_by_name: str,
        logged_by_role: str,
        notes: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Atomically confirm a dose, preventing duplicate logging."""
        pass

    @abstractmethod
    async def list_doses_for_date(self, target_date: str) -> List[Dict[str, Any]]:
        """List dose records for a specific date (YYYY-MM-DD)."""
        pass

    @abstractmethod
    async def list_pending_overdue_doses(self, overdue_threshold_iso: str) -> List[Dict[str, Any]]:
        """Query pending doses that have passed the scheduled time + grace period."""
        pass
