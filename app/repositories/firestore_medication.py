"""Firestore repository implementation for Medication Regimens."""
from datetime import datetime, timezone
import logging
import threading
from typing import Any, Dict, List, Optional
import uuid

from app.config import settings
from app.repositories.medication import MedicationRepositoryInterface
from app.services.firestore import (
    CircleIsolationViolation,
    CircleSecurityContext,
    FirestoreConfigurationError,
    get_firestore_client,
)

logger = logging.getLogger("carecircle.repository.medication")

_IN_MEMORY_MEDICATIONS: Dict[str, Dict[str, Any]] = {}
_MED_LOCK = threading.Lock()


class FirestoreMedicationRepository(MedicationRepositoryInterface):
    """
    Concrete implementation of MedicationRepositoryInterface backed by Cloud Firestore
    with automatic thread-safe in-memory fallback for offline test environments.
    """

    def __init__(self, circle_context: Optional[CircleSecurityContext] = None, client: Optional[Any] = None):
        if circle_context is not None:
            super().__init__(circle_context)
        else:
            self.context = None
            self.circle_id = None
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

    def _get_context(self, circle_id: Optional[str] = None) -> CircleSecurityContext:
        cid = circle_id or self.circle_id
        if not cid:
            raise ValueError("circle_id is required for medication repository operations.")
        return CircleSecurityContext(cid)

    # -------------------------------------------------------------------------
    # BaseRepositoryInterface implementations
    # -------------------------------------------------------------------------

    async def get_by_id(self, doc_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve medication by ID verifying circle isolation."""
        context = self._get_context()
        return await self.get_medication(context.circle_id, doc_id)

    async def list_for_circle(self, limit: int = 100) -> List[Dict[str, Any]]:
        """List medications for the configured circle context."""
        context = self._get_context()
        return await self.list_medications(context.circle_id, active_only=False, limit=limit)

    async def create(self, doc_id: Optional[str], data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a medication document ensuring circle payload isolation."""
        context = self._get_context()
        return await self.create_medication(context.circle_id, data, med_id=doc_id)

    async def update(self, doc_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Update a medication document ensuring circle payload isolation."""
        context = self._get_context()
        return await self.update_medication(context.circle_id, doc_id, data)

    async def delete(self, doc_id: str) -> bool:
        """Soft-deactivate rather than physical deletion to preserve medical history."""
        context = self._get_context()
        res = await self.set_active_status(doc_id, is_active=False)
        return bool(res)

    async def list_active_medications(self) -> List[Dict[str, Any]]:
        """List active medications for the configured circle context."""
        context = self._get_context()
        return await self.list_medications(context.circle_id, active_only=True)

    async def set_active_status(
        self, med_id: str, is_active: bool, circle_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """Activate or deactivate a medication regimen."""
        context = self._get_context(circle_id)
        return await self.update_medication(context.circle_id, med_id, {"is_active": is_active})

    async def set_paused_status(
        self, med_id: str, is_paused: bool, circle_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """Pause or resume a medication regimen."""
        context = self._get_context(circle_id)
        return await self.update_medication(context.circle_id, med_id, {"is_paused": is_paused})

    # -------------------------------------------------------------------------
    # Direct Scoped Operations (Reusable across services)
    # -------------------------------------------------------------------------

    async def create_medication(
        self, circle_id: str, data: Dict[str, Any], med_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """Create a new medication regimen within a circle."""
        context = self._get_context(circle_id)
        validated = context.validate_payload(data.copy())
        validated_id = med_id or validated.get("med_id") or str(uuid.uuid4())
        validated["med_id"] = validated_id
        if "created_at" not in validated:
            validated["created_at"] = datetime.now(timezone.utc).isoformat()

        c = self.client
        if c is not None:
            c.collection(self.collection_name).document(validated_id).set(validated)
        else:
            with _MED_LOCK:
                _IN_MEMORY_MEDICATIONS[validated_id] = validated.copy()
        return validated

    async def get_medication(self, circle_id: str, med_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve single medication document enforcing circle isolation."""
        if not circle_id or not med_id:
            return None
        context = self._get_context(circle_id)
        c = self.client
        if c is not None:
            doc = c.collection(self.collection_name).document(med_id).get()
            if not doc.exists:
                return None
            return context.validate_document(doc.to_dict())

        with _MED_LOCK:
            m = _IN_MEMORY_MEDICATIONS.get(med_id)
            if m:
                return context.validate_document(m.copy())
        return None

    async def list_medications(
        self, circle_id: str, active_only: bool = True, limit: int = 100
    ) -> List[Dict[str, Any]]:
        """List medications for a circle with optional active filtering and query bounding."""
        context = self._get_context(circle_id)
        c = self.client
        if c is not None:
            query = context.scope_query(c.collection(self.collection_name))
            if active_only:
                query = query.where("is_active", "==", True)
            query = query.limit(limit)
            docs = query.get()
            return [doc.to_dict() for doc in docs]

        with _MED_LOCK:
            results = []
            for m in _IN_MEMORY_MEDICATIONS.values():
                if m.get("circle_id") == circle_id:
                    if not active_only or m.get("is_active", True) is True:
                        results.append(m.copy())
            return results[:limit]

    async def update_medication(
        self, circle_id: str, med_id: str, data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Update a medication document ensuring circle isolation."""
        existing = await self.get_medication(circle_id, med_id)
        if not existing:
            raise ValueError(f"Medication {med_id} not found in circle {circle_id}.")

        context = self._get_context(circle_id)
        clean_update = context.validate_payload(data.copy())
        clean_update["med_id"] = med_id
        clean_update["updated_at"] = datetime.now(timezone.utc).isoformat()
        existing.update(clean_update)

        c = self.client
        if c is not None:
            c.collection(self.collection_name).document(med_id).set(existing, merge=True)
        else:
            with _MED_LOCK:
                _IN_MEMORY_MEDICATIONS[med_id] = existing.copy()
        return existing
