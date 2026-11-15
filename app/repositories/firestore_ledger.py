"""Firestore repository implementation for Shared Dose Ledger."""
from datetime import datetime, timezone
import logging
import threading
from typing import Any, Dict, List, Optional

from app.config import settings
from app.repositories.ledger import DoseLedgerRepositoryInterface
from app.services.firestore import (
    CircleIsolationViolation,
    CircleSecurityContext,
    DoseConflictError,
    FirestoreConfigurationError,
    execute_atomic_dose_confirmation,
    get_firestore_client,
)

logger = logging.getLogger("carecircle.repository.ledger")

_IN_MEMORY_DOSES: Dict[str, Dict[str, Any]] = {}
_IN_MEMORY_LEDGER = _IN_MEMORY_DOSES
_LEDGER_LOCK = threading.Lock()


class FirestoreDoseLedgerRepository(DoseLedgerRepositoryInterface):
    """
    Concrete implementation of DoseLedgerRepositoryInterface backed by Cloud Firestore
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
            raise ValueError("circle_id is required for dose ledger repository operations.")
        return CircleSecurityContext(cid)

    # -------------------------------------------------------------------------
    # BaseRepositoryInterface implementations
    # -------------------------------------------------------------------------

    async def get_by_id(self, doc_id: str) -> Optional[Dict[str, Any]]:
        context = self._get_context()
        return await self.get_dose(doc_id, circle_id=context.circle_id)

    async def list_for_circle(self, limit: int = 100) -> List[Dict[str, Any]]:
        context = self._get_context()
        return await self.list_dose_history(context.circle_id, limit=limit)

    async def create(self, doc_id: Optional[str], data: Dict[str, Any]) -> Dict[str, Any]:
        context = self._get_context()
        validated = context.validate_payload(data.copy())
        target_id = doc_id or validated.get("dose_id")
        if not target_id:
            raise ValueError("dose_id is required for dose ledger creation.")
        validated["dose_id"] = target_id

        c = self.client
        if c is not None:
            c.collection(self.collection_name).document(target_id).set(validated)
        else:
            with _LEDGER_LOCK:
                _IN_MEMORY_DOSES[target_id] = validated.copy()
        return validated

    async def update(self, doc_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        raise NotImplementedError("Dose ledger records are append-only and immutable. Direct updates are prohibited.")

    async def delete(self, doc_id: str) -> bool:
        raise NotImplementedError("Dose ledger records are permanent audit logs. Physical deletion is prohibited.")

    # -------------------------------------------------------------------------
    # DoseLedgerRepositoryInterface implementations
    # -------------------------------------------------------------------------

    async def get_dose(self, dose_id: str, circle_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Retrieve dose record by deterministic dose ID with circle isolation."""
        if not dose_id:
            return None
        context = self._get_context(circle_id)
        c = self.client
        if c is not None:
            doc = c.collection(self.collection_name).document(dose_id).get()
            if not doc.exists:
                return None
            return context.validate_document(doc.to_dict())

        with _LEDGER_LOCK:
            d = _IN_MEMORY_DOSES.get(dose_id)
            if d:
                return context.validate_document(d.copy())
        return None

    async def confirm_dose_atomic(
        self,
        dose_id: str,
        logged_by_member_id: str,
        logged_by_name: str,
        logged_by_role: str,
        notes: Optional[str] = None,
        circle_id: Optional[str] = None,
        initial_dose_meta: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Atomically confirm a dose occurrence.
        Strict invariant: An occurrence must never receive two successful confirmations.
        If already taken, raises DoseConflictError.
        """
        context = self._get_context(circle_id)
        c = self.client
        now_iso = datetime.now(timezone.utc).isoformat()

        if c is not None:
            from google.cloud import firestore

            dose_ref = c.collection(self.collection_name).document(dose_id)
            transaction = c.transaction()

            @firestore.transactional
            def _transact_dose(txn):
                snapshot = dose_ref.get(transaction=txn)
                if not snapshot.exists:
                    # If document does not exist yet, prepare initial pending record
                    meta = initial_dose_meta or {}
                    initial_record = {
                        "dose_id": dose_id,
                        "circle_id": context.circle_id,
                        "status": "pending",
                        "created_at": now_iso,
                        **meta,
                    }
                    txn.set(dose_ref, initial_record)

                # Now execute standard atomic confirmation verification
                return execute_atomic_dose_confirmation(
                    transaction=txn,
                    dose_ref=dose_ref,
                    logged_by_member_id=logged_by_member_id,
                    logged_by_name=logged_by_name,
                    logged_by_role=logged_by_role,
                    notes=notes,
                    server_timestamp=now_iso,
                )

            return _transact_dose(transaction)

        # Thread-safe in-memory transaction
        with _LEDGER_LOCK:
            existing = _IN_MEMORY_DOSES.get(dose_id)
            if existing is not None:
                context.validate_document(existing)
                current_status = existing.get("status", "pending")
                if current_status != "pending":
                    already_by = existing.get("logged_by_name", "another member")
                    already_at = existing.get("logged_at", "earlier")
                    raise DoseConflictError(
                        message=f"Dose was already recorded as '{current_status}' by {already_by} at {already_at}.",
                        existing_status=current_status,
                        logged_by=already_by,
                    )
                # Transition status to taken
                existing["status"] = "taken"
                existing["logged_by_member_id"] = logged_by_member_id
                existing["logged_by_name"] = logged_by_name
                existing["logged_by_role"] = logged_by_role
                existing["logged_at"] = now_iso
                existing["confirmed_by_name"] = logged_by_name
                existing["confirmed_by_role"] = logged_by_role
                existing["recorded_at"] = now_iso
                existing["confirmed_method"] = "administered" if notes and "admin" in notes.lower() else "observed"
                existing["notes"] = notes or ""
                return existing.copy()

            # Record does not exist yet: create directly as taken
            meta = initial_dose_meta or {}
            new_record = {
                "dose_id": dose_id,
                "circle_id": context.circle_id,
                "status": "taken",
                "logged_by_member_id": logged_by_member_id,
                "logged_by_name": logged_by_name,
                "logged_by_role": logged_by_role,
                "logged_at": now_iso,
                "confirmed_by_name": logged_by_name,
                "confirmed_by_role": logged_by_role,
                "recorded_at": now_iso,
                "confirmed_method": "administered" if notes and "admin" in notes.lower() else "observed",
                "notes": notes or "",
                **meta,
            }
            context.validate_payload(new_record)
            _IN_MEMORY_DOSES[dose_id] = new_record.copy()
            return new_record.copy()

    async def list_doses_for_date(
        self, target_date: str, circle_id: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """List dose records for a specific date (YYYY-MM-DD) within the circle."""
        context = self._get_context(circle_id)
        c = self.client
        if c is not None:
            query = (
                context.scope_query(c.collection(self.collection_name))
                .where("scheduled_date", "==", target_date)
            )
            docs = query.get()
            return [doc.to_dict() for doc in docs]

        with _LEDGER_LOCK:
            results = []
            for d in _IN_MEMORY_DOSES.values():
                if d.get("circle_id") == context.circle_id and d.get("scheduled_date") == target_date:
                    results.append(d.copy())
            return results

    async def list_dose_history(
        self, circle_id: str, limit: int = 50
    ) -> List[Dict[str, Any]]:
        """List dose ledger audit history ordered by confirmation timestamp (bounded to limit)."""
        context = self._get_context(circle_id)
        c = self.client
        if c is not None:
            query = (
                context.scope_query(c.collection(self.collection_name))
                .where("status", "==", "taken")
                .limit(limit)
            )
            docs = query.get()
            results = [doc.to_dict() for doc in docs]
            results.sort(key=lambda x: x.get("logged_at", ""), reverse=True)
            return results[:limit]

        with _LEDGER_LOCK:
            results = []
            for d in _IN_MEMORY_DOSES.values():
                if d.get("circle_id") == circle_id and d.get("status") == "taken":
                    results.append(d.copy())
            results.sort(key=lambda x: x.get("logged_at", ""), reverse=True)
            return results[:limit]

    async def list_pending_overdue_doses(
        self, overdue_threshold_iso: str, circle_id: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Query pending doses that have passed the scheduled time threshold."""
        context = self._get_context(circle_id)
        c = self.client
        if c is not None:
            query = (
                context.scope_query(c.collection(self.collection_name))
                .where("status", "==", "pending")
                .where("scheduled_datetime_utc", "<=", overdue_threshold_iso)
                .limit(50)
            )
            docs = query.get()
            return [doc.to_dict() for doc in docs]

        with _LEDGER_LOCK:
            results = []
            for d in _IN_MEMORY_DOSES.values():
                if (
                    d.get("circle_id") == context.circle_id
                    and d.get("status") == "pending"
                    and d.get("scheduled_datetime_utc", "") <= overdue_threshold_iso
                ):
                    results.append(d.copy())
            return results
