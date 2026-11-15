"""Firestore repository implementation for Care Circle invitations."""
from datetime import datetime, timezone
import logging
import threading
from typing import Any, Dict, List, Optional, Tuple

from app.config import settings
from app.repositories.firestore_circle import _IN_MEMORY_MEMBERS
from app.repositories.invitation import InvitationRepositoryInterface
from app.services.firestore import (
    CircleIsolationViolation,
    CircleSecurityContext,
    FirestoreConfigurationError,
    get_firestore_client,
)

logger = logging.getLogger("carecircle.repository.invitation")

# In-memory store fallback when Firestore client is unconfigured/offline
_IN_MEMORY_INVITATIONS: Dict[str, Dict[str, Any]] = {}
_INVITATION_LOCK = threading.Lock()


class FirestoreInvitationRepository(InvitationRepositoryInterface):
    """
    Concrete implementation of InvitationRepositoryInterface backed by Cloud Firestore
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

    async def create_invitation(self, invitation_data: Dict[str, Any]) -> Dict[str, Any]:
        """Store a new invitation document."""
        circle_id = invitation_data.get("circle_id")
        if not circle_id:
            raise ValueError("circle_id is required for invitation.")
        invitation_id = invitation_data.get("invitation_id")
        if not invitation_id:
            raise ValueError("invitation_id is required.")

        context = CircleSecurityContext(circle_id)
        validated = context.validate_payload(invitation_data.copy())

        c = self.client
        if c is not None:
            c.collection("circle_invitations").document(invitation_id).set(validated)
        else:
            with _INVITATION_LOCK:
                _IN_MEMORY_INVITATIONS[invitation_id] = validated
        return validated

    async def get_invitation_by_token_hash(self, token_hash: str) -> Optional[Dict[str, Any]]:
        """Retrieve an invitation by the SHA-256 hash of its token."""
        if not token_hash:
            return None
        c = self.client
        if c is not None:
            docs = (
                c.collection("circle_invitations")
                .where("token_hash", "==", token_hash)
                .limit(1)
                .get()
            )
            for doc in docs:
                return doc.to_dict()
            return None

        with _INVITATION_LOCK:
            for inv in _IN_MEMORY_INVITATIONS.values():
                if inv.get("token_hash") == token_hash:
                    return inv.copy()
        return None

    async def get_invitation_by_id(self, circle_id: str, invitation_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve an invitation by ID ensuring circle isolation."""
        if not circle_id or not invitation_id:
            return None
        context = CircleSecurityContext(circle_id)
        c = self.client
        if c is not None:
            doc = c.collection("circle_invitations").document(invitation_id).get()
            if not doc.exists:
                return None
            return context.validate_document(doc.to_dict())

        with _INVITATION_LOCK:
            inv = _IN_MEMORY_INVITATIONS.get(invitation_id)
            if inv:
                return context.validate_document(inv.copy())
        return None

    async def list_invitations_for_circle(
        self, circle_id: str, status_filter: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """List invitations for a care circle with optional status filter."""
        if not circle_id:
            return []
        context = CircleSecurityContext(circle_id)
        c = self.client
        if c is not None:
            query = context.scope_query(c.collection("circle_invitations"))
            if status_filter:
                query = query.where("status", "==", status_filter)
            docs = query.get()
            return [doc.to_dict() for doc in docs]

        with _INVITATION_LOCK:
            results = []
            for inv in _IN_MEMORY_INVITATIONS.values():
                if inv.get("circle_id") == circle_id:
                    if status_filter is None or inv.get("status") == status_filter:
                        results.append(inv.copy())
            return results

    async def revoke_invitation(
        self, circle_id: str, invitation_id: str, revoked_by: str
    ) -> Optional[Dict[str, Any]]:
        """Mark an invitation as revoked."""
        inv = await self.get_invitation_by_id(circle_id, invitation_id)
        if not inv:
            return None
        if inv.get("status") != "pending":
            return inv

        now = datetime.now(timezone.utc).isoformat()
        inv["status"] = "revoked"
        inv["revoked_at"] = now
        inv["revoked_by"] = revoked_by

        c = self.client
        if c is not None:
            c.collection("circle_invitations").document(invitation_id).set(inv, merge=True)
        else:
            with _INVITATION_LOCK:
                _IN_MEMORY_INVITATIONS[invitation_id] = inv
        return inv

    async def redeem_invitation_atomically(
        self, token_hash: str, new_member_data: Dict[str, Any]
    ) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        """
        Atomically redeem an invitation and create the new circle member.
        Precondition: Password hashing must be done outside this call.
        """
        if not token_hash:
            raise ValueError("Token hash cannot be empty.")
        member_id = new_member_data.get("member_id")
        if not member_id:
            raise ValueError("member_id is required in new_member_data.")

        now_iso = datetime.now(timezone.utc).isoformat()
        c = self.client

        if c is not None:
            # Query the invitation outside the transaction to obtain its document reference
            docs = (
                c.collection("circle_invitations")
                .where("token_hash", "==", token_hash)
                .limit(1)
                .get()
            )
            inv_doc = None
            for d in docs:
                inv_doc = d
                break
            if not inv_doc:
                raise ValueError("Invitation not found.")

            invitation_id = inv_doc.id
            invite_ref = c.collection("circle_invitations").document(invitation_id)
            member_ref = c.collection("circle_members").document(member_id)

            transaction = c.transaction()

            from google.cloud import firestore

            @firestore.transactional
            def _transact_redemption(txn, i_ref, m_ref, m_data, now_ts):
                snapshot = i_ref.get(transaction=txn)
                if not snapshot.exists:
                    raise ValueError("Invitation does not exist.")
                current_inv = snapshot.to_dict()
                if current_inv.get("status") != "pending":
                    raise ValueError(f"Invitation is no longer pending (current: {current_inv.get('status')}).")
                
                # Check expiration
                expires_at = current_inv.get("expires_at")
                if expires_at and expires_at < now_ts:
                    txn.update(i_ref, {"status": "expired"})
                    raise ValueError("Invitation has expired.")

                update_fields = {
                    "status": "accepted",
                    "accepted_at": now_ts,
                    "accepted_by": m_data["member_id"],
                }
                txn.update(i_ref, update_fields)
                txn.set(m_ref, m_data)

                current_inv.update(update_fields)
                return current_inv, m_data

            return _transact_redemption(transaction, invite_ref, member_ref, new_member_data, now_iso)

        # In-memory transaction with threading lock
        with _INVITATION_LOCK:
            target_inv = None
            for inv in _IN_MEMORY_INVITATIONS.values():
                if inv.get("token_hash") == token_hash:
                    target_inv = inv
                    break
            if not target_inv:
                raise ValueError("Invitation not found.")

            if target_inv.get("status") != "pending":
                raise ValueError(f"Invitation is no longer pending (current: {target_inv.get('status')}).")

            expires_at = target_inv.get("expires_at")
            if expires_at and expires_at < now_iso:
                target_inv["status"] = "expired"
                raise ValueError("Invitation has expired.")

            # Update invitation
            target_inv["status"] = "accepted"
            target_inv["accepted_at"] = now_iso
            target_inv["accepted_by"] = member_id

            # Save new member
            _IN_MEMORY_MEMBERS[member_id] = new_member_data

            return target_inv.copy(), new_member_data.copy()
