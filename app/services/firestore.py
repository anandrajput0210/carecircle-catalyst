"""Firestore Core Service with Server-Side Credentials, Circle Isolation, and Atomic Transactions."""
import base64
import json
import logging
from typing import Any, Callable, Dict, Optional, Tuple

from app.config import settings

logger = logging.getLogger("carecircle.firestore")

# Global instances for serverless connection reuse
_firebase_app = None
_firestore_client = None


class FirestoreConfigurationError(Exception):
    """Raised when Firestore is not configured or credentials are invalid."""
    pass


class CircleIsolationViolation(Exception):
    """Raised when an operation attempts to access or mutate cross-circle data."""
    pass


class DoseConflictError(Exception):
    """Raised when an atomic dose confirmation detects a concurrent or duplicate update."""
    def __init__(self, message: str, existing_status: str, logged_by: Optional[str] = None):
        super().__init__(message)
        self.existing_status = existing_status
        self.logged_by = logged_by


def parse_service_account_credentials() -> Optional[Dict[str, Any]]:
    """
    Parse server-side service account credentials from environment variables.
    Never exposes or returns credentials to client or public interfaces.
    """
    # 1. Check base64-encoded service account key
    b64_key = settings.FIREBASE_SERVICE_ACCOUNT_KEY_B64
    if b64_key:
        try:
            decoded = base64.b64decode(b64_key.strip()).decode("utf-8")
            return json.loads(decoded)
        except Exception as e:
            logger.error(f"Failed to decode FIREBASE_SERVICE_ACCOUNT_KEY_B64: {e}")
            raise FirestoreConfigurationError(f"Invalid base64 service account key: {e}")

    # 2. Check raw JSON string
    raw_json = settings.FIREBASE_SERVICE_ACCOUNT_JSON
    if raw_json:
        try:
            return json.loads(raw_json.strip())
        except Exception as e:
            logger.error(f"Failed to parse FIREBASE_SERVICE_ACCOUNT_JSON: {e}")
            raise FirestoreConfigurationError(f"Invalid JSON service account key: {e}")

    return None


def get_firebase_app():
    """Initialize or retrieve the Firebase Admin App singleton."""
    global _firebase_app
    if _firebase_app is not None:
        return _firebase_app

    import firebase_admin
    from firebase_admin import credentials

    # If already initialized globally by another import
    try:
        _firebase_app = firebase_admin.get_app()
        return _firebase_app
    except ValueError:
        pass  # Not yet initialized

    cred_dict = parse_service_account_credentials()
    if cred_dict:
        cred = credentials.Certificate(cred_dict)
        _firebase_app = firebase_admin.initialize_app(cred, {
            "projectId": settings.FIREBASE_PROJECT_ID,
        })
        logger.info("Firebase Admin initialized with service account certificate.")
        return _firebase_app

    # Only attempt ApplicationDefault if explicit file path or GCP environment exists
    has_gcp_env = bool(
        settings.FIREBASE_SERVICE_ACCOUNT_KEY_B64
        or settings.FIREBASE_SERVICE_ACCOUNT_JSON
    )
    # Check if standard Google ADC environment is present
    import os
    if os.getenv("GOOGLE_APPLICATION_CREDENTIALS") or os.getenv("K_SERVICE") or os.getenv("GAE_ENV"):
        try:
            cred = credentials.ApplicationDefault()
            _firebase_app = firebase_admin.initialize_app(cred, {
                "projectId": settings.FIREBASE_PROJECT_ID,
            })
            logger.info("Firebase Admin initialized with Application Default Credentials.")
            return _firebase_app
        except Exception as e:
            logger.warning(f"Failed to initialize ApplicationDefault credentials: {e}")
            return None

    logger.info("No Firebase credentials provided. Operating in unconfigured/offline mode.")
    return None


def get_firestore_client():
    """Retrieve the Firestore Client singleton for serverless connection reuse."""
    global _firestore_client
    if _firestore_client is not None:
        return _firestore_client

    app = get_firebase_app()
    if app is None:
        return None

    from firebase_admin import firestore
    _firestore_client = firestore.client(app=app)
    return _firestore_client


def verify_firestore_health() -> Dict[str, Any]:
    """Verify Firestore connection health and readiness."""
    try:
        client = get_firestore_client()
        if client is None:
            return {
                "configured": False,
                "status": "unconfigured",
                "message": "Firebase credentials not provided. Running in offline/preview mode.",
            }

        # Attempt a shallow read on care_circles collection with limit 1 (Spark-friendly: 1 read)
        client.collection("care_circles").limit(1).get()
        return {
            "configured": True,
            "status": "connected",
            "project_id": settings.FIREBASE_PROJECT_ID,
        }
    except Exception as e:
        logger.error(f"Firestore health check failed: {e}")
        return {
            "configured": True,
            "status": "error",
            "error": str(e),
        }


# ============================================================================
# Circle Isolation Security Helpers
# ============================================================================

def make_deterministic_dose_id(circle_id: str, med_id: str, scheduled_date: str, scheduled_time: str) -> str:
    """
    Generate an immutable, deterministic dose ledger document ID.
    Format: {circle_id}_{med_id}_{YYYY-MM-DD}_{HH-MM}
    Ensures idempotent creation and prevents race-condition duplicate dosing.
    """
    if not circle_id or not med_id or not scheduled_date or not scheduled_time:
        raise ValueError("circle_id, med_id, scheduled_date, and scheduled_time are required")
    
    clean_circle = str(circle_id).strip().replace("/", "_")
    clean_med = str(med_id).strip().replace("/", "_")
    clean_date = str(scheduled_date).strip().replace("/", "-")
    clean_time = str(scheduled_time).strip().replace(":", "-").replace("/", "-")
    return f"{clean_circle}_{clean_med}_{clean_date}_{clean_time}"


class CircleSecurityContext:
    """
    Enforces circle-level data isolation on all Firestore operations.
    Validates that queries and document payloads belong strictly to the authenticated circle.
    """

    def __init__(self, circle_id: str):
        if not circle_id or not str(circle_id).strip():
            raise CircleIsolationViolation("A valid, non-empty circle_id is strictly required.")
        self.circle_id = str(circle_id).strip()

    def validate_payload(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Verify that a document payload explicitly belongs to this circle."""
        payload_circle = data.get("circle_id")
        if payload_circle and str(payload_circle).strip() != self.circle_id:
            raise CircleIsolationViolation(
                f"Circle isolation breach: Payload circle_id '{payload_circle}' does not match "
                f"authenticated circle_id '{self.circle_id}'."
            )
        data["circle_id"] = self.circle_id
        return data

    def validate_document(self, doc_data: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """Verify that a retrieved document belongs strictly to this circle."""
        if not doc_data:
            raise CircleIsolationViolation("Cannot validate an empty document.")
        
        doc_circle = doc_data.get("circle_id")
        if str(doc_circle).strip() != self.circle_id:
            raise CircleIsolationViolation(
                f"Cross-circle access blocked: Document belongs to circle '{doc_circle}', "
                f"not '{self.circle_id}'."
            )
        return doc_data

    def scope_query(self, collection_ref):
        """Mandates WHERE circle_id == self.circle_id on any Firestore collection query."""
        return collection_ref.where("circle_id", "==", self.circle_id)


# ============================================================================
# Atomic Transaction Wrappers
# ============================================================================

def execute_atomic_dose_confirmation(
    transaction,
    dose_ref,
    logged_by_member_id: str,
    logged_by_name: str,
    logged_by_role: str,
    notes: Optional[str] = None,
    server_timestamp: Any = None,
) -> Dict[str, Any]:
    """
    Execute atomic dose confirmation inside a Firestore transaction.
    
    Guarantees:
    - Atomically checks if status is 'pending'.
    - If 'pending', transitions status to 'taken' with member audit data.
    - If not 'pending' (e.g. already 'taken', 'skipped'), raises DoseConflictError.
    - Duplicate confirmations are blocked atomically with zero race conditions.
    """
    snapshot = dose_ref.get(transaction=transaction)
    if not snapshot.exists:
        raise DoseConflictError(
            message="Dose ledger record does not exist for confirmation.",
            existing_status="missing"
        )

    current_data = snapshot.to_dict() or {}
    current_status = current_data.get("status", "pending")

    if current_status != "pending":
        already_by = current_data.get("logged_by_name", "another member")
        already_at = current_data.get("logged_at", "earlier")
        raise DoseConflictError(
            message=f"Dose was already recorded as '{current_status}' by {already_by} at {already_at}.",
            existing_status=current_status,
            logged_by=already_by,
        )

    # Perform atomic update
    update_data = {
        "status": "taken",
        "logged_by_member_id": logged_by_member_id,
        "logged_by_name": logged_by_name,
        "logged_by_role": logged_by_role,
        "notes": notes or "",
    }
    if server_timestamp is not None:
        update_data["logged_at"] = server_timestamp

    transaction.update(dose_ref, update_data)
    current_data.update(update_data)
    return current_data
