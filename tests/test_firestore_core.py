"""Unit tests for Phase 2: Configuration, Firestore Core, Circle Isolation, and Atomic Transactions."""
import base64
import json
import pytest
from unittest.mock import MagicMock
from fastapi.testclient import TestClient

from app.config import settings, _detect_environment
from app.main import app
from app.services.firestore import (
    parse_service_account_credentials,
    verify_firestore_health,
    make_deterministic_dose_id,
    CircleSecurityContext,
    CircleIsolationViolation,
    execute_atomic_dose_confirmation,
    DoseConflictError,
    FirestoreConfigurationError,
)
from app.repositories import (
    BaseRepositoryInterface,
    CircleRepositoryInterface,
    MedicationRepositoryInterface,
    DoseLedgerRepositoryInterface,
    AppointmentRepositoryInterface,
    EscalationRepositoryInterface,
)

client = TestClient(app)


# ============================================================================
# 1. Environment Detection Tests
# ============================================================================

def test_environment_detection_vercel_production(monkeypatch):
    """Verify that VERCEL_ENV=production is correctly detected."""
    monkeypatch.setenv("VERCEL_ENV", "production")
    assert _detect_environment() == "production"


def test_environment_detection_local_default(monkeypatch):
    """Verify that unconfigured environment defaults to development."""
    monkeypatch.delenv("VERCEL_ENV", raising=False)
    monkeypatch.setenv("ENVIRONMENT", "development")
    assert _detect_environment() == "development"


# ============================================================================
# 2. Credential Parsing Tests
# ============================================================================

def test_parse_credentials_missing(monkeypatch):
    """Verify that absent credentials return None without crashing."""
    monkeypatch.setattr(settings, "FIREBASE_SERVICE_ACCOUNT_KEY_B64", "")
    monkeypatch.setattr(settings, "FIREBASE_SERVICE_ACCOUNT_JSON", "")
    creds = parse_service_account_credentials()
    assert creds is None


def test_parse_credentials_valid_base64(monkeypatch):
    """Verify that valid base64 service account JSON is properly parsed."""
    fake_creds = {"type": "service_account", "project_id": "test-carecircle"}
    b64_str = base64.b64encode(json.dumps(fake_creds).encode("utf-8")).decode("utf-8")
    monkeypatch.setattr(settings, "FIREBASE_SERVICE_ACCOUNT_KEY_B64", b64_str)
    
    parsed = parse_service_account_credentials()
    assert parsed == fake_creds


def test_parse_credentials_invalid_base64(monkeypatch):
    """Verify that corrupted base64 string raises FirestoreConfigurationError."""
    monkeypatch.setattr(settings, "FIREBASE_SERVICE_ACCOUNT_KEY_B64", "!!!not-valid-base64!!!")
    with pytest.raises(FirestoreConfigurationError):
        parse_service_account_credentials()


def test_parse_credentials_valid_json(monkeypatch):
    """Verify that raw JSON service account string is parsed."""
    monkeypatch.setattr(settings, "FIREBASE_SERVICE_ACCOUNT_KEY_B64", "")
    fake_creds = {"type": "service_account", "project_id": "test-json"}
    monkeypatch.setattr(settings, "FIREBASE_SERVICE_ACCOUNT_JSON", json.dumps(fake_creds))
    
    parsed = parse_service_account_credentials()
    assert parsed == fake_creds


def test_verify_firestore_health_unconfigured(monkeypatch):
    """Verify health check reports unconfigured when no credentials are provided."""
    monkeypatch.setattr("app.services.firestore.get_firestore_client", lambda: None)
    health = verify_firestore_health()
    assert health["configured"] is False
    assert health["status"] == "unconfigured"


# ============================================================================
# 3. Circle Isolation Tests
# ============================================================================

def test_circle_security_context_empty_id():
    """Verify that an empty or whitespace circle_id is rejected."""
    with pytest.raises(CircleIsolationViolation):
        CircleSecurityContext("")
    with pytest.raises(CircleIsolationViolation):
        CircleSecurityContext("   ")


def test_circle_security_context_validate_payload():
    """Verify that payload circle_id matches authenticated circle."""
    ctx = CircleSecurityContext("circle-alpha")

    # Injects circle_id if absent
    data = {"med_name": "Lisinopril"}
    validated = ctx.validate_payload(data)
    assert validated["circle_id"] == "circle-alpha"

    # Accepts matching circle_id
    data_matching = {"circle_id": "circle-alpha", "med_name": "Metformin"}
    assert ctx.validate_payload(data_matching)["circle_id"] == "circle-alpha"

    # Rejects mismatched cross-circle payload
    data_mismatched = {"circle_id": "circle-beta", "med_name": "Amlodipine"}
    with pytest.raises(CircleIsolationViolation):
        ctx.validate_payload(data_mismatched)


def test_circle_security_context_validate_document():
    """Verify that retrieved documents belonging to another circle are blocked."""
    ctx = CircleSecurityContext("circle-alpha")

    # Valid matching document
    valid_doc = {"circle_id": "circle-alpha", "name": "Eleanor"}
    assert ctx.validate_document(valid_doc) == valid_doc

    # Cross-circle document leakage attempt
    leaked_doc = {"circle_id": "circle-beta", "name": "Arthur"}
    with pytest.raises(CircleIsolationViolation):
        ctx.validate_document(leaked_doc)

    # Empty document validation
    with pytest.raises(CircleIsolationViolation):
        ctx.validate_document(None)


def test_deterministic_dose_id_generation():
    """Verify consistent, idempotent dose document ID format."""
    dose_id = make_deterministic_dose_id(
        circle_id="circle101",
        med_id="med-amlodipine",
        scheduled_date="2026-11-15",
        scheduled_time="08:00",
    )
    assert dose_id == "circle101_med-amlodipine_2026-11-15_08-00"

    # Missing parameters raise ValueError
    with pytest.raises(ValueError):
        make_deterministic_dose_id("", "med", "2026-11-15", "08:00")


# ============================================================================
# 4. Atomic Transaction & Duplicate Protection Tests
# ============================================================================

def test_atomic_dose_confirmation_success():
    """Verify successful atomic transition from pending to taken."""
    mock_transaction = MagicMock()
    mock_dose_ref = MagicMock()
    mock_snapshot = MagicMock()

    mock_snapshot.exists = True
    mock_snapshot.to_dict.return_value = {
        "circle_id": "circle101",
        "med_id": "med1",
        "status": "pending",
        "scheduled_for": "2026-11-15T08:00:00Z",
    }
    mock_dose_ref.get.return_value = mock_snapshot

    result = execute_atomic_dose_confirmation(
        transaction=mock_transaction,
        dose_ref=mock_dose_ref,
        logged_by_member_id="mem-caregiver-1",
        logged_by_name="Sarah",
        logged_by_role="caregiver",
        notes="Taken with water",
        server_timestamp="2026-11-15T08:05:00Z",
    )

    assert result["status"] == "taken"
    assert result["logged_by_name"] == "Sarah"
    assert result["logged_by_role"] == "caregiver"
    mock_transaction.update.assert_called_once()


def test_atomic_dose_confirmation_duplicate_blocked():
    """Verify that a dose already recorded as 'taken' atomically raises DoseConflictError."""
    mock_transaction = MagicMock()
    mock_dose_ref = MagicMock()
    mock_snapshot = MagicMock()

    mock_snapshot.exists = True
    mock_snapshot.to_dict.return_value = {
        "circle_id": "circle101",
        "med_id": "med1",
        "status": "taken",
        "logged_by_name": "Eleanor (Elder)",
        "logged_at": "2026-11-15T08:01:00Z",
    }
    mock_dose_ref.get.return_value = mock_snapshot

    with pytest.raises(DoseConflictError) as exc_info:
        execute_atomic_dose_confirmation(
            transaction=mock_transaction,
            dose_ref=mock_dose_ref,
            logged_by_member_id="mem-caregiver-1",
            logged_by_name="Sarah",
            logged_by_role="caregiver",
        )

    assert "already recorded as 'taken'" in str(exc_info.value)
    assert exc_info.value.existing_status == "taken"
    # Verify update was never called
    mock_transaction.update.assert_not_called()


def test_atomic_dose_confirmation_missing_record():
    """Verify that attempting to confirm a non-existent dose raises DoseConflictError."""
    mock_transaction = MagicMock()
    mock_dose_ref = MagicMock()
    mock_snapshot = MagicMock()
    mock_snapshot.exists = False
    mock_dose_ref.get.return_value = mock_snapshot

    with pytest.raises(DoseConflictError) as exc_info:
        execute_atomic_dose_confirmation(
            transaction=mock_transaction,
            dose_ref=mock_dose_ref,
            logged_by_member_id="mem-1",
            logged_by_name="Sarah",
            logged_by_role="caregiver",
        )

    assert exc_info.value.existing_status == "missing"


# ============================================================================
# 5. Health API with Firestore Health Integration Tests
# ============================================================================

def test_api_health_includes_firestore_status():
    """Verify that /api/health returns firestore health status and correct response format."""
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()

    assert data["service"] == "CareCircle"
    assert "firestore" in data
    assert "configured" in data["firestore"]
    assert "status" in data["firestore"]
