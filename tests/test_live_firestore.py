"""Live Firestore Integration Test Suite: Document Write/Read, Application-Level Tenant Isolation, and Atomic Transactions."""
import uuid
import pytest
from google.cloud import firestore
from app.services.firestore import (
    get_firestore_client,
    verify_firestore_health,
    make_deterministic_dose_id,
    CircleSecurityContext,
    CircleIsolationViolation,
    execute_atomic_dose_confirmation,
    DoseConflictError,
)

# Generate a full 32-character unique run UUID for complete document isolation per test execution
TEST_RUN_UUID = uuid.uuid4().hex
TEST_COLLECTION_NAME = "_live_verification_tests"
CIRCLE_ALPHA_ID = f"test-alpha-{TEST_RUN_UUID}"
CIRCLE_BETA_ID = f"test-beta-{TEST_RUN_UUID}"


@pytest.fixture(scope="module")
def firestore_client():
    """Fixture providing initialized Firestore client or skipping if unconfigured."""
    client = get_firestore_client()
    if client is None:
        pytest.skip("Firestore client is unconfigured. Set FIREBASE_SERVICE_ACCOUNT_KEY_B64 to run live integration.")
    return client


@pytest.fixture(scope="module")
def live_test_session(firestore_client):
    """
    Fixture tracking documents created in this specific test run.
    Guarantees cleanup via try/finally even if test assertions or transactions fail.
    Deletes strictly documents registered in this run, leaving all other data untouched.
    Collects and reports cleanup errors explicitly instead of silently suppressing them.
    """
    created_doc_refs = []
    collection = firestore_client.collection(TEST_COLLECTION_NAME)

    def track(doc_ref):
        created_doc_refs.append(doc_ref)
        return doc_ref

    cleanup_errors = []

    try:
        yield {
            "collection": collection,
            "track": track,
            "run_uuid": TEST_RUN_UUID,
            "circle_alpha": CIRCLE_ALPHA_ID,
            "circle_beta": CIRCLE_BETA_ID,
        }
    finally:
        # Guaranteed cleanup of only documents created in this test run
        for ref in created_doc_refs:
            try:
                ref.delete()
            except Exception as e:
                # Capture document path and sanitized error type without printing credentials
                cleanup_errors.append(f"{ref.path}: {type(e).__name__} ({str(e)[:120]})")

        if cleanup_errors:
            error_details = "; ".join(cleanup_errors)
            pytest.fail(f"Test document cleanup encountered errors: {error_details}")


def test_01_live_firestore_connection(firestore_client):
    """Test 1: Verify live connection and health status of Firestore database."""
    health = verify_firestore_health()
    assert health["configured"] is True, "Firestore should be configured"
    assert health["status"] == "connected", f"Expected connected, got {health.get('status')}: {health.get('error')}"
    assert health["project_id"] == "carecircle-catalyst"


def test_02_live_document_write_and_read(live_test_session):
    """
    Test 2: Perform real document write and read on the live Firestore database.
    Independently creates, verifies, and registers its own test document.
    """
    collection = live_test_session["collection"]
    circle_alpha = live_test_session["circle_alpha"]
    run_uuid = live_test_session["run_uuid"]

    doc_id = f"{circle_alpha}_write_read_{run_uuid}"
    doc_ref = live_test_session["track"](collection.document(doc_id))

    # Step A: Real write with CircleSecurityContext payload validation
    context = CircleSecurityContext(circle_alpha)
    payload = context.validate_payload({
        "test_run": f"run_{run_uuid}",
        "elder_name": "Eleanor Test",
        "status": "active",
    })
    doc_ref.set(payload)

    # Step B: Real read from Firestore
    snapshot = doc_ref.get()
    assert snapshot.exists, "Document write failed to persist in Firestore"
    data = snapshot.to_dict()
    assert data["elder_name"] == "Eleanor Test"
    assert data["circle_id"] == circle_alpha
    assert data["status"] == "active"


def test_03_application_level_tenant_isolation(live_test_session):
    """
    Test 3: Verify strict circle-level data isolation logic via CircleSecurityContext.
    Independently creates, verifies, and registers its own isolated test document.

    NOTE ON SCOPE: This test validates CareCircle's backend application-level isolation
    enforced by CircleSecurityContext. It does NOT verify Firestore client-side
    security rules, because the Firebase Admin SDK executes with server-side
    administrative privileges and bypasses client rules by design.
    """
    collection = live_test_session["collection"]
    circle_alpha = live_test_session["circle_alpha"]
    circle_beta = live_test_session["circle_beta"]
    run_uuid = live_test_session["run_uuid"]

    # Independent document creation for test 03
    doc_id = f"{circle_alpha}_isolation_{run_uuid}"
    doc_ref = live_test_session["track"](collection.document(doc_id))

    context_alpha = CircleSecurityContext(circle_alpha)
    doc_ref.set(context_alpha.validate_payload({
        "test_run": f"run_{run_uuid}",
        "confidential_data": "alpha_protected_record",
    }))

    snapshot = doc_ref.get()
    assert snapshot.exists, "Isolation test document failed to persist"
    alpha_data = snapshot.to_dict()

    # Context A validates successfully
    assert context_alpha.validate_document(alpha_data)["circle_id"] == circle_alpha

    # Context B MUST raise CircleIsolationViolation when attempting to access Alpha's data
    context_beta = CircleSecurityContext(circle_beta)
    with pytest.raises(CircleIsolationViolation):
        context_beta.validate_document(alpha_data)

    # Context B MUST reject writing data stamped with Alpha's circle ID
    with pytest.raises(CircleIsolationViolation):
        context_beta.validate_payload({"circle_id": circle_alpha, "data": "cross-circle-leak"})


def test_04_live_atomic_transaction_duplicate_prevention(firestore_client, live_test_session):
    """
    Test 4: Verify atomic dose confirmation and sequential duplicate attempt blocking.
    Independently creates, verifies, and registers its own isolated dose document.

    NOTE ON CONCURRENCY: This test verifies transaction status guard logic in a sequential
    duplicate scenario; it demonstrates that a second sequential confirmation attempt
    is atomically aborted and raises DoseConflictError. It does not claim to verify
    simultaneous multi-threaded race conditions.
    """
    collection = live_test_session["collection"]
    circle_alpha = live_test_session["circle_alpha"]
    run_uuid = live_test_session["run_uuid"]

    med_id = f"med-amlodipine-{run_uuid}"
    dose_id = make_deterministic_dose_id(circle_alpha, med_id, "2026-11-15", "08:00")
    dose_ref = live_test_session["track"](collection.document(dose_id))

    # Seed pending dose on Firestore
    dose_ref.set({
        "circle_id": circle_alpha,
        "med_id": med_id,
        "med_name": "Amlodipine",
        "status": "pending",
        "scheduled_for": "2026-11-15T08:00:00Z",
    })

    # Transaction 1: Initial valid confirmation
    @firestore.transactional
    def run_first_confirmation(transaction):
        return execute_atomic_dose_confirmation(
            transaction=transaction,
            dose_ref=dose_ref,
            logged_by_member_id="caregiver-001",
            logged_by_name="Sarah Nurse",
            logged_by_role="caregiver",
            notes="Morning dose taken with water",
            server_timestamp="2026-11-15T08:02:00Z",
        )

    txn1 = firestore_client.transaction()
    res1 = run_first_confirmation(txn1)
    assert res1["status"] == "taken"
    assert res1["logged_by_name"] == "Sarah Nurse"

    # Verify persisted state on Firestore
    persisted_snapshot = dose_ref.get()
    assert persisted_snapshot.to_dict()["status"] == "taken"

    # Transaction 2: Sequential duplicate confirmation attempt on the same dose
    @firestore.transactional
    def run_duplicate_confirmation(transaction):
        return execute_atomic_dose_confirmation(
            transaction=transaction,
            dose_ref=dose_ref,
            logged_by_member_id="elder-001",
            logged_by_name="Eleanor",
            logged_by_role="elder",
        )

    txn2 = firestore_client.transaction()
    with pytest.raises(DoseConflictError) as exc_info:
        run_duplicate_confirmation(txn2)

    assert exc_info.value.existing_status == "taken"
    assert "already recorded as 'taken'" in str(exc_info.value)
    assert "Sarah Nurse" in str(exc_info.value)
