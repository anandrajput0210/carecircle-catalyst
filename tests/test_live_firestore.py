"""Live Firestore Integration Test: Document Write/Read, Circle Isolation, and Atomic Transactions."""
import pytest
from app.services.firestore import (
    get_firestore_client,
    verify_firestore_health,
    make_deterministic_dose_id,
    CircleSecurityContext,
    CircleIsolationViolation,
    execute_atomic_dose_confirmation,
    DoseConflictError,
)


@pytest.mark.integration
def test_live_firestore_lifecycle_and_isolation():
    """
    Live Firestore Verification:
    1. Verifies connection to real Firestore database.
    2. Writes a test document under circle 'circle-alpha'.
    3. Reads back the test document and validates data integrity.
    4. Enforces circle isolation: asserts 'circle-beta' context is rejected.
    5. Tests atomic transaction wrapper: confirms dose, then verifies duplicate attempt raises DoseConflictError.
    6. Cleans up test documents.
    """
    client = get_firestore_client()
    if client is None:
        pytest.skip("Firestore client is unconfigured. Set FIREBASE_SERVICE_ACCOUNT_KEY_B64 or JSON to run live integration.")

    test_collection = client.collection("_live_verification_tests")
    circle_alpha_id = "test-live-alpha"
    circle_beta_id = "test-live-beta"

    doc_alpha_ref = test_collection.document(f"{circle_alpha_id}_doc1")
    dose_doc_ref = test_collection.document(f"{circle_alpha_id}_med1_2026-11-15_08-00")

    try:
        # Step 1: Real document write
        alpha_context = CircleSecurityContext(circle_alpha_id)
        payload = alpha_context.validate_payload({
            "test_key": "carecircle_live_verification",
            "elder_name": "Eleanor Test",
        })
        doc_alpha_ref.set(payload)

        # Step 2: Real document read
        snapshot = doc_alpha_ref.get()
        assert snapshot.exists, "Document write failed to persist in Firestore"
        data = snapshot.to_dict()
        assert data["elder_name"] == "Eleanor Test"
        assert data["circle_id"] == circle_alpha_id

        # Step 3: Tenant Isolation Verification (Circle A vs Circle B)
        # Alpha context validates successfully
        assert alpha_context.validate_document(data)["circle_id"] == circle_alpha_id

        # Beta context MUST raise CircleIsolationViolation when accessing Alpha's document
        beta_context = CircleSecurityContext(circle_beta_id)
        with pytest.raises(CircleIsolationViolation):
            beta_context.validate_document(data)

        # Beta context cannot write a document claiming Alpha's circle
        with pytest.raises(CircleIsolationViolation):
            beta_context.validate_payload({"circle_id": circle_alpha_id, "data": "intruder"})

        # Step 4: Real Firestore Transaction & Duplicate Confirmation Protection
        # Seed initial pending dose
        dose_doc_ref.set({
            "circle_id": circle_alpha_id,
            "med_id": "med1",
            "med_name": "Amlodipine",
            "status": "pending",
            "scheduled_for": "2026-11-15T08:00:00Z",
        })

        # Run Transaction 1: Confirm dose
        @client.transactional
        def run_txn_1(transaction):
            return execute_atomic_dose_confirmation(
                transaction=transaction,
                dose_ref=dose_doc_ref,
                logged_by_member_id="caregiver-001",
                logged_by_name="Sarah Nurse",
                logged_by_role="caregiver",
                notes="Morning dose taken with water",
                server_timestamp="2026-11-15T08:02:00Z",
            )

        transaction_1 = client.transaction()
        result_1 = run_txn_1(transaction_1)
        assert result_1["status"] == "taken"
        assert result_1["logged_by_name"] == "Sarah Nurse"

        # Verify persisted state in Firestore
        dose_snapshot = dose_doc_ref.get()
        assert dose_snapshot.to_dict()["status"] == "taken"

        # Run Transaction 2: Duplicate confirmation attempt on the same dose
        @client.transactional
        def run_txn_2(transaction):
            return execute_atomic_dose_confirmation(
                transaction=transaction,
                dose_ref=dose_doc_ref,
                logged_by_member_id="elder-001",
                logged_by_name="Eleanor",
                logged_by_role="elder",
            )

        transaction_2 = client.transaction()
        with pytest.raises(DoseConflictError) as exc_info:
            run_txn_2(transaction_2)

        assert exc_info.value.existing_status == "taken"
        assert "already recorded as 'taken'" in str(exc_info.value)
        assert "Sarah Nurse" in str(exc_info.value)

    finally:
        # Step 5: Clean up test documents to keep database pristine
        try:
            doc_alpha_ref.delete()
            dose_doc_ref.delete()
        except Exception:
            pass


if __name__ == "__main__":
    test_live_firestore_lifecycle_and_isolation()
    print("ALL LIVE FIRESTORE INTEGRATION CHECKS PASSED!")
