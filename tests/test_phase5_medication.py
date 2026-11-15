"""Comprehensive Phase 5 Tests: Medication Management, Dose Ledger, Safety, and Care Brief."""
from datetime import datetime, timedelta, timezone
import pytest
from fastapi.testclient import TestClient

from app.config import settings
from app.main import app
from app.models.auth import MemberRole
from app.models.medication import DoseStatus
from app.repositories.firestore_circle import (
    _IN_MEMORY_CIRCLES,
    _IN_MEMORY_MEMBERS,
    _IN_MEMORY_METADATA,
)
from app.repositories.firestore_invitation import _IN_MEMORY_INVITATIONS
from app.repositories.firestore_ledger import _IN_MEMORY_LEDGER
from app.repositories.firestore_medication import _IN_MEMORY_MEDICATIONS
from app.repositories.firestore_session import _IN_MEMORY_SESSIONS


@pytest.fixture(autouse=True)
def reset_in_memory_stores():
    """Reset all in-memory repository dictionaries between tests."""
    _IN_MEMORY_CIRCLES.clear()
    _IN_MEMORY_MEMBERS.clear()
    _IN_MEMORY_METADATA.clear()
    _IN_MEMORY_SESSIONS.clear()
    _IN_MEMORY_INVITATIONS.clear()
    _IN_MEMORY_MEDICATIONS.clear()
    _IN_MEMORY_LEDGER.clear()


def make_csrf_headers(client: TestClient) -> dict:
    """Helper to fetch a fresh CSRF token and return headers with automatic cookie retention."""
    res = client.get("/api/auth/csrf")
    token = res.json()["csrf_token"]
    return {
        "headers": {
            settings.CSRF_HEADER_NAME: token,
            "Origin": "http://testserver",
        },
        "token": token,
    }


def setup_circle_and_login() -> tuple[TestClient, dict]:
    """Helper to provision a primary care circle and log in as the primary caregiver."""
    client = TestClient(app)
    csrf = make_csrf_headers(client)

    payload = {
        "bootstrap_secret": settings.BOOTSTRAP_SECRET,
        "circle_name": "Sunrise Haven",
        "caregiver_name": "Sarah Primary",
        "caregiver_username": "sarah_primary",
        "caregiver_password": "PrimaryPassword123!",
        "elder_name": "Eleanor Vance",
        "elder_pin": "1234",
        "elder_dob": "1940-08-20",
        "primary_condition": "Mild Cognitive Impairment",
        "emergency_phone": "+1-555-0100",
    }

    res = client.post("/auth/setup-circle", json=payload, headers=csrf["headers"])
    assert res.status_code == 200, res.text
    circle_data = res.json()

    # Log in as primary caregiver
    csrf_login = make_csrf_headers(client)
    login_res = client.post(
        "/auth/login",
        json={"username": "sarah_primary", "password": "PrimaryPassword123!"},
        headers=csrf_login["headers"],
    )
    assert login_res.status_code == 200, login_res.text
    return client, circle_data


def login_elder(circle_data: dict) -> TestClient:
    """Helper to create a TestClient logged in as the Elder."""
    client = TestClient(app)
    csrf = make_csrf_headers(client)
    circle_code = circle_data["circle"]["circle_code"]

    res = client.post(
        "/auth/elder-login",
        json={"circle_code": circle_code, "elder_name": "Eleanor Vance", "pin": "1234"},
        headers=csrf["headers"],
    )
    assert res.status_code == 200, res.text
    return client


def invite_and_login_family(primary_client: TestClient) -> TestClient:
    """Helper to create a family invitation, accept it, and return a client logged in as family."""
    csrf_primary = make_csrf_headers(primary_client)

    inv_res = primary_client.post(
        "/api/circle/invitations",
        json={"role": "family", "invited_name": "Grandson Leo"},
        headers=csrf_primary["headers"],
    )
    assert inv_res.status_code == 201
    raw_token = inv_res.json()["raw_token"]

    family_client = TestClient(app)
    csrf_fam = make_csrf_headers(family_client)

    accept_res = family_client.post(
        "/api/circle/invitations/accept",
        json={
            "invite_token": raw_token,
            "username": "leo_family",
            "password": "FamilyPassword123!",
            "display_name": "Leo Vance",
        },
        headers=csrf_fam["headers"],
    )
    assert accept_res.status_code == 200

    # Log in as family member
    login_csrf = make_csrf_headers(family_client)
    login_res = family_client.post(
        "/auth/login",
        json={"username": "leo_family", "password": "FamilyPassword123!"},
        headers=login_csrf["headers"],
    )
    assert login_res.status_code == 200
    return family_client


# ============================================================================
# 1. Medication Creation & Validation Tests
# ============================================================================

def test_medication_creation_caregiver_success():
    """Verify primary caregiver can create a valid medication regimen."""
    client, data = setup_circle_and_login()
    csrf = make_csrf_headers(client)

    payload = {
        "name": "Lisinopril",
        "dosage": "10 mg (1 tablet)",
        "frequency": "daily",
        "times_of_day": ["08:00"],
        "instructions": "Take with water after breakfast",
        "start_date": "2026-01-01",
    }

    res = client.post("/api/medications", json=payload, headers=csrf["headers"])
    assert res.status_code == 201
    med = res.json()

    assert med["name"] == "Lisinopril"
    assert med["dosage"] == "10 mg (1 tablet)"
    assert med["frequency"] == "daily"
    assert med["times_of_day"] == ["08:00"]
    assert med["is_active"] is True
    assert med["is_paused"] is False
    assert med["circle_id"] == data["circle"]["circle_id"]


def test_medication_creation_invalid_times_rejected():
    """Verify invalid time format (e.g. 25:00 or 8am) is rejected with 422."""
    client, data = setup_circle_and_login()
    csrf = make_csrf_headers(client)

    payload = {
        "name": "Metformin",
        "dosage": "500 mg",
        "frequency": "daily",
        "times_of_day": ["25:00"],
        "start_date": "2026-01-01",
    }

    res = client.post("/api/medications", json=payload, headers=csrf["headers"])
    assert res.status_code == 422


def test_medication_creation_end_before_start_rejected():
    """Verify end date before start date is rejected with 422."""
    client, data = setup_circle_and_login()
    csrf = make_csrf_headers(client)

    payload = {
        "name": "Amoxicillin",
        "dosage": "250 mg",
        "frequency": "daily",
        "times_of_day": ["09:00"],
        "start_date": "2026-06-15",
        "end_date": "2026-06-01",
    }

    res = client.post("/api/medications", json=payload, headers=csrf["headers"])
    assert res.status_code == 422


def test_medication_creation_by_elder_forbidden():
    """Verify Elder role CANNOT create medications (HTTP 403)."""
    primary_client, data = setup_circle_and_login()
    elder_client = login_elder(data)
    csrf = make_csrf_headers(elder_client)

    payload = {
        "name": "Aspirin",
        "dosage": "81 mg",
        "frequency": "daily",
        "times_of_day": ["08:00"],
        "start_date": "2026-01-01",
    }

    res = elder_client.post("/api/medications", json=payload, headers=csrf["headers"])
    assert res.status_code == 403
    assert "forbidden" in res.json()["detail"].lower()


def test_medication_creation_by_family_forbidden():
    """Verify Family role CANNOT create medications (HTTP 403)."""
    primary_client, data = setup_circle_and_login()
    family_client = invite_and_login_family(primary_client)
    csrf = make_csrf_headers(family_client)

    payload = {
        "name": "Aspirin",
        "dosage": "81 mg",
        "frequency": "daily",
        "times_of_day": ["08:00"],
        "start_date": "2026-01-01",
    }

    res = family_client.post("/api/medications", json=payload, headers=csrf["headers"])
    assert res.status_code == 403


def test_medication_creation_unauthenticated_rejected():
    """Verify unauthenticated user cannot create medications (HTTP 401)."""
    anon_client = TestClient(app)
    csrf = make_csrf_headers(anon_client)

    payload = {
        "name": "Aspirin",
        "dosage": "81 mg",
        "frequency": "daily",
        "times_of_day": ["08:00"],
        "start_date": "2026-01-01",
    }

    res = anon_client.post("/api/medications", json=payload, headers=csrf["headers"])
    assert res.status_code == 401


# ============================================================================
# 2. Medication Pause, Resume & Deactivation Tests
# ============================================================================

def test_medication_pause_and_resume():
    """Verify caregiver can pause and resume a medication regimen."""
    client, data = setup_circle_and_login()
    csrf = make_csrf_headers(client)

    # Create medication
    create_res = client.post(
        "/api/medications",
        json={
            "name": "Atorvastatin",
            "dosage": "20 mg",
            "frequency": "daily",
            "times_of_day": ["21:00"],
            "start_date": "2026-01-01",
        },
        headers=csrf["headers"],
    )
    med_id = create_res.json()["medication_id"]

    # Pause medication
    csrf_pause = make_csrf_headers(client)
    pause_res = client.post(
        f"/api/medications/{med_id}/pause",
        json={"is_paused": True},
        headers=csrf_pause["headers"],
    )
    assert pause_res.status_code == 200
    assert pause_res.json()["is_paused"] is True

    # Check schedule: Doses for paused medication have status "paused"
    sched_res = client.get("/api/medications/schedule")
    assert sched_res.status_code == 200
    items = [d for d in sched_res.json() if d["medication_id"] == med_id]
    assert len(items) == 1
    assert items[0]["status"] == "paused"
    assert items[0]["can_confirm"] is False

    # Resume medication
    csrf_resume = make_csrf_headers(client)
    resume_res = client.post(
        f"/api/medications/{med_id}/pause",
        json={"is_paused": False},
        headers=csrf_resume["headers"],
    )
    assert resume_res.status_code == 200
    assert resume_res.json()["is_paused"] is False


def test_medication_soft_deactivation():
    """Verify deactivating a medication marks is_active=False and excludes it from active schedule."""
    client, data = setup_circle_and_login()
    csrf = make_csrf_headers(client)

    # Create medication
    create_res = client.post(
        "/api/medications",
        json={
            "name": "Antibiotic Course",
            "dosage": "500 mg",
            "frequency": "daily",
            "times_of_day": ["12:00"],
            "start_date": "2026-01-01",
        },
        headers=csrf["headers"],
    )
    med_id = create_res.json()["medication_id"]

    # Deactivate (DELETE)
    csrf_del = make_csrf_headers(client)
    del_res = client.delete(f"/api/medications/{med_id}", headers=csrf_del["headers"])
    assert del_res.status_code == 200
    assert del_res.json()["is_active"] is False

    # Schedule should not include deactivated medication
    sched_res = client.get("/api/medications/schedule")
    assert sched_res.status_code == 200
    med_ids = [d["medication_id"] for d in sched_res.json()]
    assert med_id not in med_ids


# ============================================================================
# 3. Daily Schedule Generation & Dose State Machine Tests
# ============================================================================

def test_daily_schedule_deterministic_ids_and_sorting():
    """Verify daily schedule produces deterministic dose IDs sorted chronologically."""
    client, data = setup_circle_and_login()
    csrf = make_csrf_headers(client)

    # Add morning and evening medications
    client.post(
        "/api/medications",
        json={
            "name": "Morning Med",
            "dosage": "1 pill",
            "frequency": "daily",
            "times_of_day": ["08:00"],
            "start_date": "2026-01-01",
        },
        headers=csrf["headers"],
    )
    csrf2 = make_csrf_headers(client)
    client.post(
        "/api/medications",
        json={
            "name": "Evening Med",
            "dosage": "2 pills",
            "frequency": "daily",
            "times_of_day": ["20:00"],
            "start_date": "2026-01-01",
        },
        headers=csrf2["headers"],
    )

    today_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    sched_res = client.get("/api/medications/schedule")
    assert sched_res.status_code == 200
    doses = sched_res.json()
    assert len(doses) >= 2

    # Check chronological ordering
    times = [d["scheduled_time"] for d in doses]
    assert times == sorted(times)

    # Check deterministic format
    for d in doses:
        assert d["scheduled_date"] == today_str
        assert today_str in d["dose_id"]
        assert d["scheduled_time"].replace(":", "-") in d["dose_id"]


# ============================================================================
# 4. Atomic Dose Confirmation & Duplicate Prevention Tests
# ============================================================================

def test_dose_confirmation_by_elder_and_duplicate_rejection():
    """
    Verify:
    1. Elder can confirm a scheduled dose using one-tap confirmation.
    2. Atomic double-dose prevention: Second confirmation of the SAME dose returns HTTP 409 Conflict.
    """
    primary_client, data = setup_circle_and_login()
    csrf_p = make_csrf_headers(primary_client)

    # Create medication
    create_res = primary_client.post(
        "/api/medications",
        json={
            "name": "Blood Pressure Pill",
            "dosage": "5 mg",
            "frequency": "daily",
            "times_of_day": ["08:00"],
            "start_date": "2026-01-01",
        },
        headers=csrf_p["headers"],
    )
    assert create_res.status_code == 201

    # Login as elder
    elder_client = login_elder(data)
    sched_res = elder_client.get("/api/medications/schedule")
    assert sched_res.status_code == 200
    doses = sched_res.json()
    assert len(doses) >= 1
    target_dose = doses[0]
    dose_id = target_dose["dose_id"]

    # 1. Elder confirms dose
    csrf_elder = make_csrf_headers(elder_client)
    confirm_res = elder_client.post(
        f"/api/medications/doses/{dose_id}/confirm",
        json={"method": "self_reported", "notes": "Elder took dose"},
        headers=csrf_elder["headers"],
    )
    assert confirm_res.status_code == 200
    confirm_data = confirm_res.json()
    assert confirm_data["status"] == "taken"
    assert confirm_data["is_taken"] is True
    assert confirm_data["dose_id"] == dose_id
    assert confirm_data["confirmed_by_role"] == "elder"

    # Verify schedule reflects "taken" status
    sched_res2 = elder_client.get("/api/medications/schedule")
    updated_dose = [d for d in sched_res2.json() if d["dose_id"] == dose_id][0]
    assert updated_dose["status"] == "taken"
    assert updated_dose["can_confirm"] is False

    # 2. Duplicate Prevention: Caregiver attempts to confirm the SAME dose again
    csrf_p2 = make_csrf_headers(primary_client)
    dup_res = primary_client.post(
        f"/api/medications/doses/{dose_id}/confirm",
        json={"method": "observed", "notes": "Caregiver attempting duplicate"},
        headers=csrf_p2["headers"],
    )
    assert dup_res.status_code == 409
    dup_detail = dup_res.json()["detail"]
    assert "already recorded" in dup_detail.lower()


def test_family_member_cannot_confirm_dose():
    """Verify Family members have read-only visibility and cannot confirm doses (HTTP 403)."""
    primary_client, data = setup_circle_and_login()
    csrf_p = make_csrf_headers(primary_client)

    primary_client.post(
        "/api/medications",
        json={
            "name": "Vitamin D",
            "dosage": "1000 IU",
            "frequency": "daily",
            "times_of_day": ["09:00"],
            "start_date": "2026-01-01",
        },
        headers=csrf_p["headers"],
    )

    family_client = invite_and_login_family(primary_client)
    sched_res = family_client.get("/api/medications/schedule")
    assert sched_res.status_code == 200
    doses = sched_res.json()
    assert len(doses) >= 1
    dose_id = doses[0]["dose_id"]

    csrf_fam = make_csrf_headers(family_client)
    res = family_client.post(
        f"/api/medications/doses/{dose_id}/confirm",
        json={"method": "observed"},
        headers=csrf_fam["headers"],
    )
    assert res.status_code == 403
    assert "read-only" in res.json()["detail"].lower()


# ============================================================================
# 5. Cross-Circle Tenant Isolation Tests
# ============================================================================

def test_cross_circle_isolation():
    """Verify members of Circle A cannot access, modify, or confirm doses of Circle B."""
    client_a, data_a = setup_circle_and_login()
    csrf_a = make_csrf_headers(client_a)

    # Directly inject foreign medication belonging to another circle
    other_circle_id = "other-circle-uuid-999"
    foreign_med_id = "foreign-med-uuid-888"
    _IN_MEMORY_MEDICATIONS[foreign_med_id] = {
        "med_id": foreign_med_id,
        "circle_id": other_circle_id,
        "elder_id": "foreign-elder-uuid-777",
        "name": "Circle B Med",
        "dosage_instructions": "50 mg",
        "frequency": "daily",
        "scheduled_times": ["10:00"],
        "start_date": "2026-01-01",
        "is_active": True,
        "is_paused": False,
        "created_by": "other-caregiver",
        "created_by_name": "Other Caregiver",
        "created_at": datetime.now(timezone.utc).isoformat(),
    }

    # 1. Circle A caregiver attempts to view Circle B medication
    get_res = client_a.get(f"/api/medications/{foreign_med_id}")
    assert get_res.status_code == 404

    # 2. Circle A caregiver attempts to pause Circle B medication
    pause_res = client_a.post(
        f"/api/medications/{foreign_med_id}/pause",
        json={"is_paused": True},
        headers=csrf_a["headers"],
    )
    assert pause_res.status_code == 404

    # 3. Circle A caregiver attempts to delete Circle B medication
    del_res = client_a.delete(f"/api/medications/{foreign_med_id}", headers=csrf_a["headers"])
    assert del_res.status_code == 404

    # 4. Circle A caregiver attempts to confirm Circle B dose
    confirm_res = client_a.post(
        f"/api/medications/doses/{other_circle_id}_{foreign_med_id}_2026-01-01_10-00/confirm",
        headers=csrf_a["headers"],
    )
    assert confirm_res.status_code == 404


# ============================================================================
# 6. Context-Aware Deterministic Care Brief Tests (Zero Hallucinations)
# ============================================================================

def test_care_brief_factual_generation():
    """Verify Care Brief generates deterministic, factual narrative matching exact counts."""
    client, data = setup_circle_and_login()
    csrf = make_csrf_headers(client)

    # Empty state care brief
    brief_res = client.get("/api/medications/care-brief")
    assert brief_res.status_code == 200
    brief = brief_res.json()
    assert brief["status_tone"] == "neutral"
    assert brief["total_scheduled"] == 0
    assert brief["active_prescriptions_count"] == 0

    # Add medication with time past (simulating overdue or due)
    now_hour = datetime.now(timezone.utc).hour
    past_time = f"{max(0, now_hour - 3):02d}:00"

    client.post(
        "/api/medications",
        json={
            "name": "Heart Medication",
            "dosage": "25 mg",
            "frequency": "daily",
            "times_of_day": [past_time],
            "start_date": "2026-01-01",
        },
        headers=csrf["headers"],
    )

    brief_res2 = client.get("/api/medications/care-brief")
    assert brief_res2.status_code == 200
    brief2 = brief_res2.json()
    assert brief2["active_prescriptions_count"] == 1
    assert brief2["total_scheduled"] == 1
    assert brief2["status_tone"] in ("alert", "warning", "neutral")


# ============================================================================
# 7. Shared Dose Ledger Audit & Bounded Query Tests
# ============================================================================

def test_dose_ledger_history_and_bounded_queries():
    """Verify dose ledger records events with identity, method, notes, and respects query limit."""
    client, data = setup_circle_and_login()
    csrf = make_csrf_headers(client)

    # Add medication
    res = client.post(
        "/api/medications",
        json={
            "name": "Calcium Carbonate",
            "dosage": "500 mg",
            "frequency": "daily",
            "times_of_day": ["08:00"],
            "start_date": "2026-01-01",
        },
        headers=csrf["headers"],
    )
    med_id = res.json()["medication_id"]

    # Get scheduled dose
    sched = client.get("/api/medications/schedule").json()
    dose_id = sched[0]["dose_id"]

    # Confirm dose
    csrf_c = make_csrf_headers(client)
    confirm_res = client.post(
        f"/api/medications/doses/{dose_id}/confirm",
        json={"method": "administered", "notes": "Administered by Sarah with breakfast"},
        headers=csrf_c["headers"],
    )
    assert confirm_res.status_code == 200

    # Query ledger
    ledger_res = client.get("/api/medications/ledger?limit=10")
    assert ledger_res.status_code == 200
    events = ledger_res.json()
    assert len(events) == 1
    evt = events[0]
    assert evt["dose_id"] == dose_id
    assert evt["medication_name"] == "Calcium Carbonate"
    assert evt["confirmed_by_name"] == "Sarah Primary"
    assert evt["confirmed_by_role"] == "caregiver"
    assert evt["confirmed_method"] == "administered"
    assert evt["notes"] == "Administered by Sarah with breakfast"


# ============================================================================
# 8. Web Views Accessibility & Rendering Tests
# ============================================================================

def test_medications_html_page_rendering():
    """Verify /medications returns 200 HTML with CSRF meta tag and Care Brief."""
    client, data = setup_circle_and_login()
    res = client.get("/medications")
    assert res.status_code == 200
    assert "text/html" in res.headers["content-type"]
    assert "Medication Management" in res.text
    assert "Care Brief" in res.text
    assert 'meta name="csrf-token"' in res.text


def test_elder_doses_html_page_rendering():
    """Verify /elder/doses returns 200 HTML with high-contrast, large-touch interface."""
    client, data = setup_circle_and_login()
    elder_client = login_elder(data)

    res = elder_client.get("/elder/doses")
    assert res.status_code == 200
    assert "text/html" in res.headers["content-type"]
    assert "Today's Medicines" in res.text
    assert "Eleanor Vance" in res.text
    assert "Daily Medicine Helper" in res.text


# ============================================================================
# 9. Enterprise Security Headers, Efficiency Caching & Clinical Safety Tests
# ============================================================================

def test_enterprise_security_headers_applied():
    """Verify defense-in-depth HTTP security headers are present on responses."""
    client = TestClient(app)
    res = client.get("/api/health")
    assert res.status_code == 200

    headers = res.headers
    assert headers["x-content-type-options"] == "nosniff"
    assert headers["x-frame-options"] == "DENY"
    assert headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert "permissions-policy" in headers
    assert "content-security-policy" in headers
    assert "default-src 'self'" in headers["content-security-policy"]


def test_efficiency_caching_controls_and_static_assets():
    """Verify long-lived caching on static assets and no-store on sensitive API endpoints."""
    client = TestClient(app)

    # Static CSS uses short revalidation caching for unversioned assets
    res_static = client.get("/static/css/style.css")
    assert res_static.status_code == 200
    assert "public" in res_static.headers["cache-control"]
    assert "max-age=3600" in res_static.headers["cache-control"]
    assert "must-revalidate" in res_static.headers["cache-control"]

    # API and private HTML endpoints must not be cached by intermediate proxies
    res_api = client.get("/api/health")
    assert res_api.status_code == 200
    assert "no-store" in res_api.headers["cache-control"]
    assert "private" in res_api.headers["cache-control"]


def test_clinical_safety_duplicate_active_prescription_rejected():
    """Verify attempt to create duplicate active prescription for same medication name is blocked (HTTP 400)."""
    client, data = setup_circle_and_login()
    csrf = make_csrf_headers(client)

    # 1. First prescription succeeds
    res1 = client.post(
        "/api/medications",
        json={
            "name": "Metformin",
            "dosage": "500 mg",
            "frequency": "daily",
            "times_of_day": ["08:00"],
            "start_date": "2026-01-01",
        },
        headers=csrf["headers"],
    )
    assert res1.status_code == 201

    # 2. Duplicate active prescription for "Metformin" is rejected as a clinical safety conflict
    csrf2 = make_csrf_headers(client)
    res2 = client.post(
        "/api/medications",
        json={
            "name": "metformin",  # Case-insensitive duplicate
            "dosage": "1000 mg",
            "frequency": "twice_daily",
            "times_of_day": ["08:00", "20:00"],
            "start_date": "2026-01-01",
        },
        headers=csrf2["headers"],
    )
    assert res2.status_code == 400
    assert "safety conflict" in res2.json()["detail"].lower()


def test_elder_doses_accessible_button_activation_no_unsafe_single_key():
    """Verify Elder dose cards require focused button activation, preventing silent accidental confirmations."""
    client, data = setup_circle_and_login()
    csrf = make_csrf_headers(client)

    client.post(
        "/api/medications",
        json={
            "name": "Amlodipine",
            "dosage": "5 mg",
            "frequency": "daily",
            "times_of_day": ["08:00"],
            "start_date": "2026-01-01",
        },
        headers=csrf["headers"],
    )

    elder_client = login_elder(data)
    res = elder_client.get("/elder/doses")
    assert res.status_code == 200
    # Single-key auto-click shortcuts removed to prevent silent accidental confirmations
    assert "data-key-index=" not in res.text
    assert "Press [1]" not in res.text
    # Accessible button for intentional focused activation is present
    assert "I TOOK THIS MEDICINE" in res.text
    assert "aria-label=" in res.text


def test_urgent_escalation_alert_rendered_on_overdue_dose():
    """Verify that when a dose is overdue, the urgent caregiver escalation banner with emergency dialer renders."""
    client, data = setup_circle_and_login()
    csrf = make_csrf_headers(client)

    # Schedule medication at past time today (ensuring overdue state)
    now_hour = datetime.now(timezone.utc).hour
    past_time = f"{max(0, now_hour - 3):02d}:00"

    client.post(
        "/api/medications",
        json={
            "name": "Warfarin",
            "dosage": "2 mg",
            "frequency": "daily",
            "times_of_day": [past_time],
            "start_date": "2026-01-01",
        },
        headers=csrf["headers"],
    )

    res = client.get("/medications")
    assert res.status_code == 200
    assert "URGENT ESCALATION" in res.text
    assert "tel:+1-555-0100" in res.text  # Emergency phone from setup fixture


# ============================================================================
# Additional Comprehensive Validation & Regression Tests (Urgent Corrections)
# ============================================================================

def test_backend_dose_confirmation_strict_validations():
    """Verify backend rejects invalid confirmation attempts across all safety invariants."""
    client, data = setup_circle_and_login()
    csrf = make_csrf_headers(client)

    # Setup active medication (open-ended regimen started in 2020)
    today_dt = datetime.now(timezone.utc)
    today_str = today_dt.strftime("%Y-%m-%d")
    yesterday_str = (today_dt - timedelta(days=1)).strftime("%Y-%m-%d")

    med_res = client.post(
        "/api/medications",
        json={
            "name": "Levothyroxine",
            "dosage": "50 mcg",
            "frequency": "daily",
            "times_of_day": ["08:00"],
            "start_date": "2020-01-01",
        },
        headers=csrf["headers"],
    )
    assert med_res.status_code == 201
    med_id = med_res.json()["medication_id"]
    circle_id = data["circle"]["circle_id"]

    # 1. Reject future date confirmation on open-ended medication (400)
    future_date = "2029-01-01"
    future_dose_id = f"{circle_id}_{med_id}_{future_date}_08-00"
    csrf1 = make_csrf_headers(client)
    res_future = client.post(
        f"/api/medications/doses/{future_dose_id}/confirm",
        json={"notes": "premature"},
        headers=csrf1["headers"],
    )
    assert res_future.status_code == 400
    assert "future" in res_future.json()["detail"].lower()

    # 2. Reject past missed date confirmation within regimen (400)
    past_dose_id = f"{circle_id}_{med_id}_{yesterday_str}_08-00"
    csrf2 = make_csrf_headers(client)
    res_past = client.post(
        f"/api/medications/doses/{past_dose_id}/confirm",
        json={"notes": "late"},
        headers=csrf2["headers"],
    )
    assert res_past.status_code == 400
    assert "past" in res_past.json()["detail"].lower()

    # 3. Reject scheduled time not in regimen (400)
    invalid_time_dose_id = f"{circle_id}_{med_id}_{today_str}_15-30"
    csrf3 = make_csrf_headers(client)
    res_bad_time = client.post(
        f"/api/medications/doses/{invalid_time_dose_id}/confirm",
        json={},
        headers=csrf3["headers"],
    )
    assert res_bad_time.status_code == 400
    assert "regimen" in res_bad_time.json()["detail"].lower()

    # 4. Reject confirmation >60m before scheduled time (400)
    now_hour = datetime.now(timezone.utc).hour
    future_time_today = f"{(now_hour + 4) % 24:02d}:00"
    csrf_far = make_csrf_headers(client)
    med_far_res = client.post(
        "/api/medications",
        json={
            "name": "Insulin",
            "dosage": "10 units",
            "frequency": "daily",
            "times_of_day": [future_time_today],
            "start_date": today_str,
        },
        headers=csrf_far["headers"],
    )
    med_far_id = med_far_res.json()["medication_id"]
    far_dose_id = f"{circle_id}_{med_far_id}_{today_str}_{future_time_today.replace(':', '-')}"
    csrf_far_confirm = make_csrf_headers(client)
    res_far = client.post(
        f"/api/medications/doses/{far_dose_id}/confirm",
        json={},
        headers=csrf_far_confirm["headers"],
    )
    assert res_far.status_code == 400
    assert "60 minutes" in res_far.json()["detail"].lower()

    # 5. Reject paused medication confirmation (400)
    csrf_pause = make_csrf_headers(client)
    client.post(
        f"/api/medications/{med_id}/pause",
        json={"is_paused": True},
        headers=csrf_pause["headers"],
    )
    csrf_paused_confirm = make_csrf_headers(client)
    res_paused = client.post(
        f"/api/medications/doses/{circle_id}_{med_id}_{today_str}_08-00/confirm",
        json={},
        headers=csrf_paused_confirm["headers"],
    )
    assert res_paused.status_code == 400
    assert "paused" in res_paused.json()["detail"].lower()


def test_timezone_asia_kolkata_schedule_and_iso():
    """Verify care circle with Asia/Kolkata timezone translates scheduled times correctly."""
    from app.services.medication import MedicationService

    med_service = MedicationService()
    # Circle in Asia/Kolkata (+05:30)
    circle_data = {"circle_id": "test_c1", "timezone": "Asia/Kolkata"}
    tz = med_service._get_circle_tz(circle_data)
    assert tz is not None

    # Test local 09:00 IST translates to 03:30 UTC
    dt_local = datetime(2026, 11, 15, 9, 0, tzinfo=tz)
    dt_utc = dt_local.astimezone(timezone.utc)
    assert dt_utc.hour == 3
    assert dt_utc.minute == 30


def test_production_secrets_fail_closed():
    """Verify Settings.validate_production_secrets raises RuntimeError on default or missing secrets in production."""
    from app.config import Settings
    prod_settings = Settings()
    prod_settings.ENVIRONMENT = "production"
    prod_settings.SECRET_KEY = "carecircle-insecure-dev-secret-key-32b"

    with pytest.raises(RuntimeError) as exc:
        prod_settings.validate_production_secrets()
    assert "insecure default or missing secret_key" in str(exc.value).lower()
    # Ensure raw secret is not leaked in exception string
    assert "carecircle-insecure-dev-secret-key-32b" not in str(exc.value)


def test_https_hsts_header_conditioning():
    """Verify HSTS Strict-Transport-Security header is only emitted on HTTPS connections."""
    client = TestClient(app)

    # 1. Plain HTTP request: No HSTS header
    res_http = client.get("/api/health")
    assert res_http.status_code == 200
    assert "strict-transport-security" not in res_http.headers

    # 2. HTTPS request (via X-Forwarded-Proto): HSTS present
    res_https = client.get("/api/health", headers={"X-Forwarded-Proto": "https"})
    assert res_https.status_code == 200
    assert "strict-transport-security" in res_https.headers
    assert "max-age=31536000" in res_https.headers["strict-transport-security"]

