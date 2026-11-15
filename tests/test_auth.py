"""Comprehensive Authentication and Security Tests for Phase 3."""
import copy
import re
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock
import pytest
from fastapi.testclient import TestClient

from app.config import settings
from app.main import app
from app.models.auth import (
    AuthType,
    CircleCreateRequest,
    CredentialResetRequest,
    ElderLoginRequest,
    LoginRequest,
    MemberDoc,
    MemberRole,
    RecoveryRequest,
    SessionDoc,
)
from app.repositories.firestore_circle import (
    _IN_MEMORY_CIRCLES,
    _IN_MEMORY_MEMBERS,
    _IN_MEMORY_METADATA,
    FirestoreCircleRepository,
)
from app.repositories.firestore_session import (
    _IN_MEMORY_SESSIONS,
    FirestoreSessionRepository,
)
from app.services.auth import (
    generate_circle_code,
    generate_recovery_key,
    generate_session_token,
    hash_credential,
    hash_session_token,
    verify_credential,
    verify_dummy_credential,
)
from app.services.csrf import (
    generate_csrf_token,
    is_allowed_origin,
    verify_csrf_token,
)
from app.services.session import SessionService


@pytest.fixture(autouse=True)
def reset_in_memory_stores():
    """Reset all in-memory repository dictionaries between tests."""
    _IN_MEMORY_CIRCLES.clear()
    _IN_MEMORY_MEMBERS.clear()
    _IN_MEMORY_METADATA.clear()
    _IN_MEMORY_SESSIONS.clear()


def make_csrf_headers(client_instance: TestClient) -> dict:
    """Helper to fetch a fresh CSRF token and return headers with automatic cookie retention."""
    res = client_instance.get("/api/auth/csrf")
    token = res.json()["csrf_token"]
    # TestClient automatically stores the Set-Cookie header in client_instance.cookies
    return {
        "headers": {
            settings.CSRF_HEADER_NAME: token,
            "Origin": "http://testserver",
        },
        "token": token,
    }


# ============================================================================
# 1. Credential Service Tests
# ============================================================================

def test_password_hashing_and_verification():
    """Verify Argon2id hashing and verification logic."""
    password = "CorrectHorseBatteryStaple!123"
    hashed = hash_credential(password)

    # Argon2id identifier prefix
    assert hashed.startswith("$argon2id$")

    # Correct password succeeds
    assert verify_credential(hashed, password) is True

    # Incorrect password fails
    assert verify_credential(hashed, "WrongPassword") is False
    assert verify_credential(hashed, "") is False
    assert verify_credential(None, password) is False


def test_pin_hashing_preserves_leading_zeros():
    """Verify elder PIN hashing preserves leading zeros and matches string exactly."""
    pin = "0123"
    hashed = hash_credential(pin)

    assert verify_credential(hashed, "0123") is True
    assert verify_credential(hashed, "123") is False
    assert verify_credential(hashed, "01234") is False


def test_verify_dummy_credential():
    """Verify dummy credential check executes without raising exceptions."""
    verify_dummy_credential()


def test_token_and_recovery_key_generation():
    """Verify formats of generated tokens and keys."""
    # Recovery Key (24 characters, unambiguous uppercase alphanumeric)
    rec_key = generate_recovery_key()
    assert len(rec_key) == 24
    assert re.match(r"^[A-HJ-NP-Za-hj-np-z2-9]{24}$", rec_key)

    # Session token
    token = generate_session_token()
    assert len(token) >= 32
    token_hash = hash_session_token(token)
    assert len(token_hash) == 64  # SHA-256 hex string

    # Circle code (6 characters, unambiguous uppercase alphanumeric)
    circle_code = generate_circle_code()
    assert len(circle_code) == 6
    assert re.match(r"^[A-HJ-NP-Za-hj-np-z2-9]{6}$", circle_code)


# ============================================================================
# 2. CSRF Service Tests
# ============================================================================

def test_csrf_token_generation_and_validation():
    """Verify CSRF token generation, signature validation, and tamper rejection."""
    token = generate_csrf_token()
    assert verify_csrf_token(token) is True

    # Tampered signature rejected
    parts = token.split(":")
    tampered = f"{parts[0]}:{parts[1]}:badsignature123"
    assert verify_csrf_token(tampered) is False

    # Expired token rejected
    expired_ts = str(int(datetime.now(timezone.utc).timestamp()) - 100000)
    expired_token = f"{parts[0]}:{expired_ts}:{parts[2]}"
    assert verify_csrf_token(expired_token) is False


def test_is_allowed_origin():
    """Verify allowed and blocked origins for CSRF protection."""
    assert is_allowed_origin("http://localhost:8000") is True
    assert is_allowed_origin("http://127.0.0.1:3000") is True
    assert is_allowed_origin("http://testserver") is True
    assert is_allowed_origin("https://carecircle-catalyst.vercel.app") is True
    assert is_allowed_origin("https://carecircle-catalyst-git-master.vercel.app") is True

    # Block attacker origins and unrelated vercel domains
    assert is_allowed_origin("https://evil-attacker.com") is False
    assert is_allowed_origin("https://unrelated-app.vercel.app") is False
    assert is_allowed_origin("http://localhost.attacker.com") is False
    assert is_allowed_origin(None) is False


def test_csrf_protection_on_state_changing_requests():
    """Verify state-changing endpoints reject requests lacking valid CSRF."""
    client = TestClient(app)
    # Attempt login without CSRF header/cookie
    res = client.post(
        "/auth/login",
        json={"username": "sarah", "password": "Password123!"},
    )
    assert res.status_code == 403
    assert "CSRF validation failed" in res.json()["detail"]


# ============================================================================
# 3. First-Circle Bootstrap Tests
# ============================================================================

def test_first_circle_bootstrap_success():
    """Verify successful one-time circle bootstrap provisioning."""
    client = TestClient(app)
    csrf = make_csrf_headers(client)

    payload = {
        "bootstrap_secret": settings.BOOTSTRAP_SECRET,
        "circle_name": "Smith Family Circle",
        "caregiver_name": "Sarah Smith",
        "caregiver_username": "sarah_caregiver",
        "caregiver_password": "StrongPassword123!",
        "elder_name": "Eleanor Smith",
        "elder_pin": "0482",
        "elder_dob": "1945-06-15",
        "primary_condition": "Hypertension",
        "emergency_phone": "+1-555-0199",
    }

    res = client.post(
        "/auth/setup-circle",
        json=payload,
        headers=csrf["headers"],
    )

    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "success"
    assert "circle" in data
    assert len(data["circle"]["circle_code"]) == 6
    assert data["caregiver"]["username"] == "sarah_caregiver"
    assert data["elder"]["display_name"] == "Eleanor Smith"
    assert len(data["recovery_key"]) == 24

    # Verify no raw passwords or PINs stored
    caregiver_record = _IN_MEMORY_MEMBERS[data["caregiver"]["member_id"]]
    elder_record = _IN_MEMORY_MEMBERS[data["elder"]["member_id"]]

    assert "StrongPassword123!" not in str(caregiver_record)
    assert "0482" not in str(elder_record)
    assert caregiver_record["password_hash"].startswith("$argon2id$")
    assert elder_record["password_hash"].startswith("$argon2id$")


def test_first_circle_bootstrap_invalid_secret():
    """Verify bootstrap fails with 403 if bootstrap secret is wrong."""
    client = TestClient(app)
    csrf = make_csrf_headers(client)
    payload = {
        "bootstrap_secret": "incorrect-bootstrap-secret",
        "circle_name": "Test Circle",
        "caregiver_name": "Alice",
        "caregiver_username": "alice",
        "caregiver_password": "Password123!",
        "elder_name": "Bob",
        "elder_pin": "1234",
    }
    res = client.post(
        "/auth/setup-circle",
        json=payload,
        headers=csrf["headers"],
    )
    assert res.status_code == 403
    assert "Invalid bootstrap secret" in res.json()["detail"]


def test_first_circle_bootstrap_prevents_repeated_initialization():
    """Verify bootstrap cannot be executed twice."""
    client = TestClient(app)
    csrf = make_csrf_headers(client)
    payload = {
        "bootstrap_secret": settings.BOOTSTRAP_SECRET,
        "circle_name": "Circle One",
        "caregiver_name": "Alice",
        "caregiver_username": "alice",
        "caregiver_password": "Password123!",
        "elder_name": "Bob",
        "elder_pin": "1234",
    }
    res1 = client.post("/auth/setup-circle", json=payload, headers=csrf["headers"])
    assert res1.status_code == 200

    # Second bootstrap attempt must fail with 400
    res2 = client.post("/auth/setup-circle", json=payload, headers=csrf["headers"])
    assert res2.status_code == 400
    assert "already initialized" in res2.json()["detail"]


# ============================================================================
# 4. Caregiver Login & Lockout Tests
# ============================================================================

@pytest.fixture
def provisioned_circle():
    """Fixture that provisions a circle and returns access details."""
    client = TestClient(app)
    csrf = make_csrf_headers(client)
    payload = {
        "bootstrap_secret": settings.BOOTSTRAP_SECRET,
        "circle_name": "Johnson Care",
        "caregiver_name": "Jane Johnson",
        "caregiver_username": "jane_cg",
        "caregiver_password": "JanePassword123!",
        "elder_name": "Robert Johnson",
        "elder_pin": "0987",
    }
    res = client.post("/auth/setup-circle", json=payload, headers=csrf["headers"])
    return res.json()


def test_caregiver_login_success(provisioned_circle):
    """Verify caregiver login sets HttpOnly cookie and resets failure counters."""
    client = TestClient(app)
    csrf = make_csrf_headers(client)
    res = client.post(
        "/auth/login",
        json={"username": "jane_cg", "password": "JanePassword123!"},
        headers=csrf["headers"],
    )
    assert res.status_code == 200
    assert settings.SESSION_COOKIE_NAME in client.cookies
    data = res.json()
    assert data["status"] == "success"
    assert data["member"]["username"] == "jane_cg"
    assert "password_hash" not in data["member"]


def test_caregiver_login_invalid_password(provisioned_circle):
    """Verify incorrect password returns generic 401 error."""
    client = TestClient(app)
    csrf = make_csrf_headers(client)
    res = client.post(
        "/auth/login",
        json={"username": "jane_cg", "password": "WrongPassword123!"},
        headers=csrf["headers"],
    )
    assert res.status_code == 401
    assert res.json()["detail"] == "Invalid username or password."


def test_caregiver_login_unknown_user_generic_error():
    """Verify non-existent user returns identical generic 401 error."""
    client = TestClient(app)
    csrf = make_csrf_headers(client)
    res = client.post(
        "/auth/login",
        json={"username": "nonexistent_user", "password": "SomePassword123!"},
        headers=csrf["headers"],
    )
    assert res.status_code == 401
    assert res.json()["detail"] == "Invalid username or password."


def test_caregiver_login_lockout_after_max_attempts(provisioned_circle):
    """Verify account locks out after 5 consecutive failed attempts."""
    client = TestClient(app)
    csrf = make_csrf_headers(client)

    # 5 failed attempts
    for i in range(5):
        res = client.post(
            "/auth/login",
            json={"username": "jane_cg", "password": f"WrongAttempt{i}!"},
            headers=csrf["headers"],
        )
        assert res.status_code == 401

    # 6th attempt hits 429 lockout
    res_locked = client.post(
        "/auth/login",
        json={"username": "jane_cg", "password": "JanePassword123!"},
        headers=csrf["headers"],
    )
    assert res_locked.status_code == 429
    assert "temporarily locked" in res_locked.json()["detail"]


# ============================================================================
# 5. Elder Login (Option B) Tests
# ============================================================================

def test_elder_login_success(provisioned_circle):
    """Verify elder login with circle code + name + PIN succeeds."""
    client = TestClient(app)
    csrf = make_csrf_headers(client)
    circle_code = provisioned_circle["circle"]["circle_code"]

    res = client.post(
        "/auth/elder-login",
        json={"circle_code": circle_code, "elder_name": "Robert Johnson", "pin": "0987"},
        headers=csrf["headers"],
    )
    assert res.status_code == 200
    assert settings.SESSION_COOKIE_NAME in client.cookies
    data = res.json()
    assert data["status"] == "success"
    assert data["member"]["display_name"] == "Robert Johnson"
    assert data["member"]["role"] == "elder"


def test_elder_login_invalid_pin(provisioned_circle):
    """Verify wrong PIN returns generic error."""
    client = TestClient(app)
    csrf = make_csrf_headers(client)
    circle_code = provisioned_circle["circle"]["circle_code"]

    res = client.post(
        "/auth/elder-login",
        json={"circle_code": circle_code, "elder_name": "Robert Johnson", "pin": "9999"},
        headers=csrf["headers"],
    )
    assert res.status_code == 401
    assert res.json()["detail"] == "Invalid circle code, name, or passcode. Please try again."


def test_elder_login_invalid_circle_code():
    """Verify incorrect circle code returns identical generic error."""
    client = TestClient(app)
    csrf = make_csrf_headers(client)
    res = client.post(
        "/auth/elder-login",
        json={"circle_code": "ZZZZZZ", "elder_name": "Robert Johnson", "pin": "0987"},
        headers=csrf["headers"],
    )
    assert res.status_code == 401
    assert res.json()["detail"] == "Invalid circle code, name, or passcode. Please try again."


# ============================================================================
# 6. Session Management & Multi-Device Concurrency Tests
# ============================================================================

def test_session_multi_device_concurrency(provisioned_circle):
    """Verify multiple concurrent device sessions can exist simultaneously."""
    # Device 1
    device1 = TestClient(app)
    csrf1 = make_csrf_headers(device1)
    res1 = device1.post(
        "/auth/login",
        json={"username": "jane_cg", "password": "JanePassword123!"},
        headers=csrf1["headers"],
    )
    assert res1.status_code == 200
    token1 = device1.cookies[settings.SESSION_COOKIE_NAME]

    # Device 2
    device2 = TestClient(app)
    csrf2 = make_csrf_headers(device2)
    res2 = device2.post(
        "/auth/login",
        json={"username": "jane_cg", "password": "JanePassword123!"},
        headers=csrf2["headers"],
    )
    assert res2.status_code == 200
    token2 = device2.cookies[settings.SESSION_COOKIE_NAME]

    # Both tokens are distinct
    assert token1 != token2

    # Device 1 is still authenticated
    me1 = device1.get("/api/auth/me")
    assert me1.status_code == 200
    assert me1.json()["authenticated"] is True

    # Device 2 is also authenticated
    me2 = device2.get("/api/auth/me")
    assert me2.status_code == 200
    assert me2.json()["authenticated"] is True


def test_session_persistence_after_refresh(provisioned_circle):
    """Verify session cookie persists across multiple subsequent requests and page navigations."""
    client = TestClient(app)
    csrf = make_csrf_headers(client)

    # 1. Login
    login_res = client.post(
        "/auth/login",
        json={"username": "jane_cg", "password": "JanePassword123!"},
        headers=csrf["headers"],
    )
    assert login_res.status_code == 200
    session_cookie = client.cookies.get(settings.SESSION_COOKIE_NAME)
    assert session_cookie is not None

    # 2. Simulate subsequent request 1 (Dashboard / Landing)
    page_res = client.get("/")
    assert page_res.status_code == 200
    assert "jane_cg" in page_res.text or "Jane Johnson" in page_res.text

    # 3. Simulate subsequent request 2 (API status probe)
    me_res = client.get("/api/auth/me")
    assert me_res.status_code == 200
    assert me_res.json()["authenticated"] is True
    assert me_res.json()["member"]["username"] == "jane_cg"

    # 4. Simulate subsequent request 3 (Re-check status)
    me_res_repeat = client.get("/api/auth/me")
    assert me_res_repeat.status_code == 200
    assert me_res_repeat.json()["authenticated"] is True


def test_logout_revokes_only_current_session(provisioned_circle):
    """Verify logout revokes the current device without logging out other devices."""
    device1 = TestClient(app)
    csrf1 = make_csrf_headers(device1)
    device1.post(
        "/auth/login",
        json={"username": "jane_cg", "password": "JanePassword123!"},
        headers=csrf1["headers"],
    )

    device2 = TestClient(app)
    csrf2 = make_csrf_headers(device2)
    device2.post(
        "/auth/login",
        json={"username": "jane_cg", "password": "JanePassword123!"},
        headers=csrf2["headers"],
    )

    # Logout from Device 1
    csrf1_logout = make_csrf_headers(device1)
    logout_res = device1.post(
        "/auth/logout",
        headers=csrf1_logout["headers"],
    )
    assert logout_res.status_code == 200

    # Device 1 is revoked
    me1 = device1.get("/api/auth/me")
    assert me1.json()["authenticated"] is False

    # Device 2 remains authenticated!
    me2 = device2.get("/api/auth/me")
    assert me2.json()["authenticated"] is True


def test_global_revocation_via_auth_version(provisioned_circle):
    """Verify incrementing auth_version revokes all active sessions across all devices."""
    device1 = TestClient(app)
    csrf1 = make_csrf_headers(device1)
    device1.post(
        "/auth/login",
        json={"username": "jane_cg", "password": "JanePassword123!"},
        headers=csrf1["headers"],
    )

    device2 = TestClient(app)
    csrf2 = make_csrf_headers(device2)
    device2.post(
        "/auth/login",
        json={"username": "jane_cg", "password": "JanePassword123!"},
        headers=csrf2["headers"],
    )

    # Change password from Device 1
    csrf1_change = make_csrf_headers(device1)
    change_res = device1.post(
        "/api/members/change-password",
        json={"current_password": "JanePassword123!", "new_password": "BrandNewPassword456!"},
        headers=csrf1_change["headers"],
    )
    assert change_res.status_code == 200

    # Both old sessions are now invalid because member auth_version incremented
    me1 = device1.get("/api/auth/me")
    assert me1.json()["authenticated"] is False

    me2 = device2.get("/api/auth/me")
    assert me2.json()["authenticated"] is False

    # New password works for subsequent login
    device3 = TestClient(app)
    csrf3 = make_csrf_headers(device3)
    login_new = device3.post(
        "/auth/login",
        json={"username": "jane_cg", "password": "BrandNewPassword456!"},
        headers=csrf3["headers"],
    )
    assert login_new.status_code == 200


# ============================================================================
# 7. Role-Based Authorization Tests
# ============================================================================

def test_role_guard_elder_cannot_access_caregiver_endpoint(provisioned_circle):
    """Verify an elder session cannot invoke caregiver-restricted endpoints."""
    client = TestClient(app)
    csrf = make_csrf_headers(client)
    circle_code = provisioned_circle["circle"]["circle_code"]

    client.post(
        "/auth/elder-login",
        json={"circle_code": circle_code, "elder_name": "Robert Johnson", "pin": "0987"},
        headers=csrf["headers"],
    )

    # Elder attempts to reset elder PIN (caregiver only)
    csrf_elder = make_csrf_headers(client)
    reset_res = client.post(
        f"/api/members/{provisioned_circle['elder']['member_id']}/reset-pin",
        json={"new_pin": "5555"},
        headers=csrf_elder["headers"],
    )
    assert reset_res.status_code == 403
    assert "Access forbidden" in reset_res.json()["detail"]


# ============================================================================
# 8. Emergency Credential Recovery Tests
# ============================================================================

def test_emergency_recovery_workflow(provisioned_circle):
    """Verify emergency recovery key resets password, invalidates sessions, and rotates key."""
    client = TestClient(app)
    csrf = make_csrf_headers(client)
    recovery_key = provisioned_circle["recovery_key"]

    rec_res = client.post(
        "/auth/recover",
        json={
            "username": "jane_cg",
            "recovery_key": recovery_key,
            "new_password": "RecoveredPassword789!",
        },
        headers=csrf["headers"],
    )
    assert rec_res.status_code == 200
    rec_data = rec_res.json()
    new_recovery_key = rec_data["recovery_key"]
    assert new_recovery_key != recovery_key
    assert len(new_recovery_key) == 24

    # Old password no longer works
    csrf2 = make_csrf_headers(client)
    login_old = client.post(
        "/auth/login",
        json={"username": "jane_cg", "password": "JanePassword123!"},
        headers=csrf2["headers"],
    )
    assert login_old.status_code == 401

    # New password succeeds
    csrf3 = make_csrf_headers(client)
    login_new = client.post(
        "/auth/login",
        json={"username": "jane_cg", "password": "RecoveredPassword789!"},
        headers=csrf3["headers"],
    )
    assert login_new.status_code == 200

    # Old recovery key cannot be reused
    csrf4 = make_csrf_headers(client)
    reuse_res = client.post(
        "/auth/recover",
        json={
            "username": "jane_cg",
            "recovery_key": recovery_key,
            "new_password": "AnotherPassword999!",
        },
        headers=csrf4["headers"],
    )
    assert reuse_res.status_code == 400


# ============================================================================
# 9. Mandatory Sanitized Validation Error Tests (Section 8)
# ============================================================================

def test_validation_error_strips_sensitive_inputs():
    """
    MANDATORY REQUIREMENT (Section 8):
    Verify that Pydantic validation errors strip the raw 'input' property and do not leak
    passwords, PINs, recovery keys, or bootstrap secrets in HTTP 422 responses.
    """
    client = TestClient(app)
    csrf = make_csrf_headers(client)

    # 1. Invalid LoginRequest with recognizable secret
    dummy_pass = "DUMMY_SECRET_PASS_998877"
    res1 = client.post(
        "/auth/login",
        json={"username": "", "password": dummy_pass},  # empty username triggers 422
        headers=csrf["headers"],
    )
    assert res1.status_code == 422
    body1 = res1.text
    assert dummy_pass not in body1
    for err in res1.json()["detail"]:
        assert "input" not in err

    # 2. Invalid ElderLoginRequest with recognizable PIN
    dummy_pin = "0077"
    res2 = client.post(
        "/auth/elder-login",
        json={"circle_code": "INVALID_CODE_TOO_LONG", "elder_name": "Eleanor", "pin": dummy_pin},
        headers=csrf["headers"],
    )
    assert res2.status_code == 422
    body2 = res2.text
    assert dummy_pin not in body2
    for err in res2.json()["detail"]:
        assert "input" not in err

    # 3. Invalid CircleCreateRequest with recognizable bootstrap secret
    dummy_bootstrap = "DUMMY_BOOTSTRAP_SECRET_XYZ_99"
    dummy_caregiver_pass = "DUMMY_CAREGIVER_PW_1234"
    res3 = client.post(
        "/auth/setup-circle",
        json={
            "bootstrap_secret": dummy_bootstrap,
            "circle_name": "",  # triggers 422
            "caregiver_name": "A",
            "caregiver_username": "a",
            "caregiver_password": dummy_caregiver_pass,
            "elder_name": "B",
            "elder_pin": "12",
        },
        headers=csrf["headers"],
    )
    assert res3.status_code == 422
    body3 = res3.text
    assert dummy_bootstrap not in body3
    assert dummy_caregiver_pass not in body3
    for err in res3.json()["detail"]:
        assert "input" not in err

    # 4. Invalid RecoveryRequest with recognizable recovery key
    dummy_rec = "DUMMY_RECOVERY_KEY_ABCDEF1234567890"
    res4 = client.post(
        "/auth/recover",
        json={"username": "", "recovery_key": dummy_rec, "new_password": "short"},
        headers=csrf["headers"],
    )
    assert res4.status_code == 422
    body4 = res4.text
    assert dummy_rec not in body4
    for err in res4.json()["detail"]:
        assert "input" not in err
