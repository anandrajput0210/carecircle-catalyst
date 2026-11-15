"""Comprehensive Phase 4 Tests: Care Circle Management, Membership, Invitations & Access Control."""
from datetime import datetime, timedelta, timezone
import hashlib
import re
import pytest
from fastapi.testclient import TestClient

from app.config import settings
from app.main import app
from app.models.auth import MemberRole
from app.repositories.firestore_circle import (
    _IN_MEMORY_CIRCLES,
    _IN_MEMORY_MEMBERS,
    _IN_MEMORY_METADATA,
)
from app.repositories.firestore_invitation import _IN_MEMORY_INVITATIONS
from app.repositories.firestore_session import _IN_MEMORY_SESSIONS
from app.services.auth import hash_credential, verify_credential


@pytest.fixture(autouse=True)
def reset_in_memory_stores():
    """Reset all in-memory repository dictionaries between tests."""
    _IN_MEMORY_CIRCLES.clear()
    _IN_MEMORY_MEMBERS.clear()
    _IN_MEMORY_METADATA.clear()
    _IN_MEMORY_SESSIONS.clear()
    _IN_MEMORY_INVITATIONS.clear()


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


def setup_primary_circle_and_login() -> tuple[TestClient, dict]:
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
        "/api/auth/login",
        json={"username": "sarah_primary", "password": "PrimaryPassword123!"},
        headers=csrf_login["headers"],
    )
    assert login_res.status_code == 200, login_res.text

    return client, circle_data


# ============================================================================
# 1. Circle Overview Tests
# ============================================================================

def test_get_circle_overview_authenticated():
    """Verify authenticated member can retrieve circle overview with active member count."""
    client, data = setup_primary_circle_and_login()

    res = client.get("/api/circle")
    assert res.status_code == 200
    circle = res.json()

    assert circle["name"] == "Sunrise Haven"
    assert circle["circle_id"] == data["circle"]["circle_id"]
    assert circle["circle_code"] == data["circle"]["circle_code"]
    assert circle["active_member_count"] == 2  # Sarah (caregiver) + Eleanor (elder)
    assert circle["elder_profile"]["name"] == "Eleanor Vance"
    assert circle["elder_profile"]["primary_condition"] == "Mild Cognitive Impairment"
    assert circle["is_active"] is True


def test_get_circle_overview_unauthenticated():
    """Verify unauthenticated request to /api/circle returns 401."""
    client = TestClient(app)
    res = client.get("/api/circle")
    assert res.status_code == 401


# ============================================================================
# 2. Circle Metadata Update Tests
# ============================================================================

def test_patch_circle_primary_caregiver_success():
    """Verify Primary Caregiver can update circle name and elder profile."""
    client, data = setup_primary_circle_and_login()
    csrf = make_csrf_headers(client)

    patch_payload = {
        "circle_name": "Sunrise Haven Enhanced",
        "elder_name": "Eleanor M. Vance",
        "primary_condition": "Early-stage Alzheimer's",
        "emergency_phone": "+1-555-0999",
    }

    res = client.patch("/api/circle", json=patch_payload, headers=csrf["headers"])
    assert res.status_code == 200
    updated = res.json()

    assert updated["name"] == "Sunrise Haven Enhanced"
    assert updated["elder_profile"]["name"] == "Eleanor M. Vance"
    assert updated["elder_profile"]["primary_condition"] == "Early-stage Alzheimer's"
    assert updated["elder_profile"]["emergency_phone"] == "+1-555-0999"
    # Preserves unchanged DOB
    assert updated["elder_profile"]["dob"] == "1940-08-20"


def test_patch_circle_updates_elder_member_display_name_sync():
    """Verify updating elder name in elder profile synchronizes elder member's display name."""
    client, data = setup_primary_circle_and_login()
    csrf = make_csrf_headers(client)

    elder_id = data["elder"]["member_id"]
    assert _IN_MEMORY_MEMBERS[elder_id]["display_name"] == "Eleanor Vance"

    res = client.patch(
        "/api/circle",
        json={"elder_name": "Eleanor Margaret Vance"},
        headers=csrf["headers"],
    )
    assert res.status_code == 200

    assert _IN_MEMORY_MEMBERS[elder_id]["display_name"] == "Eleanor Margaret Vance"


def test_patch_circle_empty_payload_rejected():
    """Verify empty patch payload is rejected with 422."""
    client, data = setup_primary_circle_and_login()
    csrf = make_csrf_headers(client)

    res = client.patch("/api/circle", json={}, headers=csrf["headers"])
    assert res.status_code == 422


def test_patch_circle_requires_csrf():
    """Verify PATCH /api/circle strictly rejects missing CSRF header with 403."""
    client, data = setup_primary_circle_and_login()

    res = client.patch(
        "/api/circle",
        json={"circle_name": "No CSRF Circle"},
    )
    assert res.status_code == 403


# ============================================================================
# 3. Membership Roster Tests
# ============================================================================

def test_list_circle_members_sanitized():
    """Verify member listing returns sanitized responses without credential hashes."""
    client, data = setup_primary_circle_and_login()

    res = client.get("/api/circle/members")
    assert res.status_code == 200
    members = res.json()

    assert len(members) == 2
    for m in members:
        # Strict credential protection
        assert "password_hash" not in m
        assert "pin_hash" not in m
        assert "recovery_key_hash" not in m
        assert "password" not in m
        assert "pin" not in m
        assert "auth_version" not in m  # Internal version hidden from public responses
        assert m["is_active"] is True


def test_get_single_member_detail():
    """Verify single member retrieval works with circle isolation."""
    client, data = setup_primary_circle_and_login()
    caregiver_id = data["caregiver"]["member_id"]

    res = client.get(f"/api/circle/members/{caregiver_id}")
    assert res.status_code == 200
    member = res.json()

    assert member["member_id"] == caregiver_id
    assert member["username"] == "sarah_primary"
    assert member["role"] == "caregiver"
    assert member["is_primary"] is True


def test_get_member_cross_circle_isolation():
    """Verify member from Circle A cannot retrieve a member from Circle B."""
    client_a, data_a = setup_primary_circle_and_login()

    # Directly inject a member into another circle
    other_member_id = "other-circle-member-123"
    _IN_MEMORY_MEMBERS[other_member_id] = {
        "member_id": other_member_id,
        "circle_id": "other-circle-uuid",
        "username": "other_user",
        "display_name": "Other User",
        "role": "family",
        "auth_type": "password",
        "is_active": True,
        "is_primary": False,
        "password_hash": "$argon2id$v=19$m=65536,t=2,p=1$fake$fake",
        "auth_version": 1,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }

    res = client_a.get(f"/api/circle/members/{other_member_id}")
    assert res.status_code == 404


# ============================================================================
# 4. Member Deactivation Tests
# ============================================================================

def test_deactivate_member_sole_primary_caregiver_rejected():
    """Verify sole active primary caregiver CANNOT be deactivated."""
    client, data = setup_primary_circle_and_login()
    csrf = make_csrf_headers(client)

    primary_id = data["caregiver"]["member_id"]

    res = client.post(
        f"/api/circle/members/{primary_id}/deactivate",
        headers=csrf["headers"],
    )
    assert res.status_code == 400
    assert "only active primary caregiver" in res.json()["detail"].lower()


def test_deactivate_secondary_member_success_and_session_revocation():
    """
    Verify Primary Caregiver can deactivate another member.
    Verify deactivation sets is_active=False, records deactivated_at,
    and immediately revokes the target member's active sessions via auth_version.
    """
    primary_client, data = setup_primary_circle_and_login()
    circle_id = data["circle"]["circle_id"]

    # 1. Invite and register a secondary caregiver
    csrf_primary = make_csrf_headers(primary_client)
    invite_res = primary_client.post(
        "/api/circle/invitations",
        json={"role": "caregiver", "invited_name": "Nurse Bob"},
        headers=csrf_primary["headers"],
    )
    assert invite_res.status_code == 201
    raw_token = invite_res.json()["raw_token"]

    # 2. Bob accepts invitation
    bob_client = TestClient(app)
    csrf_bob = make_csrf_headers(bob_client)
    accept_res = bob_client.post(
        "/api/invitations/accept",
        json={
            "invite_token": raw_token,
            "username": "nurse_bob",
            "display_name": "Nurse Bob",
            "password": "BobPassword123!",
        },
        headers=csrf_bob["headers"],
    )
    assert accept_res.status_code == 200
    bob_id = accept_res.json()["member"]["member_id"]

    # Bob can access /api/circle
    bob_circle_res = bob_client.get("/api/circle")
    assert bob_circle_res.status_code == 200
    assert bob_circle_res.json()["active_member_count"] == 3

    # 3. Primary caregiver deactivates Bob
    deact_res = primary_client.post(
        f"/api/circle/members/{bob_id}/deactivate",
        headers=csrf_primary["headers"],
    )
    assert deact_res.status_code == 200
    deact_data = deact_res.json()
    assert deact_data["status"] == "success"
    assert deact_data["member"]["is_active"] is False
    assert deact_data["member"]["deactivated_at"] is not None

    # 4. Invariant: Historical record is preserved in repository
    assert bob_id in _IN_MEMORY_MEMBERS
    assert _IN_MEMORY_MEMBERS[bob_id]["is_active"] is False

    # 5. Invariant: Bob's existing active session is immediately rejected (401)
    bob_followup = bob_client.get("/api/circle")
    assert bob_followup.status_code == 401

    # Active member count drops back to 2
    circle_res = primary_client.get("/api/circle")
    assert circle_res.json()["active_member_count"] == 2


def test_deactivate_member_forbidden_for_non_primary():
    """Verify non-primary caregivers cannot deactivate members."""
    primary_client, data = setup_primary_circle_and_login()

    # Invite a secondary caregiver
    csrf_primary = make_csrf_headers(primary_client)
    invite_res = primary_client.post(
        "/api/circle/invitations",
        json={"role": "caregiver"},
        headers=csrf_primary["headers"],
    )
    raw_token = invite_res.json()["raw_token"]

    bob_client = TestClient(app)
    csrf_bob = make_csrf_headers(bob_client)
    bob_client.post(
        "/api/invitations/accept",
        json={
            "invite_token": raw_token,
            "username": "nurse_bob2",
            "display_name": "Nurse Bob 2",
            "password": "BobPassword123!",
        },
        headers=csrf_bob["headers"],
    )

    # Bob attempts to deactivate the elder
    elder_id = data["elder"]["member_id"]
    csrf_bob2 = make_csrf_headers(bob_client)
    res = bob_client.post(
        f"/api/circle/members/{elder_id}/deactivate",
        headers=csrf_bob2["headers"],
    )
    assert res.status_code == 403


# ============================================================================
# 5. Invitation Lifecycle Tests
# ============================================================================

def test_create_invitation_success_and_token_storage():
    """
    Verify invitation creation:
    - Primary caregiver can create 48h single-use invitation.
    - Raw token is NOT stored in Firestore document (only SHA-256 token_hash).
    """
    client, data = setup_primary_circle_and_login()
    csrf = make_csrf_headers(client)

    payload = {
        "role": "family",
        "invited_name": "Grandson Leo",
        "invited_email": "leo@example.com",
    }

    res = client.post("/api/circle/invitations", json=payload, headers=csrf["headers"])
    assert res.status_code == 201
    resp_data = res.json()

    raw_token = resp_data["raw_token"]
    assert len(raw_token) >= 32
    assert "/invite/accept?token=" in resp_data["invite_url"]
    assert resp_data["invitation"]["role"] == "family"
    assert resp_data["invitation"]["invited_name"] == "Grandson Leo"
    assert resp_data["invitation"]["status"] == "pending"

    # Verify repository storage
    inv_id = resp_data["invitation"]["invitation_id"]
    stored_doc = _IN_MEMORY_INVITATIONS[inv_id]

    # Invariant: Raw token is never stored in Firestore!
    assert raw_token not in str(stored_doc)
    expected_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
    assert stored_doc["token_hash"] == expected_hash


def test_create_invitation_for_elder_role_strictly_rejected():
    """Verify attempting to invite an elder via an invitation link is strictly rejected with 422."""
    client, data = setup_primary_circle_and_login()
    csrf = make_csrf_headers(client)

    payload = {
        "role": "elder",
        "invited_name": "Senior Friend",
    }

    res = client.post("/api/circle/invitations", json=payload, headers=csrf["headers"])
    assert res.status_code == 422
    assert "elders cannot be added via invitation links" in res.text.lower()


def test_list_and_revoke_invitations():
    """Verify listing invitations and revoking a pending invitation link."""
    client, data = setup_primary_circle_and_login()
    csrf = make_csrf_headers(client)

    # Create invitation
    inv_res = client.post(
        "/api/circle/invitations",
        json={"role": "family", "invited_name": "Cousin Clara"},
        headers=csrf["headers"],
    )
    inv_id = inv_res.json()["invitation"]["invitation_id"]
    raw_token = inv_res.json()["raw_token"]

    # List invitations
    list_res = client.get("/api/circle/invitations")
    assert list_res.status_code == 200
    invitations = list_res.json()
    assert len(invitations) >= 1
    target = next(i for i in invitations if i["invitation_id"] == inv_id)
    assert target["status"] == "pending"
    assert "token_hash" not in target

    # Revoke invitation
    csrf_revoke = make_csrf_headers(client)
    revoke_res = client.post(
        f"/api/circle/invitations/{inv_id}/revoke",
        headers=csrf_revoke["headers"],
    )
    assert revoke_res.status_code == 200
    assert revoke_res.json()["status"] == "success"

    # Inspecting revoked token returns 400
    inspect_res = client.get(f"/api/invitations/inspect?token={raw_token}")
    assert inspect_res.status_code == 400
    assert "revoked" in inspect_res.json()["detail"].lower()


# ============================================================================
# 6. Invitation Redemption & Concurrency Tests
# ============================================================================

def test_accept_invitation_success_and_session_cookie():
    """
    Verify accepting an invitation:
    - Creates member with assigned role.
    - Hashes password using Argon2id.
    - Sets HttpOnly session cookie.
    - Updates invitation status to 'accepted'.
    """
    primary_client, data = setup_primary_circle_and_login()
    csrf = make_csrf_headers(primary_client)

    inv_res = primary_client.post(
        "/api/circle/invitations",
        json={"role": "family", "invited_name": "Uncle Frank"},
        headers=csrf["headers"],
    )
    raw_token = inv_res.json()["raw_token"]

    # Public inspect succeeds
    inspect_res = primary_client.get(f"/api/invitations/inspect?token={raw_token}")
    assert inspect_res.status_code == 200
    inspect_data = inspect_res.json()
    assert inspect_data["valid"] is True
    assert inspect_data["circle_name"] == "Sunrise Haven"
    assert inspect_data["role"] == "family"

    # Accept invitation as Frank
    frank_client = TestClient(app)
    csrf_frank = make_csrf_headers(frank_client)

    join_payload = {
        "invite_token": raw_token,
        "username": "uncle_frank",
        "display_name": "Uncle Frank",
        "password": "FrankPassword123!",
    }

    accept_res = frank_client.post(
        "/api/invitations/accept",
        json=join_payload,
        headers=csrf_frank["headers"],
    )
    assert accept_res.status_code == 200
    member_data = accept_res.json()["member"]
    assert member_data["username"] == "uncle_frank"
    assert member_data["role"] == "family"
    assert member_data["is_primary"] is False

    # Check password hash in repository
    frank_id = member_data["member_id"]
    frank_doc = _IN_MEMORY_MEMBERS[frank_id]
    assert verify_credential(frank_doc["password_hash"], "FrankPassword123!") is True
    assert "FrankPassword123!" not in str(frank_doc)

    # Frank now has an active session cookie and can access circle API
    circle_res = frank_client.get("/api/circle")
    assert circle_res.status_code == 200
    assert circle_res.json()["name"] == "Sunrise Haven"


def test_accept_invitation_single_use_replay_prevention():
    """Verify an invitation token cannot be redeemed twice."""
    primary_client, data = setup_primary_circle_and_login()
    csrf = make_csrf_headers(primary_client)

    inv_res = primary_client.post(
        "/api/circle/invitations",
        json={"role": "caregiver"},
        headers=csrf["headers"],
    )
    raw_token = inv_res.json()["raw_token"]

    # First redemption succeeds
    client1 = TestClient(app)
    csrf1 = make_csrf_headers(client1)
    res1 = client1.post(
        "/api/invitations/accept",
        json={
            "invite_token": raw_token,
            "username": "member_one",
            "display_name": "Member One",
            "password": "PasswordOne123!",
        },
        headers=csrf1["headers"],
    )
    assert res1.status_code == 200

    # Second redemption with same token fails with 400
    client2 = TestClient(app)
    csrf2 = make_csrf_headers(client2)
    res2 = client2.post(
        "/api/invitations/accept",
        json={
            "invite_token": raw_token,
            "username": "member_two",
            "display_name": "Member Two",
            "password": "PasswordTwo123!",
        },
        headers=csrf2["headers"],
    )
    assert res2.status_code == 400
    assert "already been used" in res2.json()["detail"].lower()


def test_accept_invitation_expired_rejected():
    """Verify expired invitations cannot be accepted."""
    primary_client, data = setup_primary_circle_and_login()
    csrf = make_csrf_headers(primary_client)

    inv_res = primary_client.post(
        "/api/circle/invitations",
        json={"role": "caregiver"},
        headers=csrf["headers"],
    )
    raw_token = inv_res.json()["raw_token"]
    inv_id = inv_res.json()["invitation"]["invitation_id"]

    # Simulate expired timestamp in document
    past_iso = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
    _IN_MEMORY_INVITATIONS[inv_id]["expires_at"] = past_iso

    client = TestClient(app)
    csrf_c = make_csrf_headers(client)
    res = client.post(
        "/api/invitations/accept",
        json={
            "invite_token": raw_token,
            "username": "late_user",
            "display_name": "Late User",
            "password": "PasswordLate123!",
        },
        headers=csrf_c["headers"],
    )
    assert res.status_code == 400
    assert "expired" in res.json()["detail"].lower()


def test_accept_invitation_username_collision_rejected():
    """Verify duplicate username returns 409 Conflict without consuming the invitation token."""
    primary_client, data = setup_primary_circle_and_login()
    csrf = make_csrf_headers(primary_client)

    inv_res = primary_client.post(
        "/api/circle/invitations",
        json={"role": "caregiver"},
        headers=csrf["headers"],
    )
    raw_token = inv_res.json()["raw_token"]

    # Attempt to accept with sarah_primary username (already taken)
    client = TestClient(app)
    csrf_c = make_csrf_headers(client)
    res = client.post(
        "/api/invitations/accept",
        json={
            "invite_token": raw_token,
            "username": "sarah_primary",  # Collision!
            "display_name": "Impostor Sarah",
            "password": "Password123!",
        },
        headers=csrf_c["headers"],
    )
    assert res.status_code == 409
    assert "already taken" in res.json()["detail"].lower()

    # Invitation token remains pending and usable with another username
    csrf_c2 = make_csrf_headers(client)
    retry_res = client.post(
        "/api/invitations/accept",
        json={
            "invite_token": raw_token,
            "username": "valid_sarah_alias",
            "display_name": "Sarah Alias",
            "password": "Password123!",
        },
        headers=csrf_c2["headers"],
    )
    assert retry_res.status_code == 200


def test_accept_invitation_credential_leakage_prevented_on_validation_error():
    """Verify raw password never leaks in 422 validation error responses."""
    client = TestClient(app)
    csrf = make_csrf_headers(client)

    dummy_secret = "LEAK_CHECK_SECRET_PHASE4_9999"

    # Submitting an invalid payload (e.g. password too short)
    res = client.post(
        "/api/invitations/accept",
        json={
            "invite_token": "valid_token_string_here_12345",
            "username": "test_user",
            "display_name": "Test User",
            "password": "123",  # Too short (< 8 chars)
        },
        headers=csrf["headers"],
    )
    assert res.status_code == 422
    assert "123" not in res.text
    for err in res.json()["detail"]:
        assert "input" not in err


# ============================================================================
# 7. HTML Web View Tests
# ============================================================================

def test_circle_overview_page_authenticated():
    """Verify GET /circle renders HTML with circle overview for logged-in user."""
    client, data = setup_primary_circle_and_login()

    res = client.get("/circle")
    assert res.status_code == 200
    assert "text/html" in res.headers["content-type"]
    assert "Sunrise Haven" in res.text
    assert "Eleanor Vance" in res.text
    assert "Circle Membership Roster" in res.text
    assert "Active &amp; Recent Invitations" in res.text


def test_circle_overview_page_unauthenticated_redirects():
    """Verify GET /circle redirects to /auth/login when not authenticated."""
    client = TestClient(app)
    res = client.get("/circle", follow_redirects=False)
    assert res.status_code == 302
    assert res.headers["location"] == "/auth/login"


def test_accept_invitation_page_renders():
    """Verify GET /invite/accept renders HTML invitation acceptance page."""
    client = TestClient(app)
    res = client.get("/invite/accept?token=sample_token_123")
    assert res.status_code == 200
    assert "text/html" in res.headers["content-type"]
    assert "Join CareCircle" in res.text
    assert "sample_token_123" in res.text
