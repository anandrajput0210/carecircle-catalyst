"""Comprehensive validation and regression tests for CareCircle Authentication & Identity models."""
import pytest
from datetime import datetime, timezone, timedelta
from pydantic import ValidationError

from app.models.auth import (
    MemberRole,
    AuthType,
    LoginRequest,
    ElderLoginRequest,
    CircleCreateRequest,
    MemberInviteRequest,
    MemberJoinRequest,
    RecoveryRequest,
    CredentialResetRequest,
    MemberDoc,
    SessionDoc,
    SessionData,
    MemberPublicResponse,
    CirclePublicResponse,
    RecoveryKeyResponse,
    AuthStatusResponse,
    parse_and_normalize_iso_utc,
)


# ============================================================================
# 1. Enums
# ============================================================================

def test_member_role_and_auth_type_enums():
    """Verify enum members and values."""
    assert MemberRole.ELDER.value == "elder"
    assert MemberRole.CAREGIVER.value == "caregiver"
    assert MemberRole.FAMILY.value == "family"

    assert AuthType.PASSWORD.value == "password"
    assert AuthType.PASSCODE.value == "passcode"
    assert AuthType.RECOVERY_KEY.value == "recovery_key"

    with pytest.raises(ValueError):
        MemberRole("superadmin")


# ============================================================================
# 2. Password Whitespace & Casing Preservation
# ============================================================================

def test_login_request_preserves_password_whitespace_and_case():
    """Verify passwords preserve exact input including leading/trailing spaces and mixed case."""
    raw_pass = "  Secret Password with Spaces 123!  "
    req = LoginRequest(username="  Sarah.Caregiver@Example.COM  ", password=raw_pass)
    # Username normalized: trimmed and lowercased
    assert req.username == "sarah.caregiver@example.com"
    # Password exact: whitespace and casing strictly preserved
    assert req.password == raw_pass
    assert req.password.startswith("  ")
    assert req.password.endswith("  ")


def test_circle_create_request_preserves_password_whitespace():
    """Verify CircleCreateRequest preserves caregiver password exact whitespace."""
    raw_pass = "  Caregiver Pass 123!  "
    req = CircleCreateRequest(
        bootstrap_secret="  secret-bootstrap-key  ",
        circle_name="  Eleanor Circle  ",
        caregiver_name="  Sarah Nurse  ",
        caregiver_username="  Sarah@Family.org ",
        caregiver_password=raw_pass,
        elder_name="  Eleanor Smith  ",
        elder_pin="0123",
    )
    assert req.circle_name == "Eleanor Circle"
    assert req.caregiver_name == "Sarah Nurse"
    assert req.caregiver_username == "sarah@family.org"
    assert req.elder_name == "Eleanor Smith"
    assert req.caregiver_password == raw_pass
    assert req.caregiver_password.startswith("  ")


def test_member_join_request_preserves_password_whitespace():
    """Verify MemberJoinRequest preserves password exact whitespace."""
    raw_pass = "  JoinedPass 123!  "
    req = MemberJoinRequest(
        invite_token="token_1234567890abcdef",
        username="  Tim.Family@Example.com ",
        display_name="  Tim Smith  ",
        password=raw_pass,
    )
    assert req.username == "tim.family@example.com"
    assert req.display_name == "Tim Smith"
    assert req.password == raw_pass


def test_recovery_request_preserves_password_whitespace():
    """Verify RecoveryRequest preserves new password exact whitespace."""
    raw_pass = "  BrandNewPassword 123!  "
    req = RecoveryRequest(
        username="  CaregiverUser ",
        recovery_key="  rec_key_1234567890abcdef  ",
        new_password=raw_pass,
    )
    assert req.username == "caregiveruser"
    assert req.recovery_key == "rec_key_1234567890abcdef"  # key stripped
    assert req.new_password == raw_pass  # password exact


# ============================================================================
# 3. Credential & Secret Repr Masking
# ============================================================================

def test_credential_repr_masking():
    """Verify plaintext passwords, PINs, recovery keys, and bootstrap secrets do not appear in repr()."""
    login_req = LoginRequest(username="sarah", password="SuperSecretPassword123")
    repr_login = repr(login_req)
    assert "SuperSecretPassword123" not in repr_login
    assert "password" not in repr_login

    elder_req = ElderLoginRequest(circle_code="C7K9W2", elder_name="Eleanor", pin="0042")
    repr_elder = repr(elder_req)
    assert "0042" not in repr_elder
    assert "pin" not in repr_elder

    circle_req = CircleCreateRequest(
        bootstrap_secret="MyBootstrapSecret123",
        circle_name="Circle",
        caregiver_name="Sarah",
        caregiver_username="sarah",
        caregiver_password="CaregiverPassword123!",
        elder_name="Eleanor",
        elder_pin="0505",
    )
    repr_circle = repr(circle_req)
    assert "MyBootstrapSecret123" not in repr_circle
    assert "CaregiverPassword123!" not in repr_circle
    assert "0505" not in repr_circle

    join_req = MemberJoinRequest(
        invite_token="InviteSecretToken123456",
        username="tim",
        display_name="Tim",
        password="MySecretPassword123",
    )
    repr_join = repr(join_req)
    assert "InviteSecretToken123456" not in repr_join
    assert "MySecretPassword123" not in repr_join

    rec_req = RecoveryRequest(
        username="sarah",
        recovery_key="RecSecretKey1234567890",
        new_password="NewSecretPassword123!",
    )
    repr_rec = repr(rec_req)
    assert "RecSecretKey1234567890" not in repr_rec
    assert "NewSecretPassword123!" not in repr_rec

    rec_resp = RecoveryKeyResponse(recovery_key="RecKeyDisplayOnce123456")
    assert "RecKeyDisplayOnce123456" not in repr(rec_resp)


def test_member_and_session_doc_repr_masking():
    """Verify internal Firestore document models mask sensitive hashes and session IDs in repr()."""
    member = MemberDoc(
        member_id="mem_123",
        circle_id="circle_456",
        username="sarah",
        display_name="Sarah",
        role=MemberRole.CAREGIVER,
        auth_type=AuthType.PASSWORD,
        password_hash="$argon2id$v=19$m=65536,t=2,p=1$my_secret_hash_value",
        recovery_key_hash="$argon2id$v=19$m=65536,t=2,p=1$my_rec_hash_value",
    )
    repr_member = repr(member)
    assert "my_secret_hash_value" not in repr_member
    assert "my_rec_hash_value" not in repr_member
    assert "password_hash" not in repr_member
    assert "recovery_key_hash" not in repr_member

    session = SessionDoc(
        session_id="sha256_hash_of_secret_session_token",
        member_id="mem_123",
        circle_id="circle_456",
        role=MemberRole.CAREGIVER,
        username="sarah",
        display_name="Sarah",
        expires_at=(datetime.now(timezone.utc) + timedelta(days=7)).isoformat(),
    )
    repr_session = repr(session)
    assert "sha256_hash_of_secret_session_token" not in repr_session
    assert "session_id" not in repr_session


# ============================================================================
# 4. PIN Validation & Type Coercion
# ============================================================================

def test_elder_login_request_pin_preserves_leading_zeros_and_rejects_int():
    """Verify ElderLoginRequest strictly preserves leading zeros and rejects integer input."""
    # Preserves leading zero string
    req = ElderLoginRequest(circle_code="c7k9w2", elder_name="Eleanor", pin="0042")
    assert req.circle_code == "C7K9W2"
    assert req.pin == "0042"
    assert req.pin[0] == "0"
    assert isinstance(req.pin, str)

    # Rejects integer PIN (type coercion forbidden)
    with pytest.raises(ValidationError):
        ElderLoginRequest(circle_code="C7K9W2", elder_name="Eleanor", pin=1234)

    # Rejects non-numeric PIN
    with pytest.raises(ValidationError):
        ElderLoginRequest(circle_code="C7K9W2", elder_name="Eleanor", pin="12ab")

    # Rejects < 4 digits
    with pytest.raises(ValidationError):
        ElderLoginRequest(circle_code="C7K9W2", elder_name="Eleanor", pin="123")

    # Rejects > 6 digits
    with pytest.raises(ValidationError):
        ElderLoginRequest(circle_code="C7K9W2", elder_name="Eleanor", pin="1234567")


# ============================================================================
# 5. Timestamp Integrity & Naive Datetime Rejection
# ============================================================================

def test_session_data_rejects_naive_datetimes_and_normalizes_to_utc():
    """Verify SessionData rejects naive datetimes and normalizes offset datetimes to UTC."""
    now_utc = datetime.now(timezone.utc)

    # 1. Naive datetime rejected
    naive_dt = datetime(2026, 11, 15, 12, 0, 0)
    with pytest.raises(ValidationError) as exc_info:
        SessionData(
            session_id="abc",
            member_id="m1",
            circle_id="c1",
            role=MemberRole.CAREGIVER,
            username="sarah",
            display_name="Sarah",
            auth_version=1,
            created_at=naive_dt,
            expires_at=now_utc + timedelta(days=1),
            last_seen_at=now_utc,
        )
    assert "naive datetimes are strictly rejected" in str(exc_info.value)

    # 2. Timezone-aware with non-UTC offset normalized to UTC
    offset_tz = timezone(timedelta(hours=-5))
    offset_created = datetime(2026, 11, 15, 7, 0, 0, tzinfo=offset_tz)
    offset_expires = datetime(2026, 11, 22, 7, 0, 0, tzinfo=offset_tz)
    offset_seen = datetime(2026, 11, 15, 7, 5, 0, tzinfo=offset_tz)

    session = SessionData(
        session_id="abc",
        member_id="m1",
        circle_id="c1",
        role=MemberRole.CAREGIVER,
        username="sarah",
        display_name="Sarah",
        auth_version=1,
        created_at=offset_created,
        expires_at=offset_expires,
        last_seen_at=offset_seen,
    )
    assert session.created_at.tzinfo == timezone.utc
    assert session.created_at.hour == 12  # 07:00 -05:00 == 12:00 UTC
    assert session.expires_at.tzinfo == timezone.utc
    assert session.last_seen_at.tzinfo == timezone.utc


def test_session_data_ordering_validation():
    """Verify SessionData validates sensible ordering between created_at, expires_at, and last_seen_at."""
    now = datetime.now(timezone.utc)

    # Expiry before creation rejected
    with pytest.raises(ValidationError) as exc_info:
        SessionData(
            session_id="abc",
            member_id="m1",
            circle_id="c1",
            role=MemberRole.CAREGIVER,
            username="sarah",
            display_name="Sarah",
            created_at=now,
            expires_at=now - timedelta(hours=1),
            last_seen_at=now,
        )
    assert "expires_at" in str(exc_info.value)
    assert "strictly later than created_at" in str(exc_info.value)

    # last_seen before creation rejected
    with pytest.raises(ValidationError) as exc_info:
        SessionData(
            session_id="abc",
            member_id="m1",
            circle_id="c1",
            role=MemberRole.CAREGIVER,
            username="sarah",
            display_name="Sarah",
            created_at=now,
            expires_at=now + timedelta(hours=1),
            last_seen_at=now - timedelta(minutes=5),
        )
    assert "last_seen_at" in str(exc_info.value)
    assert "cannot be earlier than created_at" in str(exc_info.value)

    # last_seen after expires_at rejected (created_at <= last_seen_at <= expires_at)
    with pytest.raises(ValidationError) as exc_info:
        SessionData(
            session_id="abc",
            member_id="m1",
            circle_id="c1",
            role=MemberRole.CAREGIVER,
            username="sarah",
            display_name="Sarah",
            created_at=now,
            expires_at=now + timedelta(hours=1),
            last_seen_at=now + timedelta(hours=2),
        )
    assert "last_seen_at" in str(exc_info.value)
    assert "cannot be later than expires_at" in str(exc_info.value)

    # last_seen == expires_at accepted (boundary condition)
    s_boundary = SessionData(
        session_id="abc",
        member_id="m1",
        circle_id="c1",
        role=MemberRole.CAREGIVER,
        username="sarah",
        display_name="Sarah",
        created_at=now,
        expires_at=now + timedelta(hours=1),
        last_seen_at=now + timedelta(hours=1),
    )
    assert s_boundary.last_seen_at == s_boundary.expires_at


def test_document_models_iso_timestamp_validation():
    """Verify MemberDoc and SessionDoc strictly validate ISO strings and reject naive strings."""
    # 1. Naive ISO string rejected (missing timezone offset)
    with pytest.raises(ValidationError) as exc_info:
        MemberDoc(
            member_id="m1",
            circle_id="c1",
            username="sarah",
            display_name="Sarah",
            role=MemberRole.CAREGIVER,
            auth_type=AuthType.PASSWORD,
            password_hash="hash",
            created_at="2026-11-15T12:00:00",  # naive!
        )
    assert "naive rejected" in str(exc_info.value)

    # 2. Invalid timestamp string rejected
    with pytest.raises(ValidationError) as exc_info:
        MemberDoc(
            member_id="m1",
            circle_id="c1",
            username="sarah",
            display_name="Sarah",
            role=MemberRole.CAREGIVER,
            auth_type=AuthType.PASSWORD,
            password_hash="hash",
            locked_until="not-a-timestamp",
        )
    assert "Invalid ISO-8601" in str(exc_info.value)

    # 3. Non-UTC offset normalized to UTC ISO string
    member = MemberDoc(
        member_id="m1",
        circle_id="c1",
        username="sarah",
        display_name="Sarah",
        role=MemberRole.CAREGIVER,
        auth_type=AuthType.PASSWORD,
        password_hash="hash",
        created_at="2026-11-15T07:00:00-05:00",
    )
    assert member.created_at == "2026-11-15T12:00:00+00:00"

    # 4. Optional timestamp remains None when omitted
    assert member.locked_until is None
    assert member.last_login_at is None


def test_session_doc_ordering_validation():
    """Verify SessionDoc validates ordering between created_at, expires_at, and last_seen_at."""
    now = datetime.now(timezone.utc)

    # Expiry before creation rejected
    with pytest.raises(ValidationError) as exc_info:
        SessionDoc(
            session_id="sid",
            member_id="m1",
            circle_id="c1",
            role=MemberRole.CAREGIVER,
            username="sarah",
            display_name="Sarah",
            created_at=now.isoformat(),
            expires_at=(now - timedelta(days=1)).isoformat(),
            last_seen_at=now.isoformat(),
        )
    assert "strictly later than created_at" in str(exc_info.value)

    # last_seen before creation rejected
    with pytest.raises(ValidationError) as exc_info:
        SessionDoc(
            session_id="sid",
            member_id="m1",
            circle_id="c1",
            role=MemberRole.CAREGIVER,
            username="sarah",
            display_name="Sarah",
            created_at=now.isoformat(),
            expires_at=(now + timedelta(days=7)).isoformat(),
            last_seen_at=(now - timedelta(minutes=10)).isoformat(),
        )
    assert "cannot be earlier than created_at" in str(exc_info.value)

    # last_seen after expires_at rejected (created_at <= last_seen_at <= expires_at)
    with pytest.raises(ValidationError) as exc_info:
        SessionDoc(
            session_id="sid",
            member_id="m1",
            circle_id="c1",
            role=MemberRole.CAREGIVER,
            username="sarah",
            display_name="Sarah",
            created_at=now.isoformat(),
            expires_at=(now + timedelta(days=1)).isoformat(),
            last_seen_at=(now + timedelta(days=2)).isoformat(),
        )
    assert "cannot be later than expires_at" in str(exc_info.value)

    # last_seen == expires_at accepted (boundary condition)
    exp_iso = (now + timedelta(days=7)).isoformat()
    s_doc_boundary = SessionDoc(
        session_id="sid",
        member_id="m1",
        circle_id="c1",
        role=MemberRole.CAREGIVER,
        username="sarah",
        display_name="Sarah",
        created_at=now.isoformat(),
        expires_at=exp_iso,
        last_seen_at=exp_iso,
    )
    assert s_doc_boundary.last_seen_at == s_doc_boundary.expires_at


# ============================================================================
# 6. CredentialResetRequest Validation
# ============================================================================

def test_credential_reset_request_rejects_empty():
    """Verify empty CredentialResetRequest is rejected."""
    with pytest.raises(ValidationError) as exc_info:
        CredentialResetRequest()
    assert "Empty credential reset request" in str(exc_info.value)


def test_credential_reset_request_valid_pin_mode():
    """Verify valid PIN reset mode accepts only new_pin and preserves leading zeros."""
    req = CredentialResetRequest(new_pin="0078")
    assert req.new_pin == "0078"
    assert req.current_password is None
    assert req.new_password is None
    # PIN masked in repr
    assert "0078" not in repr(req)


def test_credential_reset_request_valid_password_mode():
    """Verify valid password change mode accepts both current and new passwords."""
    raw_current = "  OldSecret123!  "
    raw_new = "  NewStrongSecretPass123!  "
    req = CredentialResetRequest(current_password=raw_current, new_password=raw_new)
    assert req.new_pin is None
    assert req.current_password == raw_current
    assert req.new_password == raw_new
    # Passwords masked in repr
    assert "OldSecret123!" not in repr(req)
    assert "NewStrongSecretPass123!" not in repr(req)


def test_credential_reset_request_rejects_incomplete_password_mode():
    """Verify incomplete password change requests are rejected."""
    # Missing new_password
    with pytest.raises(ValidationError) as exc_info:
        CredentialResetRequest(current_password="ValidOldPassword123!")
    assert "'new_password' is required" in str(exc_info.value)

    # Missing current_password
    with pytest.raises(ValidationError) as exc_info:
        CredentialResetRequest(new_password="ValidNewPassword123!")
    assert "'current_password' is required" in str(exc_info.value)


def test_credential_reset_request_rejects_mixed_mode():
    """Verify combining PIN reset with password change is rejected as ambiguous."""
    with pytest.raises(ValidationError) as exc_info:
        CredentialResetRequest(new_pin="0123", new_password="ValidNewPassword123!")
    assert "Ambiguous credential reset request" in str(exc_info.value)


# ============================================================================
# 7. Internal Document Safety & Public Serialization
# ============================================================================

def test_member_doc_to_public_response_helper():
    """Verify MemberDoc.to_public_response() securely converts to MemberPublicResponse without leaking hashes."""
    member = MemberDoc(
        member_id="mem_001",
        circle_id="circle_001",
        username="sarah_caregiver",
        display_name="Sarah Nurse",
        role=MemberRole.CAREGIVER,
        auth_type=AuthType.PASSWORD,
        password_hash="$argon2id$v=19$m=65536,t=2,p=1$secret_password_hash",
        recovery_key_hash="$argon2id$v=19$m=65536,t=2,p=1$secret_recovery_hash",
        auth_version=2,
        is_active=True,
        is_primary=True,
        failed_login_attempts=1,
    )
    public_res = member.to_public_response()
    assert isinstance(public_res, MemberPublicResponse)
    dumped = public_res.model_dump()

    # Confirmed public fields present
    assert dumped["member_id"] == "mem_001"
    assert dumped["circle_id"] == "circle_001"
    assert dumped["username"] == "sarah_caregiver"
    assert dumped["role"] == MemberRole.CAREGIVER

    # Confirmed sensitive fields absent
    assert "password" not in dumped
    assert "password_hash" not in dumped
    assert "recovery_key" not in dumped
    assert "recovery_key_hash" not in dumped
    assert "pin" not in dumped
    assert "failed_login_attempts" not in dumped
    assert "auth_version" not in dumped


def test_member_doc_auth_version_minimum():
    """Verify auth_version < 1 is rejected by MemberDoc."""
    with pytest.raises(ValidationError):
        MemberDoc(
            member_id="m1",
            circle_id="c1",
            username="sarah",
            display_name="Sarah",
            role=MemberRole.CAREGIVER,
            auth_type=AuthType.PASSWORD,
            password_hash="hash",
            auth_version=0,  # invalid, must be >= 1
        )


def test_member_invite_blocks_elder_role():
    """Verify MemberInviteRequest strictly rejects inviting an elder."""
    with pytest.raises(ValidationError) as exc_info:
        MemberInviteRequest(role=MemberRole.ELDER)
    assert "Elders cannot be added via invitation links" in str(exc_info.value)
