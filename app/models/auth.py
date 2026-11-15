"""Authentication and identity models, schemas, and enums for CareCircle."""
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


# ============================================================================
# Enums
# ============================================================================

class MemberRole(str, Enum):
    """Role-based access tier within a care circle."""
    ELDER = "elder"
    CAREGIVER = "caregiver"
    FAMILY = "family"


class AuthType(str, Enum):
    """Authentication credential type used by an account."""
    PASSWORD = "password"
    PASSCODE = "passcode"
    RECOVERY_KEY = "recovery_key"


# ============================================================================
# Timestamp Normalization Helper
# ============================================================================

def parse_and_normalize_iso_utc(v: Optional[str]) -> Optional[str]:
    """
    Validate and normalize ISO-8601 timestamp strings.
    - Strictly rejects naive timestamps (missing timezone offset).
    - Strictly rejects invalid timestamp strings.
    - Normalizes accepted timestamps to canonical UTC ISO-8601 strings.
    - Preserves None for optional fields.
    """
    if v is None:
        return None
    if not isinstance(v, str):
        raise ValueError(f"Expected timestamp string, got {type(v).__name__}")
    cleaned = v.strip()
    if not cleaned:
        raise ValueError("Timestamp string cannot be empty")
    try:
        dt = datetime.fromisoformat(cleaned)
    except Exception as e:
        raise ValueError(f"Invalid ISO-8601 timestamp string '{cleaned}': {e}")
    if dt.tzinfo is None or dt.tzinfo.utcoffset(dt) is None:
        raise ValueError(f"Timestamp must include timezone information (naive rejected): '{cleaned}'")
    return dt.astimezone(timezone.utc).isoformat()


# ============================================================================
# Request Models (Ingress - Strict Input Validation)
# ============================================================================

class LoginRequest(BaseModel):
    """Caregiver and Family member authentication request."""
    # Global str_strip_whitespace is omitted to preserve exact password whitespace
    model_config = ConfigDict(extra="forbid")

    username: str = Field(
        ...,
        min_length=3,
        max_length=100,
        description="Normalized username or email.",
    )
    password: str = Field(
        ...,
        min_length=8,
        max_length=128,
        repr=False,
        description="Account password (exact input preserved, masked in repr).",
    )

    @field_validator("username")
    @classmethod
    def normalize_username(cls, v: str) -> str:
        cleaned = v.strip().lower()
        if not cleaned:
            raise ValueError("Username cannot be empty")
        return cleaned


class ElderLoginRequest(BaseModel):
    """Elder authentication request using Circle Code + Elder Name + PIN."""
    model_config = ConfigDict(extra="forbid")

    circle_code: str = Field(
        ...,
        min_length=6,
        max_length=6,
        pattern=r"^[A-HJ-NP-Za-hj-np-z2-9]{6}$",
        description="Randomized 6-character circle identifier.",
    )
    elder_name: str = Field(
        ...,
        min_length=1,
        max_length=60,
        description="Elder display name or alias within the circle.",
    )
    pin: str = Field(
        ...,
        pattern=r"^\d{4,6}$",
        repr=False,
        description="Elder 4-to-6 digit numeric passcode (preserves leading zeros, masked in repr).",
    )

    @field_validator("circle_code")
    @classmethod
    def normalize_circle_code(cls, v: str) -> str:
        return v.strip().upper()

    @field_validator("elder_name")
    @classmethod
    def normalize_elder_name(cls, v: str) -> str:
        cleaned = v.strip()
        if not cleaned:
            raise ValueError("Elder name cannot be empty")
        return cleaned


class CircleCreateRequest(BaseModel):
    """Initial circle and root caregiver provisioning request."""
    model_config = ConfigDict(extra="forbid")

    bootstrap_secret: str = Field(
        ...,
        min_length=8,
        max_length=256,
        repr=False,
        description="Environment-stored bootstrap secret for initial setup (masked in repr).",
    )
    circle_name: str = Field(
        ...,
        min_length=2,
        max_length=100,
        description="Human-readable name for the care circle.",
    )
    caregiver_name: str = Field(
        ...,
        min_length=1,
        max_length=100,
        description="Primary caregiver display name.",
    )
    caregiver_username: str = Field(
        ...,
        min_length=3,
        max_length=100,
        description="Primary caregiver login identifier.",
    )
    caregiver_password: str = Field(
        ...,
        min_length=10,
        max_length=128,
        repr=False,
        description="High-entropy primary caregiver password (exact input preserved, masked in repr).",
    )
    elder_name: str = Field(
        ...,
        min_length=1,
        max_length=100,
        description="Elder display name.",
    )
    elder_pin: str = Field(
        ...,
        pattern=r"^\d{4,6}$",
        repr=False,
        description="Senior-friendly 4-to-6 digit PIN (preserves leading zeros, masked in repr).",
    )
    elder_dob: Optional[str] = Field(
        default=None,
        pattern=r"^\d{4}-\d{2}-\d{2}$",
        description="Elder date of birth (YYYY-MM-DD).",
    )
    primary_condition: Optional[str] = Field(
        default=None,
        max_length=200,
        description="Elder primary medical condition summary.",
    )
    emergency_phone: Optional[str] = Field(
        default=None,
        max_length=30,
        description="Emergency contact phone number.",
    )

    @field_validator("circle_name")
    @classmethod
    def normalize_circle_name(cls, v: str) -> str:
        cleaned = v.strip()
        if not cleaned:
            raise ValueError("Circle name cannot be empty")
        return cleaned

    @field_validator("caregiver_name")
    @classmethod
    def normalize_caregiver_name(cls, v: str) -> str:
        cleaned = v.strip()
        if not cleaned:
            raise ValueError("Caregiver name cannot be empty")
        return cleaned

    @field_validator("caregiver_username")
    @classmethod
    def normalize_caregiver_username(cls, v: str) -> str:
        cleaned = v.strip().lower()
        if not cleaned:
            raise ValueError("Caregiver username cannot be empty")
        return cleaned

    @field_validator("elder_name")
    @classmethod
    def normalize_elder_name(cls, v: str) -> str:
        cleaned = v.strip()
        if not cleaned:
            raise ValueError("Elder name cannot be empty")
        return cleaned

    @field_validator("primary_condition", "emergency_phone")
    @classmethod
    def normalize_optional_strings(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        cleaned = v.strip()
        return cleaned if cleaned else None


class MemberInviteRequest(BaseModel):
    """Caregiver request to generate a member invitation token."""
    model_config = ConfigDict(extra="forbid")

    role: MemberRole = Field(
        ...,
        description="Target role for the invited member (caregiver or family only).",
    )
    invited_name: Optional[str] = Field(
        default=None,
        max_length=100,
        description="Optional display name hint for the invitee.",
    )

    @field_validator("role")
    @classmethod
    def prevent_elder_invite(cls, v: MemberRole) -> MemberRole:
        if v == MemberRole.ELDER:
            raise ValueError(
                "Elders cannot be added via invitation links. They must be provisioned within the circle by a caregiver."
            )
        return v

    @field_validator("invited_name")
    @classmethod
    def normalize_invited_name(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        cleaned = v.strip()
        return cleaned if cleaned else None


class MemberJoinRequest(BaseModel):
    """Invited member registration and token exchange request."""
    model_config = ConfigDict(extra="forbid")

    invite_token: str = Field(
        ...,
        min_length=16,
        max_length=128,
        repr=False,
        description="One-time invitation token (masked in repr).",
    )
    username: str = Field(
        ...,
        min_length=3,
        max_length=100,
        description="Desired login username or email.",
    )
    display_name: str = Field(
        ...,
        min_length=1,
        max_length=100,
        description="Member display name.",
    )
    password: str = Field(
        ...,
        min_length=8,
        max_length=128,
        repr=False,
        description="Password for the new account (exact input preserved, masked in repr).",
    )

    @field_validator("invite_token")
    @classmethod
    def normalize_invite_token(cls, v: str) -> str:
        cleaned = v.strip()
        if not cleaned:
            raise ValueError("Invite token cannot be empty")
        return cleaned

    @field_validator("username")
    @classmethod
    def normalize_username(cls, v: str) -> str:
        cleaned = v.strip().lower()
        if not cleaned:
            raise ValueError("Username cannot be empty")
        return cleaned

    @field_validator("display_name")
    @classmethod
    def normalize_display_name(cls, v: str) -> str:
        cleaned = v.strip()
        if not cleaned:
            raise ValueError("Display name cannot be empty")
        return cleaned


class RecoveryRequest(BaseModel):
    """Caregiver emergency recovery request using single-use recovery key."""
    model_config = ConfigDict(extra="forbid")

    username: str = Field(
        ...,
        min_length=3,
        max_length=100,
        description="Caregiver username.",
    )
    recovery_key: str = Field(
        ...,
        min_length=16,
        max_length=64,
        repr=False,
        description="Single-use emergency recovery key (masked in repr).",
    )
    new_password: str = Field(
        ...,
        min_length=10,
        max_length=128,
        repr=False,
        description="New high-entropy password (exact input preserved, masked in repr).",
    )

    @field_validator("username")
    @classmethod
    def normalize_username(cls, v: str) -> str:
        cleaned = v.strip().lower()
        if not cleaned:
            raise ValueError("Username cannot be empty")
        return cleaned

    @field_validator("recovery_key")
    @classmethod
    def normalize_recovery_key(cls, v: str) -> str:
        cleaned = v.strip()
        if not cleaned:
            raise ValueError("Recovery key cannot be empty")
        return cleaned


class CredentialResetRequest(BaseModel):
    """
    Caregiver request to reset an elder's PIN or self-service password change.
    Enforces exactly one valid reset mode:
    1. PIN reset: 'new_pin' is provided (and no password fields).
    2. Password change: both 'current_password' and 'new_password' are provided (and no PIN).
    Rejects empty, incomplete, or ambiguous requests.
    """
    model_config = ConfigDict(extra="forbid")

    new_pin: Optional[str] = Field(
        default=None,
        pattern=r"^\d{4,6}$",
        repr=False,
        description="New 4-to-6 digit PIN for elder (preserves leading zeros, masked in repr).",
    )
    current_password: Optional[str] = Field(
        default=None,
        min_length=8,
        max_length=128,
        repr=False,
        description="Current password for self-service password change (exact input preserved, masked in repr).",
    )
    new_password: Optional[str] = Field(
        default=None,
        min_length=10,
        max_length=128,
        repr=False,
        description="New password for self-service password change (exact input preserved, masked in repr).",
    )

    @model_validator(mode="after")
    def validate_reset_mode(self) -> "CredentialResetRequest":
        has_pin = self.new_pin is not None
        has_current = self.current_password is not None
        has_new = self.new_password is not None

        # 1. Reject empty request
        if not has_pin and not has_current and not has_new:
            raise ValueError(
                "Empty credential reset request. Specify either an elder PIN reset ('new_pin') "
                "or a password change ('current_password' and 'new_password')."
            )

        # 2. Reject ambiguous requests combining PIN and password fields
        if has_pin and (has_current or has_new):
            raise ValueError(
                "Ambiguous credential reset request. Cannot combine elder PIN reset with password change fields."
            )

        # 3. Valid PIN mode
        if has_pin:
            return self

        # 4. Incomplete password mode
        if has_current and not has_new:
            raise ValueError("Incomplete password change request. 'new_password' is required.")
        if has_new and not has_current:
            raise ValueError("Incomplete password change request. 'current_password' is required.")

        return self


# ============================================================================
# Internal Document Models (Firestore Database State)
# ============================================================================

class MemberDoc(BaseModel):
    """
    Internal Firestore document model representing a circle member.
    NOTE ON PASSWORD HASHING:
    The 'password_hash' field contains the Argon2id hash for the credential type
    specified by 'auth_type' (passwords for caregivers/family, numeric PINs for elders).
    The model schema enforces field presence and length bounds; cryptographic hash
    generation and verification are executed by auth services.
    """
    model_config = ConfigDict(extra="ignore")

    member_id: str = Field(..., description="Unique member UUID.")
    circle_id: str = Field(..., description="Unique identifier of the care circle.")
    username: str = Field(..., description="Normalized username.")
    display_name: str = Field(..., description="Human display name.")
    role: MemberRole = Field(..., description="Access tier role.")
    auth_type: AuthType = Field(..., description="Credential type.")
    password_hash: str = Field(
        ...,
        repr=False,
        description="Argon2id hash of password or PIN (masked in repr).",
    )
    recovery_key_hash: Optional[str] = Field(
        default=None,
        repr=False,
        description="Argon2id hash of emergency recovery key (masked in repr).",
    )
    auth_version: int = Field(
        default=1,
        ge=1,
        description="Monotonically increasing auth counter for instant global session revocation.",
    )
    is_active: bool = Field(default=True, description="Account status.")
    is_primary: bool = Field(default=False, description="True if primary circle administrator caregiver.")
    failed_login_attempts: int = Field(default=0, ge=0, description="Sequential failed login attempts.")
    locked_until: Optional[str] = Field(default=None, description="ISO8601 UTC lockout expiration timestamp.")
    last_login_at: Optional[str] = Field(default=None, description="ISO8601 UTC timestamp of last login.")
    created_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="ISO8601 UTC creation timestamp.",
    )

    @field_validator("created_at", "locked_until", "last_login_at", mode="after")
    @classmethod
    def validate_iso_timestamps(cls, v: Optional[str]) -> Optional[str]:
        return parse_and_normalize_iso_utc(v)

    def to_public_response(self) -> "MemberPublicResponse":
        """
        Convert internal MemberDoc to sanitized public MemberPublicResponse DTO.
        Guarantees that password_hash, recovery_key_hash, PINs, and internal security counters
        are never leaked in public API responses.
        """
        return MemberPublicResponse(
            member_id=self.member_id,
            circle_id=self.circle_id,
            username=self.username,
            display_name=self.display_name,
            role=self.role,
            auth_type=self.auth_type,
            is_active=self.is_active,
            is_primary=self.is_primary,
            created_at=self.created_at,
            last_login_at=self.last_login_at,
        )


class SessionDoc(BaseModel):
    """
    Internal Firestore document model for auth_sessions/{session_id}.
    Enforces timezone-aware UTC ISO timestamps and lifecycle ordering.
    """
    model_config = ConfigDict(extra="ignore")

    session_id: str = Field(
        ...,
        repr=False,
        description="SHA-256 hash of the raw opaque token (masked in repr).",
    )
    member_id: str = Field(..., description="Authenticated member UUID.")
    circle_id: str = Field(..., description="Care circle UUID.")
    role: MemberRole = Field(..., description="Member role at session creation time.")
    username: str = Field(..., description="Normalized username.")
    display_name: str = Field(..., description="Display name.")
    auth_version: int = Field(
        default=1,
        ge=1,
        description="Recorded auth_version; invalidated if member.auth_version > this.",
    )
    revoked: bool = Field(default=False, description="True if explicitly revoked.")
    revoked_reason: Optional[str] = Field(default=None, description="Reason for revocation.")
    created_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="ISO8601 UTC creation timestamp.",
    )
    expires_at: str = Field(..., description="ISO8601 UTC absolute expiration timestamp.")
    last_seen_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="ISO8601 UTC timestamp of last activity (throttled).",
    )
    client_ip: Optional[str] = Field(default=None, description="Client IP address.")
    user_agent: Optional[str] = Field(default=None, description="Browser User-Agent.")

    @field_validator("created_at", "expires_at", "last_seen_at", mode="after")
    @classmethod
    def validate_session_doc_timestamps(cls, v: str) -> str:
        result = parse_and_normalize_iso_utc(v)
        if result is None:
            raise ValueError("Session timestamp cannot be empty")
        return result

    @model_validator(mode="after")
    def validate_session_doc_ordering(self) -> "SessionDoc":
        c = datetime.fromisoformat(self.created_at)
        e = datetime.fromisoformat(self.expires_at)
        l = datetime.fromisoformat(self.last_seen_at)
        if e <= c:
            raise ValueError(f"expires_at '{self.expires_at}' must be strictly later than created_at '{self.created_at}'")
        if l < c:
            raise ValueError(f"last_seen_at '{self.last_seen_at}' cannot be earlier than created_at '{self.created_at}'")
        if l > e:
            raise ValueError(f"last_seen_at '{self.last_seen_at}' cannot be later than expires_at '{self.expires_at}'")
        return self


class SessionData(BaseModel):
    """
    Validated active session object injected into request state.
    Strictly rejects naive datetimes and normalizes accepted timestamps to UTC.
    Enforces created_at <= last_seen_at <= expires_at lifecycle invariant.
    """
    model_config = ConfigDict(extra="ignore")

    session_id: str = Field(..., repr=False, description="SHA-256 session ID (masked in repr).")
    member_id: str = Field(..., description="Member UUID.")
    circle_id: str = Field(..., description="Circle UUID.")
    role: MemberRole = Field(..., description="Authoritative live role from member record.")
    username: str = Field(..., description="Normalized username.")
    display_name: str = Field(..., description="Display name.")
    auth_version: int = Field(default=1, ge=1, description="Current auth version.")
    created_at: datetime
    expires_at: datetime
    last_seen_at: datetime

    @field_validator("created_at", "expires_at", "last_seen_at", mode="after")
    @classmethod
    def validate_tz_aware_utc(cls, v: datetime) -> datetime:
        if v.tzinfo is None or v.tzinfo.utcoffset(v) is None:
            raise ValueError(f"Timestamp {v} must be timezone-aware (naive datetimes are strictly rejected).")
        return v.astimezone(timezone.utc)

    @model_validator(mode="after")
    def validate_session_ordering(self) -> "SessionData":
        if self.expires_at <= self.created_at:
            raise ValueError(f"expires_at ({self.expires_at}) must be strictly later than created_at ({self.created_at})")
        if self.last_seen_at < self.created_at:
            raise ValueError(f"last_seen_at ({self.last_seen_at}) cannot be earlier than created_at ({self.created_at})")
        if self.last_seen_at > self.expires_at:
            raise ValueError(f"last_seen_at ({self.last_seen_at}) cannot be later than expires_at ({self.expires_at})")
        return self


# ============================================================================
# Public Response Models (Egress - Safe Sanitized DTOs)
# ============================================================================

class MemberPublicResponse(BaseModel):
    """
    Publicly safe member response.
    Guarantees password_hash, recovery_key_hash, and PINs cannot leak.
    """
    model_config = ConfigDict(extra="ignore")

    member_id: str
    circle_id: str
    username: str
    display_name: str
    role: MemberRole
    auth_type: AuthType
    is_active: bool
    is_primary: bool
    created_at: str
    last_login_at: Optional[str] = None


class CirclePublicResponse(BaseModel):
    """Publicly safe care circle response."""
    model_config = ConfigDict(extra="ignore")

    circle_id: str
    circle_code: str
    name: str
    is_active: bool
    created_at: str


class RecoveryKeyResponse(BaseModel):
    """One-time display response for an emergency recovery key."""
    model_config = ConfigDict(extra="forbid")

    recovery_key: str = Field(
        ...,
        repr=False,
        description="One-time plaintext emergency recovery key (masked in repr).",
    )
    message: str = "Store this recovery key securely offline. It will not be shown again."


class AuthStatusResponse(BaseModel):
    """Public response reporting session authentication status."""
    model_config = ConfigDict(extra="ignore")

    authenticated: bool
    member: Optional[MemberPublicResponse] = None
