"""Care Circle management, membership, and invitation models for Phase 4."""
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.models.auth import MemberRole, AuthType, parse_and_normalize_iso_utc


# ============================================================================
# Circle Management Request & Response Models
# ============================================================================

class CircleUpdateRequest(BaseModel):
    """Primary caregiver request to update care circle metadata and elder healthcare profile."""
    model_config = ConfigDict(extra="forbid")

    circle_name: Optional[str] = Field(
        default=None,
        min_length=2,
        max_length=100,
        description="Updated human-readable name for the care circle.",
    )
    elder_name: Optional[str] = Field(
        default=None,
        min_length=1,
        max_length=100,
        description="Updated elder display name.",
    )
    elder_dob: Optional[str] = Field(
        default=None,
        pattern=r"^\d{4}-\d{2}-\d{2}$",
        description="Elder date of birth (YYYY-MM-DD).",
    )
    primary_condition: Optional[str] = Field(
        default=None,
        max_length=200,
        description="Summary of elder primary condition.",
    )
    emergency_phone: Optional[str] = Field(
        default=None,
        max_length=30,
        description="Emergency contact phone number.",
    )
    timezone: Optional[str] = Field(
        default=None,
        max_length=64,
        description="IANA timezone identifier (e.g. 'Asia/Kolkata', 'America/New_York').",
    )

    @field_validator("circle_name", "elder_name", "primary_condition", "emergency_phone", "timezone")
    @classmethod
    def normalize_optional_text(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        cleaned = v.strip()
        return cleaned if cleaned else None

    @model_validator(mode="after")
    def validate_non_empty_update(self) -> "CircleUpdateRequest":
        if (
            self.circle_name is None
            and self.elder_name is None
            and self.elder_dob is None
            and self.primary_condition is None
            and self.emergency_phone is None
            and self.timezone is None
        ):
            raise ValueError("Circle update payload cannot be empty. Specify at least one field to update.")
        return self


class CircleDetailResponse(BaseModel):
    """Detailed care circle response including active member count and elder profile."""
    model_config = ConfigDict(extra="ignore")

    circle_id: str
    circle_code: str
    name: str
    elder_profile: Dict[str, Any]
    active_member_count: int
    is_active: bool
    timezone: Optional[str] = "UTC"
    created_at: str
    updated_at: Optional[str] = None


class CircleMemberDetailResponse(BaseModel):
    """Sanitized public member representation within circle management views."""
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
    updated_at: Optional[str] = None
    deactivated_at: Optional[str] = None
    last_login_at: Optional[str] = None


# ============================================================================
# Invitation Request, Document & Response Models
# ============================================================================

class InvitationCreateRequest(BaseModel):
    """Primary caregiver request to generate a 48-hour single-use invitation."""
    model_config = ConfigDict(extra="forbid")

    role: MemberRole = Field(
        ...,
        description="Role for invited member (caregiver or family only).",
    )
    invited_name: Optional[str] = Field(
        default=None,
        max_length=100,
        description="Optional display name hint for the invitee.",
    )
    invited_email: Optional[str] = Field(
        default=None,
        max_length=120,
        description="Optional intended recipient email for copy-link binding.",
    )

    @field_validator("role")
    @classmethod
    def prevent_elder_invite(cls, v: MemberRole) -> MemberRole:
        if v == MemberRole.ELDER:
            raise ValueError(
                "Elders cannot be added via invitation links. They must be provisioned directly within the circle."
            )
        return v

    @field_validator("invited_name", "invited_email")
    @classmethod
    def normalize_optional_fields(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        cleaned = v.strip()
        return cleaned if cleaned else None


class InvitationDoc(BaseModel):
    """Internal Firestore document model for circle_invitations/{invitation_id}."""
    model_config = ConfigDict(extra="ignore")

    invitation_id: str = Field(..., description="Unique invitation UUID.")
    circle_id: str = Field(..., description="Target care circle UUID.")
    circle_name: str = Field(..., description="Cached care circle name.")
    role: MemberRole = Field(..., description="Target role (caregiver or family).")
    invited_name: Optional[str] = Field(default=None, description="Optional name hint.")
    invited_email: Optional[str] = Field(default=None, description="Optional email hint.")
    token_hash: str = Field(
        ...,
        repr=False,
        description="SHA-256 hash of the 32-byte opaque raw token (masked in repr).",
    )
    created_by: str = Field(..., description="Member UUID of creating caregiver.")
    created_by_name: Optional[str] = Field(default=None, description="Display name of creator.")
    created_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="ISO8601 UTC creation timestamp.",
    )
    expires_at: str = Field(..., description="ISO8601 UTC expiration timestamp (48h).")
    status: str = Field(default="pending", description="Status: pending, accepted, revoked, expired.")
    accepted_at: Optional[str] = Field(default=None, description="ISO8601 UTC timestamp of redemption.")
    accepted_by: Optional[str] = Field(default=None, description="Member UUID of recipient.")
    revoked_at: Optional[str] = Field(default=None, description="ISO8601 UTC timestamp of revocation.")
    revoked_by: Optional[str] = Field(default=None, description="Member UUID who revoked invitation.")

    @field_validator("created_at", "expires_at", "accepted_at", "revoked_at", mode="after")
    @classmethod
    def validate_iso_timestamps(cls, v: Optional[str]) -> Optional[str]:
        return parse_and_normalize_iso_utc(v)


class InvitationPublicResponse(BaseModel):
    """Sanitized public invitation details safe for API responses."""
    model_config = ConfigDict(extra="ignore")

    invitation_id: str
    circle_id: str
    role: MemberRole
    invited_name: Optional[str] = None
    invited_email: Optional[str] = None
    status: str
    created_at: str
    expires_at: str
    accepted_at: Optional[str] = None


class InvitationCreateResponse(BaseModel):
    """Response returned upon generating a new invitation, providing one-time copy URL."""
    model_config = ConfigDict(extra="forbid")

    invitation: InvitationPublicResponse
    raw_token: str = Field(
        ...,
        repr=False,
        description="One-time raw invitation token (masked in repr).",
    )
    invite_url: str = Field(..., description="Ready-to-share invitation link.")
    expires_at: str
    message: str = "Share this link with the invited caregiver or family member. It expires in 48 hours."


class InvitationInspectResponse(BaseModel):
    """Publicly safe invitation inspection response for recipient landing page."""
    model_config = ConfigDict(extra="ignore")

    valid: bool
    circle_name: str
    role: MemberRole
    invited_name: Optional[str] = None
    expires_at: str
    status: str = "pending"
