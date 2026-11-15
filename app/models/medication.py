"""Medication, Schedule, and Shared Dose Ledger models for CareCircle."""
from datetime import datetime, timezone
from enum import Enum
import re
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field, computed_field, field_validator, model_validator

from app.models.auth import MemberRole, parse_and_normalize_iso_utc


class DoseStatus(str, Enum):
    """Deterministic lifecycle statuses for a scheduled medication dose."""
    UPCOMING = "upcoming"
    DUE = "due"
    TAKEN = "taken"
    OVERDUE = "overdue"
    MISSED = "missed"
    PAUSED = "paused"


class MedicationFrequency(str, Enum):
    """Standard administration frequency schedule."""
    DAILY = "daily"
    TWICE_DAILY = "twice_daily"
    THREE_TIMES_DAILY = "three_times_daily"
    AS_NEEDED = "as_needed"
    CUSTOM = "custom"


TIME_PATTERN = r"^([01]\d|2[0-3]):[0-5]\d$"
DATE_PATTERN = r"^\d{4}-\d{2}-\d{2}$"


# ============================================================================
# Ingress Request Models
# ============================================================================

class MedicationCreateRequest(BaseModel):
    """Caregiver request to create a new medication regimen."""
    model_config = ConfigDict(extra="forbid")

    name: str = Field(
        ...,
        min_length=1,
        max_length=100,
        description="Prescribed medication commercial or generic name.",
    )
    dosage_instructions: str = Field(
        ...,
        min_length=1,
        max_length=200,
        description="Administration instructions exactly as prescribed (e.g. '1 tablet with breakfast').",
    )
    frequency: MedicationFrequency = Field(
        default=MedicationFrequency.DAILY,
        description="Prescription dosage frequency.",
    )
    scheduled_times: List[str] = Field(
        ...,
        min_length=1,
        max_length=10,
        description="List of 24-hour scheduled administration times in HH:MM format (e.g. ['08:00', '20:00']).",
    )
    start_date: str = Field(
        ...,
        pattern=DATE_PATTERN,
        description="Start date of medication regimen in YYYY-MM-DD format.",
    )
    end_date: Optional[str] = Field(
        default=None,
        pattern=DATE_PATTERN,
        description="Optional end date in YYYY-MM-DD format.",
    )
    notes: Optional[str] = Field(
        default=None,
        max_length=500,
        description="Special caregiver instructions or pharmacy notes.",
    )
    elder_id: Optional[str] = Field(
        default=None,
        description="Target elder member ID if circle has multiple elders.",
    )

    @model_validator(mode="before")
    @classmethod
    def normalize_input_aliases(cls, data: Any) -> Any:
        if isinstance(data, dict):
            # Normalize dosage -> dosage_instructions
            if "dosage_instructions" not in data and "dosage" in data:
                data["dosage_instructions"] = str(data.pop("dosage"))
            # Normalize instructions -> notes
            if "notes" not in data and "instructions" in data:
                data["notes"] = data.pop("instructions")
            # Normalize times_of_day -> scheduled_times
            if "scheduled_times" not in data and "times_of_day" in data:
                data["scheduled_times"] = data.pop("times_of_day")
        return data

    @field_validator("name", "dosage_instructions")
    @classmethod
    def clean_text_fields(cls, v: str) -> str:
        cleaned = v.strip()
        if not cleaned:
            raise ValueError("Field cannot be blank or whitespace-only.")
        return cleaned

    @field_validator("scheduled_times")
    @classmethod
    def validate_and_sort_times(cls, times: List[str]) -> List[str]:
        if not times:
            raise ValueError("At least one scheduled time (HH:MM) must be provided.")
        normalized = []
        for t in times:
            clean = t.strip()
            if not re.match(TIME_PATTERN, clean):
                raise ValueError(f"Invalid scheduled time '{clean}'. Must match 24-hour HH:MM format.")
            normalized.append(clean)
        # Deduplicate and sort chronologically
        return sorted(list(set(normalized)))

    @model_validator(mode="after")
    def validate_date_range(self) -> "MedicationCreateRequest":
        if self.end_date is not None and self.start_date > self.end_date:
            raise ValueError(f"end_date ({self.end_date}) cannot be earlier than start_date ({self.start_date}).")
        return self


class MedicationUpdateRequest(BaseModel):
    """Caregiver request to update an existing medication regimen."""
    model_config = ConfigDict(extra="forbid")

    name: Optional[str] = Field(default=None, min_length=1, max_length=100)
    dosage_instructions: Optional[str] = Field(default=None, min_length=1, max_length=200)
    frequency: Optional[MedicationFrequency] = None
    scheduled_times: Optional[List[str]] = Field(default=None, min_length=1, max_length=10)
    start_date: Optional[str] = Field(default=None, pattern=DATE_PATTERN)
    end_date: Optional[str] = Field(default=None, pattern=DATE_PATTERN)
    notes: Optional[str] = Field(default=None, max_length=500)
    is_active: Optional[bool] = None
    is_paused: Optional[bool] = None

    @field_validator("name", "dosage_instructions")
    @classmethod
    def clean_optional_text(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        cleaned = v.strip()
        return cleaned if cleaned else None

    @field_validator("scheduled_times")
    @classmethod
    def validate_and_sort_times(cls, times: Optional[List[str]]) -> Optional[List[str]]:
        if times is None:
            return None
        if not times:
            raise ValueError("Scheduled times list cannot be empty if specified.")
        normalized = []
        for t in times:
            clean = t.strip()
            if not re.match(TIME_PATTERN, clean):
                raise ValueError(f"Invalid scheduled time '{clean}'. Must match 24-hour HH:MM format.")
            normalized.append(clean)
        return sorted(list(set(normalized)))

    @model_validator(mode="after")
    def validate_date_range(self) -> "MedicationUpdateRequest":
        if self.start_date is not None and self.end_date is not None:
            if self.start_date > self.end_date:
                raise ValueError(f"end_date ({self.end_date}) cannot be earlier than start_date ({self.start_date}).")
        return self


class DoseConfirmRequest(BaseModel):
    """Request payload when confirming a scheduled dose."""
    model_config = ConfigDict(extra="ignore")

    method: Optional[str] = Field(
        default="observed",
        max_length=50,
        description="Confirmation method (e.g. self_reported, observed, administered).",
    )
    notes: Optional[str] = Field(
        default=None,
        max_length=300,
        description="Optional observation note recorded at time of dose confirmation.",
    )


# ============================================================================
# Internal Document Models
# ============================================================================

class MedicationDoc(BaseModel):
    """Internal Firestore document model for medications/{med_id}."""
    model_config = ConfigDict(extra="ignore")

    med_id: str
    circle_id: str
    elder_id: str
    name: str
    dosage_instructions: str
    frequency: MedicationFrequency
    scheduled_times: List[str]
    start_date: str
    end_date: Optional[str] = None
    notes: Optional[str] = None
    is_active: bool = True
    is_paused: bool = False
    created_by: str
    created_by_name: str
    created_at: str
    updated_at: Optional[str] = None

    @field_validator("created_at", "updated_at", mode="after")
    @classmethod
    def validate_iso_timestamps(cls, v: Optional[str]) -> Optional[str]:
        return parse_and_normalize_iso_utc(v)


class DoseLedgerEventDoc(BaseModel):
    """Internal immutable Firestore document model for dose_ledger/{dose_id}."""
    model_config = ConfigDict(extra="ignore")

    dose_id: str
    circle_id: str
    elder_id: str
    medication_id: str
    medication_name: str
    dosage_instructions: str
    scheduled_date: str
    scheduled_time: str
    scheduled_datetime_utc: str
    status: str = "taken"
    logged_by_member_id: str
    logged_by_name: str
    logged_by_role: str
    logged_at: str
    notes: Optional[str] = None
    source: str = "app"  # "elder_tap" | "caregiver_log"

    @field_validator("scheduled_datetime_utc", "logged_at", mode="after")
    @classmethod
    def validate_iso_timestamps(cls, v: Optional[str]) -> Optional[str]:
        return parse_and_normalize_iso_utc(v)


# ============================================================================
# Egress Response Models
# ============================================================================

class MedicationPublicResponse(BaseModel):
    """Sanitized public medication representation for API responses."""
    model_config = ConfigDict(extra="ignore")

    med_id: str
    circle_id: str
    elder_id: str
    name: str
    dosage_instructions: str
    frequency: MedicationFrequency
    scheduled_times: List[str]
    start_date: str
    end_date: Optional[str] = None
    notes: Optional[str] = None
    is_active: bool
    is_paused: bool
    created_by_name: str
    created_at: str
    updated_at: Optional[str] = None

    @computed_field
    @property
    def medication_id(self) -> str:
        return self.med_id

    @computed_field
    @property
    def dosage(self) -> str:
        return self.dosage_instructions

    @computed_field
    @property
    def times_of_day(self) -> List[str]:
        return self.scheduled_times

    @computed_field
    @property
    def instructions(self) -> Optional[str]:
        return self.notes


class DoseItemResponse(BaseModel):
    """Dynamic view of a scheduled dose occurrence for today or target date."""
    model_config = ConfigDict(extra="ignore")

    dose_id: str
    medication_id: str
    medication_name: str
    dosage_instructions: str
    scheduled_date: str
    scheduled_time: str
    scheduled_iso: str
    status: DoseStatus
    status_label: str
    is_taken: bool
    can_confirm: bool
    confirmed_at: Optional[str] = None
    confirmed_by_name: Optional[str] = None
    confirmed_by_role: Optional[str] = None
    notes: Optional[str] = None

    @computed_field
    @property
    def dosage(self) -> str:
        return self.dosage_instructions

    @computed_field
    @property
    def instructions(self) -> Optional[str]:
        return self.notes

    @computed_field
    @property
    def taken_at(self) -> Optional[str]:
        return self.confirmed_at


class CareBriefResponse(BaseModel):
    """Context-aware deterministic summary of daily medication progress and alerts."""
    model_config = ConfigDict(extra="ignore")

    headline: str
    scheduled_today_count: int
    confirmed_today_count: int
    pending_today_count: int
    overdue_count: int
    missed_count: int
    active_medications_count: int
    status_tone: str  # "success" | "warning" | "alert" | "neutral"
    bullet_points: List[str]
    next_dose_summary: Optional[str] = None
    last_confirmed_summary: Optional[str] = None
    generated_at: str

    @computed_field
    @property
    def total_scheduled(self) -> int:
        return self.scheduled_today_count

    @computed_field
    @property
    def taken_count(self) -> int:
        return self.confirmed_today_count

    @computed_field
    @property
    def due_count(self) -> int:
        return self.pending_today_count

    @computed_field
    @property
    def active_prescriptions_count(self) -> int:
        return self.active_medications_count

    @computed_field
    @property
    def narrative(self) -> str:
        return " ".join(self.bullet_points) if self.bullet_points else self.headline

