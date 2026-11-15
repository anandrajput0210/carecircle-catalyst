"""Medication management, daily schedules, dose ledgers, and care brief routes."""
from datetime import datetime, timezone
import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from app.config import settings
from app.models.auth import MemberDoc, MemberRole, SessionData
from app.models.medication import (
    CareBriefResponse,
    DoseConfirmRequest,
    DoseItemResponse,
    MedicationCreateRequest,
    MedicationPublicResponse,
    MedicationUpdateRequest,
)
from app.repositories.firestore_circle import FirestoreCircleRepository
from app.services.csrf import generate_csrf_token, set_csrf_cookie, validate_csrf_request
from app.services.dependencies import (
    get_circle_repository,
    get_current_member,
    get_current_session,
    get_medication_service,
    get_optional_session,
    require_primary_caregiver,
)
from app.services.medication import MedicationService

logger = logging.getLogger("carecircle.routes.medication")

router = APIRouter(tags=["Medication Safety & Schedule"])
templates = Jinja2Templates(directory=str(settings.TEMPLATES_DIR))


# ============================================================================
# Medication Management Endpoints (Caregivers)
# ============================================================================

@router.get(
    "/api/medications",
    response_model=List[MedicationPublicResponse],
    summary="List all medications for current care circle",
)
async def list_medications(
    active_only: bool = Query(default=False, description="Filter for active medications only"),
    session: SessionData = Depends(get_current_session),
    med_service: MedicationService = Depends(get_medication_service),
) -> List[MedicationPublicResponse]:
    """Retrieve prescription medications belonging to caller's circle."""
    return await med_service.list_medications(session.circle_id, active_only=active_only)


@router.post(
    "/api/medications",
    response_model=MedicationPublicResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Add a new medication regimen (Primary Caregiver only)",
)
async def create_medication(
    payload: MedicationCreateRequest,
    request: Request,
    primary_caregiver: MemberDoc = Depends(require_primary_caregiver),
    _csrf: None = Depends(validate_csrf_request),
    med_service: MedicationService = Depends(get_medication_service),
) -> MedicationPublicResponse:
    """Create a new prescription medication regimen with verified scheduled times."""
    return await med_service.create_medication(
        circle_id=primary_caregiver.circle_id,
        creator=primary_caregiver,
        payload=payload,
    )


# ============================================================================
# Daily Schedule & Dose Ledger Endpoints (Static paths before {med_id})
# ============================================================================

@router.get(
    "/api/medications/schedule",
    response_model=List[DoseItemResponse],
    summary="Retrieve today's synchronized dose schedule",
)
@router.get(
    "/api/medications/schedule/today",
    response_model=List[DoseItemResponse],
    summary="Retrieve today's synchronized dose schedule (Alias)",
)
async def get_today_schedule(
    session: SessionData = Depends(get_current_session),
    member: MemberDoc = Depends(get_current_member),
    med_service: MedicationService = Depends(get_medication_service),
) -> List[DoseItemResponse]:
    """Retrieve today's daily medication schedule with real-time status and confirmation states."""
    return await med_service.get_daily_schedule(session.circle_id, member)


@router.get(
    "/api/medications/schedule/date/{target_date}",
    response_model=List[DoseItemResponse],
    summary="Retrieve dose schedule for specific date (YYYY-MM-DD)",
)
async def get_date_schedule(
    target_date: str,
    session: SessionData = Depends(get_current_session),
    member: MemberDoc = Depends(get_current_member),
    med_service: MedicationService = Depends(get_medication_service),
) -> List[DoseItemResponse]:
    """Query scheduled doses and ledger confirmations for any historical or future date."""
    return await med_service.get_daily_schedule(session.circle_id, member, target_date=target_date)


@router.get(
    "/api/medications/care-brief",
    response_model=CareBriefResponse,
    summary="Retrieve context-aware deterministic Care Brief summary",
)
async def get_care_brief(
    target_date: Optional[str] = Query(default=None),
    session: SessionData = Depends(get_current_session),
    member: MemberDoc = Depends(get_current_member),
    med_service: MedicationService = Depends(get_medication_service),
) -> CareBriefResponse:
    """Context-aware factual summary of medication progress, upcoming doses, and overdue alerts."""
    return await med_service.get_care_brief(session.circle_id, member, target_date=target_date)


@router.get(
    "/api/medications/ledger",
    summary="Retrieve shared dose ledger audit history",
)
async def get_dose_ledger(
    limit: int = Query(default=50, ge=1, le=100),
    session: SessionData = Depends(get_current_session),
    med_service: MedicationService = Depends(get_medication_service),
) -> List[Dict[str, Any]]:
    """Retrieve immutable audit history of recent dose events."""
    return await med_service.list_dose_ledger(session.circle_id, limit=limit)


@router.post(
    "/api/medications/doses/{dose_id}/confirm",
    response_model=DoseItemResponse,
    summary="Atomically confirm a dose occurrence (Elders & Caregivers; Family read-only)",
)
async def confirm_dose(
    dose_id: str,
    request: Request,
    payload: Optional[DoseConfirmRequest] = None,
    member: MemberDoc = Depends(get_current_member),
    _csrf: None = Depends(validate_csrf_request),
    med_service: MedicationService = Depends(get_medication_service),
) -> DoseItemResponse:
    """
    Atomically record dose confirmation into shared immutable ledger.
    Duplicate confirmations are rejected with HTTP 409 Conflict.
    Family members are restricted from confirming doses.
    """
    notes = payload.notes if payload else None
    return await med_service.confirm_dose(
        circle_id=member.circle_id,
        confirming_member=member,
        dose_id=dose_id,
        notes=notes,
    )


# ============================================================================
# Parameterized Medication Item Endpoints ({med_id})
# ============================================================================

@router.get(
    "/api/medications/{med_id}",
    response_model=MedicationPublicResponse,
    summary="Retrieve single medication details",
)
async def get_medication(
    med_id: str,
    session: SessionData = Depends(get_current_session),
    med_service: MedicationService = Depends(get_medication_service),
) -> MedicationPublicResponse:
    """Retrieve single medication document ensuring circle tenant isolation."""
    return await med_service.get_medication(session.circle_id, med_id)


@router.patch(
    "/api/medications/{med_id}",
    response_model=MedicationPublicResponse,
    summary="Update medication details (Primary Caregiver only)",
)
async def update_medication(
    med_id: str,
    payload: MedicationUpdateRequest,
    request: Request,
    primary_caregiver: MemberDoc = Depends(require_primary_caregiver),
    _csrf: None = Depends(validate_csrf_request),
    med_service: MedicationService = Depends(get_medication_service),
) -> MedicationPublicResponse:
    """Update prescribed dosage instructions, times, notes, or status."""
    return await med_service.update_medication(
        circle_id=primary_caregiver.circle_id,
        updater=primary_caregiver,
        med_id=med_id,
        payload=payload,
    )


@router.post(
    "/api/medications/{med_id}/deactivate",
    response_model=MedicationPublicResponse,
    summary="Soft-deactivate a medication regimen (Primary Caregiver only)",
)
@router.delete(
    "/api/medications/{med_id}",
    response_model=MedicationPublicResponse,
    summary="Soft-deactivate a medication regimen (Alias)",
)
async def deactivate_medication(
    med_id: str,
    request: Request,
    primary_caregiver: MemberDoc = Depends(require_primary_caregiver),
    _csrf: None = Depends(validate_csrf_request),
    med_service: MedicationService = Depends(get_medication_service),
) -> MedicationPublicResponse:
    """Deactivate prescription while strictly preserving historical dose logs."""
    return await med_service.deactivate_medication(
        circle_id=primary_caregiver.circle_id,
        actor=primary_caregiver,
        med_id=med_id,
    )


@router.post(
    "/api/medications/{med_id}/pause",
    response_model=MedicationPublicResponse,
    summary="Pause or resume a medication regimen (Primary Caregiver only)",
)
async def pause_medication(
    med_id: str,
    request: Request,
    payload: Optional[Dict[str, Any]] = None,
    paused: Optional[bool] = Query(default=None, description="True to pause, False to resume"),
    primary_caregiver: MemberDoc = Depends(require_primary_caregiver),
    _csrf: None = Depends(validate_csrf_request),
    med_service: MedicationService = Depends(get_medication_service),
) -> MedicationPublicResponse:
    """Temporarily pause or resume daily dose generation."""
    is_paused_val = True
    if payload is not None and "is_paused" in payload:
        is_paused_val = bool(payload["is_paused"])
    elif paused is not None:
        is_paused_val = bool(paused)

    return await med_service.toggle_paused_medication(
        circle_id=primary_caregiver.circle_id,
        actor=primary_caregiver,
        med_id=med_id,
        is_paused=is_paused_val,
    )


# ============================================================================
# Web Views (HTML Interfaces)
# ============================================================================

@router.get("/medications", response_class=HTMLResponse, tags=["Medication Safety & Schedule"])
async def medications_page(
    request: Request,
    response: Response,
    session: Optional[SessionData] = Depends(get_optional_session),
    circle_repo: FirestoreCircleRepository = Depends(get_circle_repository),
    med_service: MedicationService = Depends(get_medication_service),
):
    """Caregiver medication management and daily schedule coordination dashboard."""
    if not session:
        return RedirectResponse(url="/auth/login", status_code=status.HTTP_302_FOUND)

    member_dict = await circle_repo.get_member(session.circle_id, session.member_id)
    if not member_dict or not member_dict.get("is_active", True):
        return RedirectResponse(url="/auth/login", status_code=status.HTTP_302_FOUND)

    member_doc = MemberDoc(**member_dict)
    circle_dict = await circle_repo.get_circle(session.circle_id)

    schedule = await med_service.get_daily_schedule(session.circle_id, member_doc)
    medications = await med_service.list_medications(session.circle_id, active_only=False)
    care_brief = await med_service.get_care_brief(session.circle_id, member_doc)
    ledger = await med_service.list_dose_ledger(session.circle_id, limit=20)

    csrf_token = generate_csrf_token()
    set_csrf_cookie(response, csrf_token)

    return templates.TemplateResponse(
        request=request,
        name="medications.html",
        context={
            "app_name": settings.APP_NAME,
            "csrf_token": csrf_token,
            "user": session,
            "member": member_doc,
            "circle": circle_dict or {},
            "schedule": schedule,
            "medications": medications,
            "care_brief": care_brief,
            "ledger": ledger,
            "is_primary": member_doc.is_primary,
            "is_caregiver": member_doc.role == MemberRole.CAREGIVER,
        },
    )


@router.get("/elder/doses", response_class=HTMLResponse, tags=["Medication Safety & Schedule"])
async def elder_doses_page(
    request: Request,
    response: Response,
    session: Optional[SessionData] = Depends(get_optional_session),
    circle_repo: FirestoreCircleRepository = Depends(get_circle_repository),
    med_service: MedicationService = Depends(get_medication_service),
):
    """Elder-friendly high-contrast, large-touch one-tap dose confirmation view."""
    if not session:
        return RedirectResponse(url="/auth/login", status_code=status.HTTP_302_FOUND)

    member_dict = await circle_repo.get_member(session.circle_id, session.member_id)
    if not member_dict or not member_dict.get("is_active", True):
        return RedirectResponse(url="/auth/login", status_code=status.HTTP_302_FOUND)

    member_doc = MemberDoc(**member_dict)
    circle_dict = await circle_repo.get_circle(session.circle_id)
    schedule = await med_service.get_daily_schedule(session.circle_id, member_doc)
    care_brief = await med_service.get_care_brief(session.circle_id, member_doc)

    csrf_token = generate_csrf_token()
    set_csrf_cookie(response, csrf_token)

    return templates.TemplateResponse(
        request=request,
        name="elder_doses.html",
        context={
            "app_name": settings.APP_NAME,
            "csrf_token": csrf_token,
            "user": session,
            "member": member_doc,
            "circle": circle_dict or {},
            "schedule": schedule,
            "care_brief": care_brief,
        },
    )
