"""Care Circle management, membership, and invitation routes for Phase 4."""
import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from app.config import settings
from app.models.auth import MemberDoc, MemberJoinRequest, MemberRole, SessionData
from app.models.circle import (
    CircleDetailResponse,
    CircleMemberDetailResponse,
    CircleUpdateRequest,
    InvitationCreateRequest,
    InvitationCreateResponse,
    InvitationInspectResponse,
    InvitationPublicResponse,
)
from app.repositories.firestore_circle import FirestoreCircleRepository
from app.services.circle import CircleService
from app.services.csrf import generate_csrf_token, set_csrf_cookie, validate_csrf_request
from app.services.dependencies import (
    get_circle_repository,
    get_circle_service,
    get_current_member,
    get_current_session,
    get_invitation_service,
    get_optional_session,
    require_caregiver,
    require_primary_caregiver,
)
from app.services.invitation import InvitationService

logger = logging.getLogger("carecircle.routes.circle")

router = APIRouter(tags=["Care Circle Management"])
templates = Jinja2Templates(directory=str(settings.TEMPLATES_DIR))


# ============================================================================
# Circle Metadata & Overview Endpoints
# ============================================================================

@router.get(
    "/api/circle",
    response_model=CircleDetailResponse,
    summary="Retrieve current care circle details and active member count",
)
async def get_circle_overview(
    session: SessionData = Depends(get_current_session),
    circle_service: CircleService = Depends(get_circle_service),
) -> CircleDetailResponse:
    """Retrieve detailed information and elder healthcare profile for the caller's circle."""
    return await circle_service.get_circle_detail(session.circle_id)


@router.patch(
    "/api/circle",
    response_model=CircleDetailResponse,
    summary="Update circle metadata and elder healthcare profile (Primary Caregiver only)",
)
async def update_circle(
    payload: CircleUpdateRequest,
    primary_caregiver: MemberDoc = Depends(require_primary_caregiver),
    _csrf: None = Depends(validate_csrf_request),
    circle_service: CircleService = Depends(get_circle_service),
) -> CircleDetailResponse:
    """
    Update care circle name and/or elder profile details.
    Restricted strictly to the primary caregiver.
    """
    return await circle_service.update_circle_metadata(primary_caregiver.circle_id, payload)


# ============================================================================
# Circle Membership Roster Endpoints
# ============================================================================

@router.get(
    "/api/circle/members",
    response_model=List[CircleMemberDetailResponse],
    summary="List all members belonging to the care circle",
)
async def list_members(
    session: SessionData = Depends(get_current_session),
    circle_service: CircleService = Depends(get_circle_service),
) -> List[CircleMemberDetailResponse]:
    """List members belonging to the authenticated circle, sanitized of credential hashes."""
    return await circle_service.list_circle_members(session.circle_id)


@router.get(
    "/api/circle/members/{member_id}",
    response_model=CircleMemberDetailResponse,
    summary="Retrieve single member details with circle isolation",
)
async def get_member_detail(
    member_id: str,
    session: SessionData = Depends(get_current_session),
    circle_service: CircleService = Depends(get_circle_service),
) -> CircleMemberDetailResponse:
    """Retrieve single member document verifying circle isolation."""
    return await circle_service.get_circle_member(session.circle_id, member_id)


@router.post(
    "/api/circle/members/{member_id}/deactivate",
    summary="Soft-deactivate a member and invalidate sessions (Primary Caregiver only)",
)
async def deactivate_member(
    member_id: str,
    primary_caregiver: MemberDoc = Depends(require_primary_caregiver),
    _csrf: None = Depends(validate_csrf_request),
    circle_service: CircleService = Depends(get_circle_service),
) -> Dict[str, Any]:
    """
    Soft-deactivate a member in the circle:
    - Enforces sole primary caregiver protection.
    - Preserves historical records (is_active=False, deactivated_at=now).
    - Increments auth_version for instantaneous O(1) session revocation.
    """
    updated_member = await circle_service.deactivate_member(
        circle_id=primary_caregiver.circle_id,
        requesting_member=primary_caregiver,
        target_member_id=member_id,
    )
    return {
        "status": "success",
        "message": f"Member {updated_member.display_name} has been deactivated.",
        "member": updated_member.model_dump(),
    }


# ============================================================================
# Circle Invitation Endpoints
# ============================================================================

@router.post(
    "/api/circle/invitations",
    response_model=InvitationCreateResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Generate a 48-hour single-use invitation (Primary Caregiver only)",
)
async def create_invitation(
    payload: InvitationCreateRequest,
    request: Request,
    primary_caregiver: MemberDoc = Depends(require_primary_caregiver),
    _csrf: None = Depends(validate_csrf_request),
    invitation_service: InvitationService = Depends(get_invitation_service),
) -> InvitationCreateResponse:
    """
    Generate an invitation link for a new Caregiver or Family member.
    Elder invitations are strictly blocked.
    Stores only the SHA-256 token hash in Firestore.
    """
    base_url = str(request.base_url)
    return await invitation_service.create_invitation(
        circle_id=primary_caregiver.circle_id,
        creator=primary_caregiver,
        payload=payload,
        base_url=base_url,
    )


@router.get(
    "/api/circle/invitations",
    response_model=List[InvitationPublicResponse],
    summary="List circle invitations (Caregivers only)",
)
async def list_invitations(
    session: SessionData = Depends(require_caregiver),
    invitation_service: InvitationService = Depends(get_invitation_service),
) -> List[InvitationPublicResponse]:
    """List pending, accepted, expired, and revoked invitations for caller's circle."""
    return await invitation_service.list_invitations(session.circle_id)


@router.post(
    "/api/circle/invitations/{invitation_id}/revoke",
    response_model=Dict[str, Any],
    summary="Revoke an invitation link (Primary Caregiver only)",
)
async def revoke_invitation(
    invitation_id: str,
    primary_caregiver: MemberDoc = Depends(require_primary_caregiver),
    _csrf: None = Depends(validate_csrf_request),
    invitation_service: InvitationService = Depends(get_invitation_service),
) -> Dict[str, Any]:
    """Revoke a pending invitation link."""
    revoked = await invitation_service.revoke_invitation(
        circle_id=primary_caregiver.circle_id,
        invitation_id=invitation_id,
        revoked_by=primary_caregiver.member_id,
    )
    return {
        "status": "success",
        "message": "Invitation has been revoked.",
        "invitation": revoked.model_dump(),
    }


@router.get(
    "/api/invitations/inspect",
    response_model=InvitationInspectResponse,
    summary="Publicly inspect an invitation token before redemption",
)
async def inspect_invitation(
    token: str = Query(..., description="Raw invitation token"),
    invitation_service: InvitationService = Depends(get_invitation_service),
) -> InvitationInspectResponse:
    """Public safe inspection endpoint for the invitation acceptance page."""
    return await invitation_service.inspect_invitation(token)


@router.post(
    "/api/invitations/accept",
    summary="Accept an invitation and register account (Public)",
)
async def accept_invitation(
    payload: MemberJoinRequest,
    request: Request,
    response: Response,
    _csrf: None = Depends(validate_csrf_request),
    invitation_service: InvitationService = Depends(get_invitation_service),
) -> Dict[str, Any]:
    """
    Accept an invitation token:
    - Verifies token validity and expiration.
    - Hashes password with Argon2id outside the transaction.
    - Atomically redeems token and creates new circle member.
    - Sets active session HttpOnly cookie.
    """
    return await invitation_service.accept_invitation(
        payload=payload,
        request=request,
        response=response,
    )


# ============================================================================
# Web Views (HTML Pages)
# ============================================================================

@router.get("/circle", response_class=HTMLResponse, tags=["Care Circle Management"])
async def circle_overview_page(
    request: Request,
    response: Response,
    session: Optional[SessionData] = Depends(get_optional_session),
    circle_service: CircleService = Depends(get_circle_service),
    circle_repo: FirestoreCircleRepository = Depends(get_circle_repository),
    invitation_service: InvitationService = Depends(get_invitation_service),
):
    """Accessible Care Circle overview, roster, and invitation management view."""
    if not session:
        return RedirectResponse(url="/auth/login", status_code=status.HTTP_302_FOUND)

    member_dict = await circle_repo.get_member(session.circle_id, session.member_id)
    if not member_dict or not member_dict.get("is_active", True):
        return RedirectResponse(url="/auth/login", status_code=status.HTTP_302_FOUND)

    member_doc = MemberDoc(**member_dict)
    circle_detail = await circle_service.get_circle_detail(session.circle_id)
    members_list = await circle_service.list_circle_members(session.circle_id)

    invitations_list: List[InvitationPublicResponse] = []
    if member_doc.is_primary:
        invitations_list = await invitation_service.list_invitations(session.circle_id)

    csrf_token = generate_csrf_token()
    set_csrf_cookie(response, csrf_token)

    return templates.TemplateResponse(
        request=request,
        name="circle_overview.html",
        context={
            "app_name": settings.APP_NAME,
            "csrf_token": csrf_token,
            "user": session,
            "member": member_doc,
            "circle": circle_detail,
            "members": members_list,
            "is_primary": member_doc.is_primary,
            "invitations": invitations_list,
        },
    )


@router.get("/invite/accept", response_class=HTMLResponse, tags=["Care Circle Management"])
async def accept_invitation_page(
    request: Request,
    response: Response,
    token: Optional[str] = None,
    session: Optional[SessionData] = Depends(get_optional_session),
):
    """Accessible invitation acceptance and registration landing page."""
    csrf_token = generate_csrf_token()
    set_csrf_cookie(response, csrf_token)

    return templates.TemplateResponse(
        request=request,
        name="accept_invitation.html",
        context={
            "app_name": settings.APP_NAME,
            "csrf_token": csrf_token,
            "user": session,
            "token": token or "",
        },
    )
