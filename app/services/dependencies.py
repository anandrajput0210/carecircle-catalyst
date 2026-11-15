"""FastAPI authentication and role authorization dependencies."""
from typing import Any, List, Optional
from fastapi import Depends, HTTPException, Request, status

from app.config import settings
from app.models.auth import MemberDoc, MemberRole, SessionData
from app.repositories.firestore_circle import FirestoreCircleRepository
from app.repositories.firestore_invitation import FirestoreInvitationRepository
from app.repositories.firestore_ledger import FirestoreDoseLedgerRepository
from app.repositories.firestore_medication import FirestoreMedicationRepository
from app.services.circle import CircleService
from app.services.firestore import CircleSecurityContext
from app.services.invitation import InvitationService
from app.services.medication import MedicationService
from app.services.session import SessionService

# Singleton instances for dependency injection
_circle_repo = FirestoreCircleRepository()
_invitation_repo = FirestoreInvitationRepository()
_medication_repo = FirestoreMedicationRepository()
_ledger_repo = FirestoreDoseLedgerRepository()
_session_service = SessionService(circle_repo=_circle_repo)
_circle_service = CircleService(circle_repo=_circle_repo)
_invitation_service = InvitationService(
    invitation_repo=_invitation_repo,
    circle_repo=_circle_repo,
    session_service=_session_service,
)
_medication_service = MedicationService(
    med_repo=_medication_repo,
    ledger_repo=_ledger_repo,
    circle_repo=_circle_repo,
)


def get_circle_repository() -> FirestoreCircleRepository:
    """Dependency provider for FirestoreCircleRepository."""
    return _circle_repo


def get_invitation_repository() -> FirestoreInvitationRepository:
    """Dependency provider for FirestoreInvitationRepository."""
    return _invitation_repo


def get_medication_repository() -> FirestoreMedicationRepository:
    """Dependency provider for FirestoreMedicationRepository."""
    return _medication_repo


def get_dose_ledger_repository() -> FirestoreDoseLedgerRepository:
    """Dependency provider for FirestoreDoseLedgerRepository."""
    return _ledger_repo


def get_session_service() -> SessionService:
    """Dependency provider for SessionService."""
    return _session_service


def get_circle_service() -> CircleService:
    """Dependency provider for CircleService."""
    return _circle_service


def get_invitation_service() -> InvitationService:
    """Dependency provider for InvitationService."""
    return _invitation_service


def get_medication_service() -> MedicationService:
    """Dependency provider for MedicationService."""
    return _medication_service


def get_current_session_token(request: Request) -> Optional[str]:
    """Extract raw session token from HttpOnly cookie."""
    return request.cookies.get(settings.SESSION_COOKIE_NAME)


async def get_optional_session(
    request: Request,
    session_token: Optional[str] = Depends(get_current_session_token),
    session_service: Any = Depends(get_session_service),
) -> Optional[SessionData]:
    """Retrieve SessionData if an active valid session exists, otherwise None."""
    # Support both FastAPI dependency injection and direct function calls
    from fastapi.params import Depends as DependsType
    if isinstance(session_token, DependsType):
        session_token = get_current_session_token(request)
    if isinstance(session_service, DependsType):
        session_service = get_session_service()

    if not session_token:
        return None
    return await session_service.validate_session(session_token)


async def get_current_session(
    session_data: Optional[SessionData] = Depends(get_optional_session),
) -> SessionData:
    """
    Mandatory authentication dependency.
    Raises HTTP 401 if unauthenticated, expired, or revoked.
    """
    if not session_data:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required. Please sign in.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return session_data


async def get_current_member(
    session: SessionData = Depends(get_current_session),
    circle_repo: FirestoreCircleRepository = Depends(get_circle_repository),
) -> MemberDoc:
    """
    Retrieve full MemberDoc for authenticated session.
    Guarantees member belongs strictly to session circle.
    """
    member_dict = await circle_repo.get_member(session.circle_id, session.member_id)
    if not member_dict or not member_dict.get("is_active", True):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account is inactive or not found.",
        )
    return MemberDoc(**member_dict)


def get_security_context(
    session: SessionData = Depends(get_current_session),
) -> CircleSecurityContext:
    """
    Build authoritative CircleSecurityContext for data isolation.
    Guarantees circle_id comes strictly from validated session.
    """
    return CircleSecurityContext(session.circle_id)


# ============================================================================
# Role-Based Access Control (RBAC) Guards
# ============================================================================

def require_role(allowed_roles: List[MemberRole]):
    """Factory dependency enforcing that session member has one of allowed roles."""
    async def role_checker(session: SessionData = Depends(get_current_session)) -> SessionData:
        if session.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access forbidden: requires one of roles {[r.value for r in allowed_roles]}.",
            )
        return session
    return role_checker


async def require_caregiver(
    session: SessionData = Depends(require_role([MemberRole.CAREGIVER])),
) -> SessionData:
    """Enforce caregiver role."""
    return session


async def require_primary_caregiver(
    session: SessionData = Depends(require_caregiver),
    member: MemberDoc = Depends(get_current_member),
) -> MemberDoc:
    """Enforce primary circle administrator caregiver role."""
    if not member.is_primary:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access forbidden: requires primary circle administrator privileges.",
        )
    return member


async def require_elder(
    session: SessionData = Depends(require_role([MemberRole.ELDER])),
) -> SessionData:
    """Enforce elder role."""
    return session


async def require_family(
    session: SessionData = Depends(require_role([MemberRole.FAMILY])),
) -> SessionData:
    """Enforce family role."""
    return session


async def require_caregiver_or_family(
    session: SessionData = Depends(require_role([MemberRole.CAREGIVER, MemberRole.FAMILY])),
) -> SessionData:
    """Enforce caregiver or family role."""
    return session
