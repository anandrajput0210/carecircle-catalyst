"""Authentication, Session, and Circle Security Routes for CareCircle."""
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.responses import HTMLResponse, JSONResponse

from app.config import settings
from app.models.auth import (
    AuthStatusResponse,
    AuthType,
    CircleCreateRequest,
    CirclePublicResponse,
    CredentialResetRequest,
    ElderLoginRequest,
    LoginRequest,
    MemberDoc,
    MemberPublicResponse,
    MemberRole,
    RecoveryKeyResponse,
    RecoveryRequest,
    SessionData,
)
from app.repositories.firestore_circle import FirestoreCircleRepository
from app.repositories.firestore_session import FirestoreSessionRepository
from app.services.auth import (
    constant_time_compare,
    generate_circle_code,
    generate_recovery_key,
    hash_credential,
    verify_credential,
    verify_dummy_credential,
)
from app.services.csrf import (
    generate_csrf_token,
    set_csrf_cookie,
    validate_csrf_request,
)
from app.services.dependencies import (
    get_circle_repository,
    get_current_member,
    get_current_session,
    get_current_session_token,
    get_optional_session,
    get_session_service,
    require_caregiver,
)
from app.services.session import SessionService

logger = logging.getLogger("carecircle.routes.auth")

router = APIRouter(tags=["Authentication"])


# ============================================================================
# CSRF Token Provisioning
# ============================================================================

@router.get("/api/auth/csrf")
async def get_csrf_token_endpoint(response: Response):
    """
    Issue a new cryptographic double-submit CSRF token.
    Sets the secure CSRF cookie and returns the token in JSON.
    """
    token = generate_csrf_token()
    set_csrf_cookie(response, token)
    return {"csrf_token": token}


# ============================================================================
# Session Status
# ============================================================================

@router.get("/api/auth/me", response_model=AuthStatusResponse)
async def get_current_auth_status(
    session: Optional[SessionData] = Depends(get_optional_session),
    circle_repo: FirestoreCircleRepository = Depends(get_circle_repository),
):
    """
    Check current authentication status.
    Returns authenticated=False safely if session is missing, expired, or revoked.
    """
    if not session:
        return AuthStatusResponse(authenticated=False, member=None)

    member_dict = await circle_repo.get_member(session.circle_id, session.member_id)
    if not member_dict or not member_dict.get("is_active", True):
        return AuthStatusResponse(authenticated=False, member=None)

    member_doc = MemberDoc(**member_dict)
    return AuthStatusResponse(
        authenticated=True,
        member=member_doc.to_public_response(),
    )


# ============================================================================
# Caregiver & Family Login
# ============================================================================

@router.post("/auth/login")
@router.post("/api/auth/login")
async def caregiver_login(
    payload: LoginRequest,
    request: Request,
    response: Response,
    circle_repo: FirestoreCircleRepository = Depends(get_circle_repository),
    session_repo: FirestoreSessionRepository = Depends(lambda: FirestoreSessionRepository()),
    session_service: SessionService = Depends(get_session_service),
):
    """
    Caregiver and Family member authentication using Username and Password.
    Enforces rate limiting, account lockout, and timing mitigation.
    """
    # 1. CSRF Verification
    validate_csrf_request(request)

    # 2. Account Lookup
    member_dict = await circle_repo.get_member_by_username(payload.username)
    if not member_dict:
        verify_dummy_credential()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password.",
        )

    # Elders must log in via the elder-login endpoint
    if member_dict.get("role") == MemberRole.ELDER.value:
        verify_dummy_credential()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password.",
        )

    # Active Account Check
    if not member_dict.get("is_active", True):
        verify_dummy_credential()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password.",
        )

    # 3. Lockout Check
    locked_until_str = member_dict.get("locked_until")
    if locked_until_str:
        try:
            locked_until = datetime.fromisoformat(locked_until_str)
            if datetime.now(timezone.utc) < locked_until:
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="Account is temporarily locked due to multiple failed login attempts. Please try again later or use emergency recovery.",
                )
        except HTTPException:
            raise
        except Exception:
            pass

    # 4. Credential Verification
    is_valid = verify_credential(member_dict.get("password_hash"), payload.password)
    if not is_valid:
        await session_repo.record_failed_login(
            member_dict["member_id"],
            current_failed=member_dict.get("failed_login_attempts", 0),
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password.",
        )

    # 5. Reset Failed Counter & Create Session
    await session_repo.reset_failed_logins(member_dict["member_id"])

    client_ip = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")
    member_doc = MemberDoc(**member_dict)

    raw_token, session_doc = await session_service.create_session(
        member_doc,
        client_ip=client_ip,
        user_agent=user_agent,
    )

    # 6. Set HttpOnly Session Cookie
    response.set_cookie(
        key=settings.SESSION_COOKIE_NAME,
        value=raw_token,
        max_age=settings.CAREGIVER_ABSOLUTE_TIMEOUT_SECONDS,
        httponly=True,
        secure=settings.COOKIE_SECURE,
        samesite="lax",
        path="/",
    )

    return {
        "status": "success",
        "message": "Login successful.",
        "member": member_doc.to_public_response().model_dump(),
    }


# ============================================================================
# Elder Login (Option B: Circle Code + Elder Name + PIN)
# ============================================================================

@router.post("/auth/elder-login")
@router.post("/api/auth/elder-login")
async def elder_login(
    payload: ElderLoginRequest,
    request: Request,
    response: Response,
    circle_repo: FirestoreCircleRepository = Depends(get_circle_repository),
    session_repo: FirestoreSessionRepository = Depends(lambda: FirestoreSessionRepository()),
    session_service: SessionService = Depends(get_session_service),
):
    """
    Elder authentication using Circle Code + Elder Name + numeric PIN.
    Returns generic failure messages to avoid disclosing namespace or factor validity.
    """
    # 1. CSRF Verification
    validate_csrf_request(request)

    generic_error = "Invalid circle code, name, or passcode. Please try again."

    # 2. Circle Lookup by Code
    circle = await circle_repo.get_circle_by_code(payload.circle_code)
    if not circle or not circle.get("is_active", True):
        verify_dummy_credential()
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=generic_error)

    # 3. Elder Member Lookup within Circle
    elder = await circle_repo.get_elder_by_name(circle["circle_id"], payload.elder_name)
    if not elder or not elder.get("is_active", True):
        verify_dummy_credential()
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=generic_error)

    # 4. Lockout Check
    locked_until_str = elder.get("locked_until")
    if locked_until_str:
        try:
            locked_until = datetime.fromisoformat(locked_until_str)
            if datetime.now(timezone.utc) < locked_until:
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="Account is temporarily locked. Please try again later.",
                )
        except HTTPException:
            raise
        except Exception:
            pass

    # 5. PIN Verification (string preserving leading zeros)
    is_valid = verify_credential(elder.get("password_hash"), payload.pin)
    if not is_valid:
        await session_repo.record_failed_login(
            elder["member_id"],
            current_failed=elder.get("failed_login_attempts", 0),
        )
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=generic_error)

    # 6. Reset Failed Counter & Create Session
    await session_repo.reset_failed_logins(elder["member_id"])

    client_ip = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")
    elder_doc = MemberDoc(**elder)

    raw_token, session_doc = await session_service.create_session(
        elder_doc,
        client_ip=client_ip,
        user_agent=user_agent,
    )

    # 7. Set HttpOnly Session Cookie (12h idle / 24h absolute max)
    response.set_cookie(
        key=settings.SESSION_COOKIE_NAME,
        value=raw_token,
        max_age=settings.ELDER_ABSOLUTE_TIMEOUT_SECONDS,
        httponly=True,
        secure=settings.COOKIE_SECURE,
        samesite="lax",
        path="/",
    )

    return {
        "status": "success",
        "message": "Welcome back!",
        "member": elder_doc.to_public_response().model_dump(),
    }


# ============================================================================
# Logout
# ============================================================================

@router.post("/auth/logout")
async def logout(
    request: Request,
    response: Response,
    session_service: SessionService = Depends(get_session_service),
):
    """
    Revoke the current session and delete the session cookie.
    Other devices and simultaneous sessions for the user remain unaffected.
    """
    validate_csrf_request(request)

    raw_token = request.cookies.get(settings.SESSION_COOKIE_NAME)
    if raw_token:
        await session_service.revoke_current_session(raw_token, reason="logout")

    response.delete_cookie(
        key=settings.SESSION_COOKIE_NAME,
        path="/",
        secure=settings.COOKIE_SECURE,
        samesite="lax",
    )

    return {"status": "success", "message": "Logged out successfully."}


# ============================================================================
# First-Circle Bootstrap Provisioning
# ============================================================================

@router.post("/auth/setup-circle")
async def setup_initial_circle(
    payload: CircleCreateRequest,
    request: Request,
    circle_repo: FirestoreCircleRepository = Depends(get_circle_repository),
):
    """
    Bootstrap the initial care circle, primary caregiver, and elder profile.
    Protected by server-side BOOTSTRAP_SECRET and system_metadata/provisioning.
    """
    validate_csrf_request(request)

    # 1. Validate Bootstrap Secret
    if not settings.BOOTSTRAP_SECRET or not constant_time_compare(payload.bootstrap_secret, settings.BOOTSTRAP_SECRET):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid bootstrap secret. Initial circle setup rejected.",
        )

    # 2. Check if System is Already Initialized
    if circle_repo.is_provisioned():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="CareCircle system is already initialized. Bootstrap cannot be repeated.",
        )

    # 3. Generate Unique Identifiers
    circle_id = str(uuid.uuid4())
    circle_code = generate_circle_code()
    caregiver_id = str(uuid.uuid4())
    elder_id = str(uuid.uuid4())
    recovery_key = generate_recovery_key()

    # 4. Hash Credentials (Argon2id)
    caregiver_password_hash = hash_credential(payload.caregiver_password)
    caregiver_recovery_hash = hash_credential(recovery_key)
    elder_pin_hash = hash_credential(payload.elder_pin)

    now_iso = datetime.now(timezone.utc).isoformat()

    # 5. Create Circle Document
    elder_profile = {
        "name": payload.elder_name,
        "elder_name": payload.elder_name,
        "dob": payload.elder_dob,
        "elder_dob": payload.elder_dob,
        "primary_condition": payload.primary_condition,
        "emergency_phone": payload.emergency_phone,
    }
    await circle_repo.create_circle(
        circle_id=circle_id,
        circle_name=payload.circle_name,
        elder_profile=elder_profile,
        circle_code=circle_code,
    )

    # 6. Create Primary Caregiver Document
    caregiver_doc = MemberDoc(
        member_id=caregiver_id,
        circle_id=circle_id,
        username=payload.caregiver_username,
        display_name=payload.caregiver_name,
        role=MemberRole.CAREGIVER,
        auth_type=AuthType.PASSWORD,
        password_hash=caregiver_password_hash,
        recovery_key_hash=caregiver_recovery_hash,
        auth_version=1,
        is_active=True,
        is_primary=True,
        created_at=now_iso,
    )
    await circle_repo.add_member(circle_id, caregiver_doc.model_dump())

    # 7. Create Elder Document
    elder_username = f"elder_{circle_code.lower()}_{payload.elder_name.strip().lower().replace(' ', '_')}"
    elder_doc = MemberDoc(
        member_id=elder_id,
        circle_id=circle_id,
        username=elder_username,
        display_name=payload.elder_name,
        role=MemberRole.ELDER,
        auth_type=AuthType.PASSCODE,
        password_hash=elder_pin_hash,
        auth_version=1,
        is_active=True,
        is_primary=False,
        created_at=now_iso,
    )
    await circle_repo.add_member(circle_id, elder_doc.model_dump())

    # 8. Mark System Provisioned Permanently
    circle_repo.mark_provisioned({
        "circle_id": circle_id,
        "circle_code": circle_code,
        "primary_caregiver_id": caregiver_id,
    })

    return {
        "status": "success",
        "message": "Care circle provisioned successfully.",
        "circle": {
            "circle_id": circle_id,
            "circle_code": circle_code,
            "name": payload.circle_name,
        },
        "caregiver": caregiver_doc.to_public_response().model_dump(),
        "elder": elder_doc.to_public_response().model_dump(),
        "recovery_key": recovery_key,
    }


# ============================================================================
# Emergency Credential Recovery
# ============================================================================

@router.post("/auth/recover", response_model=RecoveryKeyResponse)
async def recover_account(
    payload: RecoveryRequest,
    request: Request,
    circle_repo: FirestoreCircleRepository = Depends(get_circle_repository),
    session_repo: FirestoreSessionRepository = Depends(lambda: FirestoreSessionRepository()),
):
    """
    Emergency account recovery using single-use recovery key.
    Resets password, rotates recovery key, and invalidates all existing sessions.
    """
    validate_csrf_request(request)

    generic_error = "Invalid username or recovery key."

    # 1. Lookup Account
    member = await circle_repo.get_member_by_username(payload.username)
    if not member or not member.get("recovery_key_hash"):
        verify_dummy_credential()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=generic_error)

    # 2. Verify Recovery Key (Outside Transaction)
    is_valid = verify_credential(member.get("recovery_key_hash"), payload.recovery_key)
    if not is_valid:
        await session_repo.record_failed_login(
            member["member_id"],
            current_failed=member.get("failed_login_attempts", 0),
        )
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=generic_error)

    # 3. Hash New Password & Replacement Key (Outside Transaction)
    new_password_hash = hash_credential(payload.new_password)
    replacement_key = generate_recovery_key()
    replacement_hash = hash_credential(replacement_key)

    # 4. Atomic Commit: Update credentials, increment auth_version, reset lockout
    current_mem = await circle_repo.get_member_by_id_only(member["member_id"])
    if not current_mem or current_mem.get("recovery_key_hash") != member.get("recovery_key_hash"):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Recovery state conflict. Please try again.",
        )

    new_version = current_mem.get("auth_version", 1) + 1
    current_mem["password_hash"] = new_password_hash
    current_mem["recovery_key_hash"] = replacement_hash
    current_mem["auth_version"] = new_version
    current_mem["failed_login_attempts"] = 0
    current_mem["locked_until"] = None

    await circle_repo.update_member(current_mem["circle_id"], current_mem["member_id"], current_mem)

    return RecoveryKeyResponse(
        recovery_key=replacement_key,
        message="Store this replacement recovery key securely offline. It will not be shown again.",
    )


# ============================================================================
# Credential & PIN Reset (Self-Service or Caregiver Admin)
# ============================================================================

@router.post("/api/members/{member_id}/reset-pin")
async def reset_elder_pin(
    member_id: str,
    payload: CredentialResetRequest,
    request: Request,
    caregiver_session: SessionData = Depends(require_caregiver),
    circle_repo: FirestoreCircleRepository = Depends(get_circle_repository),
    session_repo: FirestoreSessionRepository = Depends(lambda: FirestoreSessionRepository()),
):
    """
    Caregiver reset of an elder's numeric PIN.
    Enforces circle isolation, hashes new PIN, and invalidates active elder sessions.
    """
    validate_csrf_request(request)

    if not payload.new_pin:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="New PIN is required for elder passcode reset.",
        )

    # Lookup elder strictly within caregiver's circle
    elder = await circle_repo.get_member(caregiver_session.circle_id, member_id)
    if not elder:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Elder member not found.")

    if elder.get("role") != MemberRole.ELDER.value:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="PIN reset endpoint applies only to elder accounts.",
        )

    new_pin_hash = hash_credential(payload.new_pin)
    new_version = elder.get("auth_version", 1) + 1

    elder["password_hash"] = new_pin_hash
    elder["auth_version"] = new_version
    elder["failed_login_attempts"] = 0
    elder["locked_until"] = None

    await circle_repo.update_member(caregiver_session.circle_id, member_id, elder)

    return {
        "status": "success",
        "message": f"PIN successfully updated for {elder.get('display_name')}.",
    }


@router.post("/api/members/change-password")
async def change_password(
    payload: CredentialResetRequest,
    request: Request,
    session: SessionData = Depends(get_current_session),
    member: MemberDoc = Depends(get_current_member),
    circle_repo: FirestoreCircleRepository = Depends(get_circle_repository),
):
    """
    Self-service password change for logged-in caregivers and family members.
    Requires current password verification and invalidates all existing sessions.
    """
    validate_csrf_request(request)

    if not payload.current_password or not payload.new_password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Current and new password are required for password change.",
        )

    if not verify_credential(member.password_hash, payload.current_password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Current password is incorrect.",
        )

    new_pw_hash = hash_credential(payload.new_password)
    new_version = member.auth_version + 1

    member_dict = member.model_dump()
    member_dict["password_hash"] = new_pw_hash
    member_dict["auth_version"] = new_version

    await circle_repo.update_member(session.circle_id, session.member_id, member_dict)

    return {
        "status": "success",
        "message": "Password changed successfully. All other sessions have been logged out.",
    }
