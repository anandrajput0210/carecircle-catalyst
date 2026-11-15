"""Main FastAPI application for CareCircle."""
import logging
from pathlib import Path
from typing import Any, Optional
from fastapi import Depends, FastAPI, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from app.config import settings
from app.routes.auth import router as auth_router
from app.routes.circle import router as circle_router
from app.routes.medication import router as medication_router
from app.services.csrf import generate_csrf_token, set_csrf_cookie
from app.services.dependencies import get_optional_session
from app.services.firestore import verify_firestore_health

logger = logging.getLogger("carecircle.app")

# Initialize FastAPI app
app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="Collaborative elderly-care and medication-management platform.",
    docs_url="/docs" if settings.DEBUG else None,
    redoc_url="/redoc" if settings.DEBUG else None,
)

# Ensure static & template directories exist
settings.STATIC_DIR.mkdir(parents=True, exist_ok=True)
settings.TEMPLATES_DIR.mkdir(parents=True, exist_ok=True)

# Mount static files
app.mount("/static", StaticFiles(directory=str(settings.STATIC_DIR)), name="static")

# Configure Jinja2 templates
templates = Jinja2Templates(directory=str(settings.TEMPLATES_DIR))


# ============================================================================
# Mandatory Sanitized Validation Error Handler (Section 8)
# ============================================================================

@app.exception_handler(RequestValidationError)
async def sanitized_validation_exception_handler(request: Request, exc: RequestValidationError):
    """
    Sanitized validation error handler.
    Removes raw 'input' values from returned errors to prevent credentials, PINs,
    recovery keys, or bootstrap secrets from leaking in HTTP 422 JSON responses.
    Never logs raw request bodies or exceptions containing sensitive inputs.
    """
    sanitized_errors = []
    for err in exc.errors():
        err_copy = dict(err)
        # Strip raw submitted input value
        err_copy.pop("input", None)
        # Sanitize context dictionary if present
        if "ctx" in err_copy and isinstance(err_copy["ctx"], dict):
            err_copy["ctx"] = {
                k: (str(v) if isinstance(v, Exception) else v)
                for k, v in err_copy["ctx"].items()
                if "password" not in k.lower()
                and "pin" not in k.lower()
                and "secret" not in k.lower()
                and "key" not in k.lower()
            }
        sanitized_errors.append(err_copy)

    # Log safe summary only — never log raw exc or request bodies
    logger.warning(
        f"Validation error on {request.method} {request.url.path}: {len(sanitized_errors)} field error(s)"
    )

    return JSONResponse(
        status_code=422,
        content={"detail": sanitized_errors},
    )


# ============================================================================
# Mount Authentication, Circle Management & Medication Routes
# ============================================================================

app.include_router(auth_router)
app.include_router(circle_router)
app.include_router(medication_router)


# ============================================================================
# System Endpoints & Web Views
# ============================================================================

@app.get("/api/health", tags=["System"])
async def health_check():
    """Health check endpoint reporting runtime environment and Firestore status."""
    firestore_health = verify_firestore_health()
    overall_status = "healthy" if firestore_health.get("status") in ("connected", "unconfigured") else "degraded"
    return JSONResponse(
        status_code=200,
        content={
            "status": overall_status,
            "service": settings.APP_NAME,
            "version": settings.APP_VERSION,
            "environment": settings.ENVIRONMENT,
            "firestore": firestore_health,
        }
    )


@app.get("/", response_class=HTMLResponse, tags=["General"])
async def landing_page(
    request: Request,
    response: Response,
    session: Optional[Any] = Depends(get_optional_session),
):
    """Accessible landing page for CareCircle."""
    csrf_token = generate_csrf_token()
    set_csrf_cookie(response, csrf_token)

    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "app_name": settings.APP_NAME,
            "version": settings.APP_VERSION,
            "environment": settings.ENVIRONMENT,
            "csrf_token": csrf_token,
            "user": session,
        },
    )


@app.get("/auth/login", response_class=HTMLResponse, tags=["Authentication"])
async def login_page(
    request: Request,
    response: Response,
    session: Optional[Any] = Depends(get_optional_session),
):
    """Accessible login page with Elder PIN and Caregiver Password options."""
    csrf_token = generate_csrf_token()
    set_csrf_cookie(response, csrf_token)

    return templates.TemplateResponse(
        request=request,
        name="login.html",
        context={
            "app_name": settings.APP_NAME,
            "csrf_token": csrf_token,
            "user": session,
        },
    )


@app.get("/auth/setup-circle", response_class=HTMLResponse, tags=["Authentication"])
async def setup_circle_page(request: Request, response: Response):
    """Accessible first-circle bootstrap setup wizard."""
    csrf_token = generate_csrf_token()
    set_csrf_cookie(response, csrf_token)

    return templates.TemplateResponse(
        request=request,
        name="setup_circle.html",
        context={
            "app_name": settings.APP_NAME,
            "csrf_token": csrf_token,
        },
    )
