"""Main FastAPI application for CareCircle."""
from pathlib import Path
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from app.config import settings
from app.services.firestore import verify_firestore_health

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
async def landing_page(request: Request):
    """Accessible landing page for CareCircle."""
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "app_name": settings.APP_NAME,
            "version": settings.APP_VERSION,
            "environment": settings.ENVIRONMENT,
        },
    )
