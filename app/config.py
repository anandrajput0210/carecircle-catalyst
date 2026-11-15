"""Application configuration settings for CareCircle."""
import os
from pathlib import Path
from dotenv import load_dotenv

# Base paths
BASE_DIR = Path(__file__).resolve().parent.parent
APP_DIR = Path(__file__).resolve().parent

# Load .env file if present
load_dotenv(BASE_DIR / ".env")


def _detect_environment() -> str:
    """Detect runtime environment, prioritizing Vercel deployment variables."""
    vercel_env = os.getenv("VERCEL_ENV")
    if vercel_env:
        return vercel_env.lower()
    return os.getenv("ENVIRONMENT", "development").lower()


class Settings:
    """Application settings loaded from environment variables."""

    # Project Information
    APP_NAME: str = "CareCircle"
    APP_VERSION: str = "0.1.0"
    ENVIRONMENT: str = _detect_environment()
    DEBUG: bool = ENVIRONMENT == "development"

    # Security
    SECRET_KEY: str = os.getenv("SECRET_KEY", "carecircle-insecure-dev-secret-key-32b")
    # In production on Vercel, cookies must always be Secure
    COOKIE_SECURE: bool = (
        ENVIRONMENT in ("production", "preview")
        or os.getenv("COOKIE_SECURE", "False").lower() in ("true", "1", "t")
    )
    SESSION_COOKIE_NAME: str = "carecircle_session"
    SESSION_MAX_AGE_SECONDS: int = 60 * 60 * 24 * 30  # 30 days absolute max
    
    # CSRF Settings
    # Production uses __Host-carecircle_csrf, local dev uses carecircle_csrf
    CSRF_COOKIE_NAME: str = "__Host-carecircle_csrf" if COOKIE_SECURE else "carecircle_csrf"
    CSRF_HEADER_NAME: str = "X-CSRF-Token"
    CSRF_MAX_AGE_SECONDS: int = 60 * 60 * 24  # 24 hours

    # Session Timeouts (Application Level)
    CAREGIVER_IDLE_TIMEOUT_SECONDS: int = 7 * 24 * 60 * 60  # 7 days
    CAREGIVER_ABSOLUTE_TIMEOUT_SECONDS: int = 30 * 24 * 60 * 60  # 30 days
    ELDER_IDLE_TIMEOUT_SECONDS: int = 12 * 60 * 60  # 12 hours
    ELDER_ABSOLUTE_TIMEOUT_SECONDS: int = 24 * 60 * 60  # 24 hours
    SESSION_TOUCH_THROTTLE_SECONDS: int = 15 * 60  # 15 minutes throttle for Spark quota

    # Rate Limiting & Account Lockout
    MAX_LOGIN_ATTEMPTS: int = 5
    LOCKOUT_DURATION_MINUTES: int = 15

    # Bootstrap & First-Circle Provisioning
    BOOTSTRAP_SECRET: str = os.getenv("BOOTSTRAP_SECRET", "carecircle-bootstrap-dev-secret-change-in-prod")

    # Firebase Firestore (Server-Side Service Account Only)
    # Spark Plan Free Tier. Credentials must NEVER be exposed to frontend code.
    FIREBASE_PROJECT_ID: str = os.getenv("FIREBASE_PROJECT_ID", "carecircle-catalyst")
    FIREBASE_SERVICE_ACCOUNT_KEY_B64: str = os.getenv("FIREBASE_SERVICE_ACCOUNT_KEY_B64", "")
    FIREBASE_SERVICE_ACCOUNT_JSON: str = os.getenv("FIREBASE_SERVICE_ACCOUNT_JSON", "")

    # AI Integration (Google Gemini API - Free Tier)
    GEMINI_API_KEY: str = os.getenv("GEMINI_API_KEY", "")

    # Escalation & Background Jobs
    CRON_SECRET: str = os.getenv("CRON_SECRET", "carecircle-cron-secret")
    ESCALATION_GRACE_PERIOD_MINUTES: int = int(os.getenv("ESCALATION_GRACE_PERIOD_MINUTES", "60"))

    # Optional Real Email Delivery (No fake delivery)
    RESEND_API_KEY: str = os.getenv("RESEND_API_KEY", "")
    SENDER_EMAIL: str = os.getenv("SENDER_EMAIL", "alerts@carecircle.app")

    # Template and Static Directories
    TEMPLATES_DIR: Path = APP_DIR / "templates"
    STATIC_DIR: Path = APP_DIR / "static"


settings = Settings()
