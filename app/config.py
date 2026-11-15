"""Application configuration settings for CareCircle."""
import os
from pathlib import Path
from dotenv import load_dotenv

# Base paths
BASE_DIR = Path(__file__).resolve().parent.parent
APP_DIR = Path(__file__).resolve().parent

# Load .env file if present
load_dotenv(BASE_DIR / ".env")


class Settings:
    """Application settings loaded from environment variables."""

    # Project Information
    APP_NAME: str = "CareCircle"
    APP_VERSION: str = "0.1.0"
    ENVIRONMENT: str = os.getenv("ENVIRONMENT", "development")
    DEBUG: bool = ENVIRONMENT == "development"

    # Security
    SECRET_KEY: str = os.getenv("SECRET_KEY", "carecircle-insecure-dev-secret-key-32b")
    COOKIE_SECURE: bool = os.getenv("COOKIE_SECURE", "False").lower() in ("true", "1", "t")
    SESSION_COOKIE_NAME: str = "carecircle_session"
    SESSION_MAX_AGE_SECONDS: int = 60 * 60 * 24 * 7  # 7 days

    # Firebase Firestore
    FIREBASE_PROJECT_ID: str = os.getenv("FIREBASE_PROJECT_ID", "carecircle-catalyst")
    FIREBASE_SERVICE_ACCOUNT_KEY_B64: str = os.getenv("FIREBASE_SERVICE_ACCOUNT_KEY_B64", "")

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
