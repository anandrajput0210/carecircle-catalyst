"""Phase 1 Foundation and Vercel Readiness Tests."""
import json
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from api.index import app
from app.config import settings

client = TestClient(app)


def test_vercel_asgi_app_import():
    """Verify that api/index.py successfully imports and exposes the FastAPI ASGI app."""
    assert app is not None
    assert app.title == settings.APP_NAME


def test_health_check_endpoint():
    """Verify that the health check endpoint returns 200 OK and valid JSON."""
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["service"] == "CareCircle"
    assert data["version"] == "0.1.0"
    assert "environment" in data


def test_landing_page_accessible_rendering():
    """Verify that the landing page renders with WCAG accessibility landmarks and content."""
    response = client.get("/")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    html = response.text

    # Title & Identity
    assert "CareCircle" in html

    # Accessibility Landmarks & Attributes
    assert 'role="banner"' in html
    assert 'id="main-content"' in html
    assert 'role="main"' in html
    assert 'role="contentinfo"' in html
    assert 'class="skip-link"' in html
    assert 'id="live-announcer"' in html

    # Operational Reality Notice requirement
    assert "Just-In-Time" in html or "JIT" in html

    # Accessibility Toolbar Controls
    assert 'id="toggle-contrast"' in html
    assert 'id="decrease-font"' in html
    assert 'id="increase-font"' in html


def test_static_assets_configured():
    """Verify that CSS and JS static assets exist on disk and are accessible via FastAPI."""
    css_path = settings.STATIC_DIR / "css" / "style.css"
    js_path = settings.STATIC_DIR / "js" / "app.js"
    assert css_path.exists(), "style.css missing"
    assert js_path.exists(), "app.js missing"

    # Test static endpoint response
    css_res = client.get("/static/css/style.css")
    assert css_res.status_code == 200
    assert "high-contrast" in css_res.text


def test_vercel_json_configuration():
    """Verify that vercel.json exists, is valid JSON, and adheres to Hobby constraints."""
    vercel_path = Path(__file__).resolve().parent.parent / "vercel.json"
    assert vercel_path.exists(), "vercel.json missing"

    with open(vercel_path, "r", encoding="utf-8") as f:
        config = json.load(f)

    assert config.get("version") == 2
    assert "builds" in config
    assert config["builds"][0]["src"] == "api/index.py"
    assert config["builds"][0]["use"] == "@vercel/python"

    # Verify functions config does not exceed limits
    functions = config.get("functions", {})
    if "api/index.py" in functions:
        duration = functions["api/index.py"].get("maxDuration", 10)
        assert duration <= 300, "maxDuration exceeds Hobby Fluid compute limit of 300s"

    # Verify Cron configuration (Hobby strictly requires daily or longer)
    crons = config.get("crons", [])
    for cron in crons:
        # Schedule expression: standard 5 fields
        schedule = cron.get("schedule", "")
        parts = schedule.split()
        assert len(parts) == 5, f"Invalid cron expression: {schedule}"
        # Daily cron rule: first two parts must not be '* *' (sub-daily)
        # e.g., '0 6 * * *' runs once daily at 6:00 UTC
        assert parts[0] != "*" and parts[1] != "*", "Sub-daily cron detected! Hobby plan requires daily cron (e.g. 0 6 * * *)."
