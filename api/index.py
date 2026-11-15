"""Vercel Serverless Function entrypoint for CareCircle."""
import sys
from pathlib import Path

# Ensure the root directory is on the Python path
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from app.main import app  # ASGI app exposed for Vercel Serverless
