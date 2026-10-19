"""
Configuration settings for Digital Time Machine.
"""

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "dtm-hackathon-insecure-dev-key-track03")
    DATABASE_PATH = os.environ.get("DATABASE_PATH", str(BASE_DIR / "digital_time_machine.db"))
    UPLOAD_FOLDER = os.environ.get("UPLOAD_FOLDER", str(BASE_DIR / "uploads"))
    DEMO_DATA_DIR = str(BASE_DIR / "data" / "demo")
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16 MB max upload limit
    ALLOWED_EXTENSIONS = {"csv", "json"}
    DEMO_CASE_ID = "CASE-001"
    DEMO_CASE_NAME = "CASE-001: MISSING CUSTOMER DATABASE"
    LEGACY_DEMO_CASE_ID = "CASE-2026-001"

    # AI Investigation Copilot Configuration (Server-Side Secrets)
    AI_PROVIDER = os.environ.get("AI_PROVIDER", "openai").lower()
    OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY", "")
    OPENAI_MODEL = os.environ.get("OPENAI_MODEL", "gpt-4o-mini")
    AI_REQUEST_TIMEOUT = int(os.environ.get("AI_REQUEST_TIMEOUT", "25"))
    AI_MAX_OUTPUT_TOKENS = int(os.environ.get("AI_MAX_OUTPUT_TOKENS", "1024"))

