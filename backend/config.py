"""Application configuration settings for APIShield."""

import os
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables from .env file if present (SPEC.md Safety Rule 4)
env_file_path = Path(__file__).resolve().parent.parent / ".env"
if env_file_path.exists():
    load_dotenv(dotenv_path=env_file_path)

# Network binding configuration (SPEC.md Safety Rule 1: bind only to 127.0.0.1)
HOST = "127.0.0.1"
PORT = 8000

# JWT Authentication configuration (SPEC.md Safety Rule 4: read from environment)
# Real secrets must come from the environment / .env (which is git-ignored)
JWT_SECRET = os.getenv("JWT_SECRET", "change-me")
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Startup-enforced Lab Mode (SPEC.md Safety Rule 6)
# Default is strictly False. Read exclusively from process environment on startup.
# A server started without APISHIELD_LAB_MODE=true never exposes intentionally vulnerable behavior.
STARTUP_LAB_MODE: bool = os.getenv("APISHIELD_LAB_MODE", "false").lower() in ("true", "1", "yes")


def is_lab_mode() -> bool:
    """Return whether the server is operating in experimental lab mode."""
    return STARTUP_LAB_MODE


def set_lab_mode(enabled: bool) -> None:
    """Set lab mode state (primarily for test fixture isolation)."""
    global STARTUP_LAB_MODE
    STARTUP_LAB_MODE = enabled


def reset_lab_mode() -> None:
    """Reset lab mode back to the process environment setting."""
    global STARTUP_LAB_MODE
    STARTUP_LAB_MODE = os.getenv("APISHIELD_LAB_MODE", "false").lower() in ("true", "1", "yes")
