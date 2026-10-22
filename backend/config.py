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
# Real secrets must come from the environment / .env (which is git-ignored).
# If missing, "change-me", or shorter than 32 chars → generate a one-time ephemeral key
# and emit a WARNING. Never hardcode "change-me" as an operational secret.
import secrets as _secrets
import sys as _sys

_raw_jwt_secret = os.getenv("JWT_SECRET")
if (
    _raw_jwt_secret is None
    or _raw_jwt_secret == "change-me"
    or len(_raw_jwt_secret) < 32
):
    JWT_SECRET: str = _secrets.token_hex(32)
    print(
        "WARNING: JWT_SECRET env var is missing, equals 'change-me', or is shorter than "
        "32 characters. A one-time ephemeral key has been generated for this process. "
        "Set a strong JWT_SECRET in your .env file for production use.",
        file=_sys.stderr,
    )
else:
    JWT_SECRET = _raw_jwt_secret
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
