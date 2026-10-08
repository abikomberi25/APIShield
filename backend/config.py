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
