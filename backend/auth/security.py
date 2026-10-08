"""Password hashing and JWT token security utilities for APIShield."""

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional
import bcrypt
import jwt

from backend.config import ACCESS_TOKEN_EXPIRE_MINUTES, JWT_ALGORITHM, JWT_SECRET


def hash_password(password: str) -> str:
    """Hash a plaintext password using bcrypt with a random 128-bit salt.

    Bcrypt is deliberately computationally expensive and therefore significantly
    increases the computational cost of large-scale offline dictionary and brute-force
    attacks if the database is ever compromised.
    """
    password_bytes = password.encode("utf-8")
    salt = bcrypt.gensalt(rounds=12)
    hashed = bcrypt.hashpw(password_bytes, salt)
    return hashed.decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a candidate plaintext password against a stored bcrypt hash.

    Uses constant-time comparison under the hood to protect against timing side-channel attacks.
    """
    password_bytes = plain_password.encode("utf-8")
    hashed_bytes = hashed_password.encode("utf-8")
    return bcrypt.checkpw(password_bytes, hashed_bytes)


def create_access_token(
    subject: str,
    claims: Optional[Dict[str, Any]] = None,
    expires_delta: Optional[timedelta] = None,
) -> str:
    """Create a cryptographically signed JWT access token using HS256.

    Contains sub (stable user identity), iat (issued at), exp (expiration timestamp),
    and safe authorization claims. Never places passwords, hashes, or secrets in payload.
    """
    now = datetime.now(timezone.utc)
    if expires_delta:
        expire = now + expires_delta
    else:
        expire = now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)

    payload: Dict[str, Any] = {
        "sub": str(subject),
        "iat": int(now.timestamp()),
        "exp": int(expire.timestamp()),
    }
    if claims:
        payload.update(claims)

    encoded_jwt = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return encoded_jwt


def decode_access_token(token: str) -> Dict[str, Any]:
    """Decode and verify a JWT access token using the server's JWT_SECRET.

    Validates cryptographic signature and expiration before returning payload claims.
    Raises jwt.PyJWTError if the token is invalid, expired, or malformed.
    """
    payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    return payload
