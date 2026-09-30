"""Password hashing and verification utilities using bcrypt."""

import bcrypt


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
