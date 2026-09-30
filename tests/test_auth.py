"""Tests for password hashing, registration, and login (Milestone M1-C)."""

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from backend.auth.security import hash_password, verify_password
from backend.models.user import User


def test_password_hashing_and_verification() -> None:
    """Verify bcrypt hashing salts unique outputs and verifies timing-safely."""
    password = "MySecurePassword123!"

    hash1 = hash_password(password)
    hash2 = hash_password(password)

    # Hashes must start with bcrypt identifier
    assert hash1.startswith("$2b$")
    # Salting ensures identical plaintext produces different hashes
    assert hash1 != hash2

    # Verification must succeed for correct password
    assert verify_password(password, hash1) is True
    assert verify_password(password, hash2) is True

    # Verification must fail for incorrect password
    assert verify_password("WrongPassword123!", hash1) is False


def test_register_success(client: TestClient, db_session: Session) -> None:
    """Verify user registration persists user, hashes password, and assigns 'user' role."""
    payload = {
        "username": "alice",
        "password": "UserPass123!",
    }
    response = client.post("/auth/register", json=payload)
    assert response.status_code == 201

    data = response.json()
    assert data["username"] == "alice"
    assert data["role"] == "user"
    assert "id" in data
    # Sensitive credentials must not be returned
    assert "password" not in data
    assert "hashed_password" not in data

    # Verify database state
    user = db_session.query(User).filter(User.username == "alice").first()
    assert user is not None
    assert user.role == "user"
    assert verify_password("UserPass123!", user.hashed_password) is True


def test_register_duplicate_username_rejection(client: TestClient) -> None:
    """Verify duplicate username registrations are rejected with HTTP 400."""
    payload = {
        "username": "alice",
        "password": "UserPass123!",
    }
    resp1 = client.post("/auth/register", json=payload)
    assert resp1.status_code == 201

    resp2 = client.post("/auth/register", json=payload)
    assert resp2.status_code == 400
    assert resp2.json()["detail"] == "Username already registered"


def test_register_rejects_client_specified_role(client: TestClient) -> None:
    """Verify registration request rejects attempts by client to inject a role."""
    payload = {
        "username": "malicious_user",
        "password": "UserPass123!",
        "role": "admin",
    }
    response = client.post("/auth/register", json=payload)
    # Extra field rejected by Pydantic extra="forbid"
    assert response.status_code == 422


def test_login_success(client: TestClient) -> None:
    """Verify login succeeds with correct credentials."""
    # Register user
    reg_payload = {"username": "bob", "password": "BobPassword123!"}
    client.post("/auth/register", json=reg_payload)

    # Login
    login_payload = {"username": "bob", "password": "BobPassword123!"}
    response = client.post("/auth/login", json=login_payload)
    assert response.status_code == 200

    data = response.json()
    assert data["message"] == "Login successful"
    assert data["user"]["username"] == "bob"
    assert data["user"]["role"] == "user"


def test_login_incorrect_password_rejection(client: TestClient) -> None:
    """Verify login fails with HTTP 401 when given an incorrect password."""
    reg_payload = {"username": "charlie", "password": "CorrectPassword123!"}
    client.post("/auth/register", json=reg_payload)

    login_payload = {"username": "charlie", "password": "WrongPassword123!"}
    response = client.post("/auth/login", json=login_payload)
    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid username or password"


def test_login_nonexistent_user_rejection(client: TestClient) -> None:
    """Verify login fails with HTTP 401 for a user that does not exist."""
    login_payload = {"username": "nonexistent_user", "password": "AnyPassword123!"}
    response = client.post("/auth/login", json=login_payload)
    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid username or password"
