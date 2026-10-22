"""Authentication and registration routes for APIShield."""

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from backend.config import is_lab_mode
from backend.database import get_db
from backend.models.user import User
from backend.auth.security import hash_password, verify_password, create_access_token
from backend.security.defenses import defense_manager
from backend.security.lockout import login_tracker
from detection.auth import detect_brute_force

router = APIRouter()


class UserRegisterRequest(BaseModel):
    """Registration payload.

    Security requirement: Client must NOT specify role. Server assigns default 'user'.
    extra="forbid" rejects any unexpected fields like 'role'.
    """

    model_config = ConfigDict(extra="forbid")

    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=8, max_length=72)


class UserLoginRequest(BaseModel):
    """Login payload containing username and plaintext password."""

    username: str = Field(...)
    password: str = Field(...)


class UserResponse(BaseModel):
    """Safe user representation omitting sensitive credentials."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    username: str
    role: str


class LoginSuccessResponse(BaseModel):
    """Response returned upon successful credential verification with JWT access token."""

    access_token: str
    token_type: str = "bearer"
    user: UserResponse
    message: str = "Login successful"


@router.post(
    "/register",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new user account",
)
def register(
    request: UserRegisterRequest,
    db: Session = Depends(get_db),
) -> User:
    """Register a new user account with hashed password and default 'user' role."""
    existing_user = db.query(User).filter(User.username == request.username).first()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already registered",
        )

    hashed = hash_password(request.password)

    new_user = User(
        username=request.username,
        hashed_password=hashed,
        role="user",
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user


@router.post(
    "/login",
    response_model=LoginSuccessResponse,
    status_code=status.HTTP_200_OK,
    summary="Authenticate user credentials and issue JWT",
)
def login(
    request: UserLoginRequest,
    db: Session = Depends(get_db),
) -> LoginSuccessResponse:
    """Verify user credentials and issue signed JWT access token.

    Broken Authentication experiment integration (OWASP API2:2023):
    - Failed-login attempts are tracked per username via login_tracker.
    - In lab mode with auth_hardening defense ON:
      * If account is locked out: return HTTP 429 (lockout enforced / blocked).
      * After each failed attempt: record_failure(); emit "blocked" security event.
    - In lab mode with auth_hardening defense OFF:
      * Lockout is NOT enforced; attempts are tracked and a "detected" event is emitted.
    - Outside lab mode: failures are tracked but no events are emitted (safe mode).
    - Successful login always calls record_success() to clear the counter.
    """
    defense_active = defense_manager.get_defenses().get("auth_hardening", False)
    in_lab = is_lab_mode()

    # BOLA-safe: check lockout before revealing whether the account exists
    if defense_active and login_tracker.is_locked_out(request.username):
        retry_after = login_tracker.get_lockout_remaining(request.username) or 0
        # Emit blocked event (lockout enforced)
        if in_lab:
            detect_brute_force(
                db=db,
                username=request.username,
                endpoint="/auth/login",
                method="POST",
                defense_active=True,
                action="blocked",
                user_id=None,
            )
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Account temporarily locked. Try again later.",
            headers={"Retry-After": str(retry_after)},
        )

    user = db.query(User).filter(User.username == request.username).first()

    if not user or not verify_password(request.password, user.hashed_password):
        # Record failed attempt for all modes
        login_tracker.record_failure(request.username)

        # Emit security event in lab mode only
        if in_lab:
            action = "blocked" if defense_active else "detected"
            detect_brute_force(
                db=db,
                username=request.username,
                endpoint="/auth/login",
                method="POST",
                defense_active=defense_active,
                action=action,
                user_id=None,
            )

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )

    # Successful login — clear failure counter
    login_tracker.record_success(request.username)

    # Issue signed JWT containing user ID (sub), username, and role
    access_token = create_access_token(
        subject=str(user.id),
        claims={"username": user.username, "role": user.role},
    )

    return LoginSuccessResponse(
        access_token=access_token,
        token_type="bearer",
        user=UserResponse.model_validate(user),
        message="Login successful",
    )
