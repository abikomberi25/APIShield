"""Authentication and registration routes for APIShield."""

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from backend.database import get_db
from backend.models.user import User
from backend.auth.security import hash_password, verify_password

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
    """Response returned upon successful credential verification."""

    message: str
    user: UserResponse


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
    # Check if username is already registered to enforce uniqueness
    existing_user = db.query(User).filter(User.username == request.username).first()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already registered",
        )

    # Hash plaintext password using bcrypt before persisting to database
    hashed = hash_password(request.password)

    # All public registrations default strictly to role 'user'
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
    summary="Authenticate user credentials",
)
def login(
    request: UserLoginRequest,
    db: Session = Depends(get_db),
) -> LoginSuccessResponse:
    """Verify user credentials against stored bcrypt hash."""
    user = db.query(User).filter(User.username == request.username).first()

    # Generic error message avoids user enumeration side-channels
    if not user or not verify_password(request.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )

    return LoginSuccessResponse(
        message="Login successful",
        user=UserResponse.model_validate(user),
    )
