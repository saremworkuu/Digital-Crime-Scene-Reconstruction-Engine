from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select, delete, func
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError

from app.db.session import get_db
from app.core.dependencies import get_current_user
from app.core.security import verify_password, create_access_token, hash_password

from app.db.models.user import User, UserRole
from app.db.models.login_attempt import LoginAttempt
from app.db.models.revoked_token import RevokedToken

from app.schemas.auth import (
    LoginRequest,
    SignupRequest,
    RegisterRequest,
    TokenResponse,
    UserResponse,
    ChangePasswordRequest,
)
from app.core.config import settings
from slowapi import Limiter
from slowapi.util import get_remote_address
from jose import jwt

router = APIRouter()
security = HTTPBearer()
limiter = Limiter(key_func=get_remote_address)


def to_user_response(user: User) -> UserResponse:
    role_str = user.role.value if hasattr(user.role, "value") else str(user.role)
    created_at_str = (
        user.created_at.isoformat()
        if hasattr(user.created_at, "isoformat")
        else str(user.created_at or "")
    )
    return UserResponse(
        id=str(user.id),
        username=user.username,
        name=user.username,
        email=user.email,
        role=role_str,
        is_active=user.is_active,
        created_at=created_at_str,
    )


@router.post(
    "/signup",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
)
def signup(
    signup_data: SignupRequest,
    db: Session = Depends(get_db),
):
    result = db.execute(
        select(User).where(
            (User.email == str(signup_data.email).lower())
            | (User.username == signup_data.username)
        )
    )
    existing_user = result.scalar_one_or_none()

    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email or username is already registered",
        )
    new_user = User(
        username=signup_data.username,
        email=str(signup_data.email).lower(),
        hashed_password=hash_password(signup_data.password),
        role=UserRole.VIEWER,
        is_active=True,
    )

    try:
        db.add(new_user)
        db.commit()
        db.refresh(new_user)
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Could not register user; email or username may already exist",
        )
    except Exception:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Registration failed due to a server error",
        )

    return to_user_response(new_user)


@router.post(
    "/register",
    response_model=TokenResponse,
    status_code=status.HTTP_201_CREATED,
)
def register(
    register_data: RegisterRequest,
    db: Session = Depends(get_db),
):
    email_clean = str(register_data.email).lower()
    username = register_data.username or register_data.name or email_clean.split("@")[0]

    result = db.execute(
        select(User).where(
            (User.email == email_clean) | (User.username == username)
        )
    )
    if result.scalar_one_or_none() is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email or username is already registered.",
        )

    role_val = register_data.role or "viewer"
    try:
        role_enum = UserRole(role_val.lower())
    except ValueError:
        role_enum = UserRole.VIEWER

    new_user = User(
        username=username,
        email=email_clean,
        hashed_password=hash_password(register_data.password),
        role=role_enum,
        is_active=True,
    )

    try:
        db.add(new_user)
        db.commit()
        db.refresh(new_user)
    except Exception:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="User registration failed.",
        )

    role_str = new_user.role.value if hasattr(new_user.role, "value") else str(new_user.role)
    access_token = create_access_token({
        "sub": str(new_user.id),
        "role": role_str,
    })

    user_resp = to_user_response(new_user)
    return TokenResponse(
        access_token=access_token,
        token=access_token,
        token_type="bearer",
        user=user_resp,
    )


@router.post("/login", response_model=TokenResponse)
def login(
    request: Request,
    login_data: LoginRequest,
    db: Session = Depends(get_db),
):
    client_ip = request.client.host if request.client else "unknown"
    email = str(login_data.email).lower()

    cutoff_time = datetime.now(timezone.utc) - timedelta(minutes=15)

    # Count recent failed attempts for this email and IP.
    attempts = db.execute(
        select(func.count())
        .select_from(LoginAttempt)
        .where(
            LoginAttempt.email == email,
            LoginAttempt.ip_address == client_ip,
            LoginAttempt.failed_at >= cutoff_time,
        )
    ).scalar_one()

    if attempts >= 10:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many failed login attempts. Try again later.",
        )

    # Find the user and verify the password.
    result = db.execute(
        select(User).where(User.email == email)
    )
    user = result.scalar_one_or_none()

    if user is None or not verify_password(
        login_data.password,
        user.hashed_password,
    ):
        db.add(
            LoginAttempt(
                email=email,
                ip_address=client_ip,
            )
        )
        db.commit()

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This account is inactive. Contact an administrator.",
        )

    # Clear recent failures for this email and IP after success.
    db.execute(
        delete(LoginAttempt).where(
            LoginAttempt.email == email,
            LoginAttempt.ip_address == client_ip,
        )
    )
    db.commit()

    role_str = user.role.value if hasattr(user.role, "value") else str(user.role)
    access_token = create_access_token({
        "sub": str(user.id),
        "role": role_str,
    })

    user_resp = to_user_response(user)
    return TokenResponse(
        access_token=access_token,
        token=access_token,
        token_type="bearer",
        user=user_resp,
    )


@router.get("/me", response_model=UserResponse)
def get_current_user_profile(
    current_user: User = Depends(get_current_user),
):
    return to_user_response(current_user)


@router.get("/users", response_model=list[UserResponse])
def get_auth_users(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    users = db.execute(select(User).order_by(User.created_at)).scalars().all()
    return [to_user_response(u) for u in users]


@router.post("/logout")
def logout(
    current_user: User = Depends(get_current_user),
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db),
):
    token = credentials.credentials

    payload = jwt.decode(
        token,
        settings.SECRET_KEY,
        algorithms=[settings.ALGORITHM],
    )
    token_id = payload["jti"]
    expires_at = datetime.fromtimestamp(
        payload["exp"],
        tz=timezone.utc,
    )

    revoked_token = RevokedToken(
        jti=token_id,
        expires_at=expires_at,
    )

    db.add(revoked_token)
    db.commit()

    return {"message": "Logged out successfully"}


@router.post("/refresh", response_model=TokenResponse)
def refresh_token(
    current_user: User = Depends(get_current_user),
):
    role_str = current_user.role.value if hasattr(current_user.role, "value") else str(current_user.role)
    new_token = create_access_token({
        "sub": str(current_user.id),
        "role": role_str,
    })
    return TokenResponse(
        access_token=new_token,
        token=new_token,
        token_type="bearer",
        user=to_user_response(current_user),
    )


@router.post("/change-password")
def change_password(
    data: ChangePasswordRequest,
    current_user: User = Depends(get_current_user),
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db),
):
    if data.confirm_password and data.new_password != data.confirm_password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="New password and confirmation do not match.",
        )
    if data.current_password == data.new_password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="New password must be different from the current password.",
        )
    if not verify_password(
        data.current_password,
        current_user.hashed_password,
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Current password is incorrect.",
        )
    current_user.hashed_password = hash_password(data.new_password)

    payload = jwt.decode(
        credentials.credentials,
        settings.SECRET_KEY,
        algorithms=[settings.ALGORITHM],
    )
    expires_at = datetime.fromtimestamp(
        payload["exp"],
        tz=timezone.utc,
    )
    db.add(
        RevokedToken(
            jti=payload["jti"],
            expires_at=expires_at,
        )
    )

    db.commit()
    return {
        "message": "Password changed successfully. Please log in again."
    }