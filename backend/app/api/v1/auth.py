from datetime import datetime, timedelta, timezone

from fastapi import APIRouter,Depends,HTTPException,status,Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select, delete, func
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError

from app.db.session import get_db
from app.core.dependencies import get_current_user
from app.core.security import( verify_password,create_access_token,hash_password)
from app.core.dependencies import get_current_user

from app.db.models.user import User
from app.db.models.login_attempt import LoginAttempt
from app.db.models.revoked_token import RevokedToken

from app.schemas.auth import LoginRequest,SignupRequest,TokenResponse,UserResponse, ChangePasswordRequest
from app.core.security import verify_password,create_access_token
from app.core.config import settings
from slowapi import Limiter
from slowapi.util import get_remote_address
from jose import jwt
from fastapi import Request,Depends,HTTPException

router = APIRouter()
security = HTTPBearer()
limiter = Limiter(key_func=get_remote_address)


@router.post(
    "/signup",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
)
def signup(signup_data:SignupRequest,db:Session=Depends(get_db),):
    result=db.execute(
        select(User).where(
            (User.email==signup_data.email)
            | (User.username==signup_data.username)
        )
    )
    existing_user=result.scalar_one_or_none()

    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email or username is already registered"
        )
    new_user=User(
        username=signup_data.username,
        email=str(signup_data.email),
        hashed_password=hash_password(signup_data.password),
        role="viewer",
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
            detail="Could not register user; email or username may already exist"  
        )
    except Exception:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Registration failed due to a server error"
        )
    return UserResponse(
        id=str(new_user.id),
        username=new_user.username,
        email=new_user.email,
        role=new_user.role.value,
        is_active=new_user.is_active,
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

    if attempts >= 5:
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
            detail="This acount is inactive.Contact an admin"
        )

    # Clear recent failures for this email and IP after success.
    db.execute(
        delete(LoginAttempt).where(
            LoginAttempt.email == email,
            LoginAttempt.ip_address == client_ip,
        )
    )
    db.commit()

    access_token = create_access_token({
        "sub": str(user.id),
        "role": user.role.value,
    })

    return TokenResponse(access_token=access_token)


@router.post("/logout")
def logout(
    current_user: User = Depends(get_current_user),
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db),
):
    token=credentials.credentials
    
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

    return {'message':"Logged out successfully"}

@router.post("/refresh",response_model=TokenResponse)
def refresh_token(current_user:User=Depends(get_current_user)):
    new_token=create_access_token({
        "sub":str(current_user.id),
        "role":current_user.role.value,
    })
    return TokenResponse(access_token=new_token)


@router.post("/change-password")
def change_password(data:ChangePasswordRequest,current_user:User=Depends(get_current_user),credentials:HTTPAuthorizationCredentials=Depends(security),db:Session=Depends(get_db),):
    if data.new_password != data.confirm_password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="New password and confirmation do not match",
        )
    if data.current_password ==data.confirm_password:
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
    current_user.hashed_password=hash_password(data.new_password)

    payload=jwt.decode(
        credentials.credentials,
        settings.SECRET_KEY,
        algorithms=[settings.ALGORITHM]
    )
    expires_at=datetime.fromtimestamp(
        payload["exp"],
        tz=timezone.utc
    )
    db.add(
        RevokedToken(
            jti=payload["jti"],
            expires_at=expires_at,
        )
    )

    db.commit()
    return{
        "message":"Password changed successfully.Please log in again"
    }