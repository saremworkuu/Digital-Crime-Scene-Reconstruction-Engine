# Dependency injection
import uuid

from fastapi import Depends, HTTPException,status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy import select
from sqlalchemy.orm import Session
from jose import JWTError,jwt

from app.core.config import settings
from app.db.session import get_db
from app.db.models.user import User

security=HTTPBearer()

def get_current_user(
        credentials:HTTPAuthorizationCredentials=Depends(security),
        db: Session=Depends(get_db)
)->User:
    token=credentials.credentials

    try:
        payload=jwt.decode(
            token,
            settings.SECRET_KEY,
            algorithms=[settings.ALGORITHM]
        )
        user_id=payload.get("sub")

        if user_id is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token",
            )
        user_uuid=uuid.UUID(user_id)

    except(JWTError,ValueError):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
        )
    result=db.execute(
        select(User).where(User.id==user_uuid)
    )

    user=result.scalar_one_or_none()

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token"
        )
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is inactive",
        )
    return user