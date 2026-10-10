# Security utilities
from argon2 import PasswordHasher
from datetime import datetime,timedelta,timezone
from jose import jwt 
from app.core.config import settings

password_hasher=PasswordHasher()

def hash_password(password:str)->str:
    return password_hasher.hash(password)

def verify_password(password:str,hashed_password:str)->bool:
    try:
        password_hasher.verify(hashed_password,password)
        return True
    except Exception:
        return False

def create_access_token(data:dict)->str:
    to_encode=data.copy()

    now=datetime.now(timezone.utc)
    expire=now + timedelta(
        minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES
    )

    to_encode.update({
        "iat":now,   #issued at
        "exp":expire  #expiration
    })

    return jwt.encode(
        to_encode,
        settings.SECRET_KEY,
        algorithm=settings.ALGORITHM
    )