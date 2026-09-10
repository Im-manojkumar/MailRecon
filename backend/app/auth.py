from datetime import datetime, timedelta, timezone
from typing import Optional
from jose import JWTError, jwt
from passlib.context import CryptContext
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
import uuid

from app.config import settings
from app.database import get_db
from app.models.analyst import Analyst

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)

def create_access_token(analyst_id: uuid.UUID) -> str:
    expire = datetime.now(timezone.utc) + timedelta(hours=settings.JWT_EXPIRY_HOURS)
    to_encode = {"exp": expire, "sub": str(analyst_id)}
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.JWT_ALGORITHM)
    return encoded_jwt

def verify_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
        return payload
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

async def get_current_analyst(
    token: str = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_db)
) -> uuid.UUID:
    payload = verify_token(token)
    analyst_id_str = payload.get("sub")
    if analyst_id_str is None:
        raise HTTPException(status_code=401, detail="Invalid authentication token")
    
    try:
        analyst_id = uuid.UUID(analyst_id_str)
    except ValueError:
        raise HTTPException(status_code=401, detail="Invalid user ID in token")
        
    return analyst_id
