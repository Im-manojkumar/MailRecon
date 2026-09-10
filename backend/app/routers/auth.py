from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
import uuid

from app.database import get_db
from app.models.analyst import Analyst
from app.schemas.auth import LoginRequest, RegisterRequest, TokenResponse, AnalystResponse
from app.auth import hash_password, verify_password, create_access_token, get_current_analyst

router = APIRouter()

@router.post("/register", response_model=TokenResponse, status_code=status.HTTP_201_CREATED)
async def register(req: RegisterRequest, db: AsyncSession = Depends(get_db)):
    # Check if email exists
    result = await db.execute(select(Analyst).where(Analyst.email == req.email))
    if result.scalars().first():
        raise HTTPException(status_code=400, detail="Email already registered")
        
    new_analyst = Analyst(
        email=req.email,
        hashed_password=hash_password(req.password),
        display_name=req.display_name
    )
    db.add(new_analyst)
    await db.commit()
    await db.refresh(new_analyst)
    
    token = create_access_token(new_analyst.id)
    return {"access_token": token, "token_type": "bearer"}

@router.post("/login", response_model=TokenResponse)
async def login(req: LoginRequest, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Analyst).where(Analyst.email == req.email))
    analyst = result.scalars().first()
    
    if not analyst or not verify_password(req.password, analyst.hashed_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
        
    if not analyst.is_active:
        raise HTTPException(status_code=400, detail="Inactive user")
        
    token = create_access_token(analyst.id)
    return {"access_token": token, "token_type": "bearer"}

@router.get("/me", response_model=AnalystResponse)
async def get_me(analyst_id: uuid.UUID = Depends(get_current_analyst), db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Analyst).where(Analyst.id == analyst_id))
    analyst = result.scalars().first()
    if not analyst:
        raise HTTPException(status_code=404, detail="User not found")
    return analyst
