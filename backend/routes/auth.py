from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, EmailStr
from sqlalchemy.orm import Session
from ..database import get_db
from .. import models
from ..middleware.auth import hash_password, verify_password, create_access_token, get_current_user
import secrets

router = APIRouter(prefix="/auth", tags=["Authentication"])


class RegisterRequest(BaseModel):
    email: EmailStr
    password: str
    full_name: str = ""


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class AuthResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user_id: int
    plan: str
    api_key: str


@router.post("/register")
def register(req: RegisterRequest, db: Session = Depends(get_db)):
    existing = db.query(models.User).filter(models.User.email == req.email).first()
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")

    user = models.User(
        email=req.email,
        hashed_password=hash_password(req.password),
        full_name=req.full_name,
        plan="free",
        api_key=f"aeg_{secrets.token_hex(24)}",
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    token = create_access_token({"user_id": user.id, "email": user.email, "plan": user.plan})
    return AuthResponse(
        access_token=token,
        user_id=user.id,
        plan=user.plan,
        api_key=user.api_key,
    )


@router.post("/login")
def login(req: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.email == req.email).first()
    if not user or not verify_password(req.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid email or password")

    token = create_access_token({"user_id": user.id, "email": user.email, "plan": user.plan})
    return AuthResponse(
        access_token=token,
        user_id=user.id,
        plan=user.plan,
        api_key=user.api_key,
    )


@router.get("/me")
def get_profile(current_user: dict = Depends(get_current_user)):
    return current_user
