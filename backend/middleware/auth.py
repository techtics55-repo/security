from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError, jwt
from datetime import datetime, timedelta
from passlib.context import CryptContext
from sqlalchemy.orm import Session
from ..config import settings
from ..database import get_db, SessionLocal
from .. import models
from typing import Optional

security = HTTPBearer()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=settings.jwt_expire_minutes))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, settings.jwt_secret, algorithm=settings.jwt_algorithm)


def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    try:
        payload = jwt.decode(token, settings.jwt_secret, algorithms=[settings.jwt_algorithm])
        user_id: int = payload.get("user_id")
        if user_id is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        return {"user_id": user_id, "email": payload.get("email", ""), "plan": payload.get("plan", "free")}
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")


def verify_api_key(api_key: str) -> Optional[dict]:
    db = SessionLocal()
    try:
        user = db.query(models.User).filter(models.User.api_key == api_key).first()
        if user and user.is_active:
            return {"user_id": user.id, "email": user.email, "plan": user.plan}
    finally:
        db.close()
    return None


def check_rate_limit(user_info: dict, db: Session) -> bool:
    user = db.query(models.User).filter(models.User.id == user_info["user_id"]).first()
    if not user:
        return False

    today = datetime.utcnow().date()
    if user.last_request_date and user.last_request_date.date() == today:
        if user.plan == "free" and user.requests_today >= settings.free_requests_per_day:
            return False
        if user.plan == "medium" and user.requests_today >= settings.medium_requests_per_day:
            return False
    else:
        user.requests_today = 0
        user.last_request_date = datetime.utcnow()
    return True
