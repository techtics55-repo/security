from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session
from datetime import datetime, timedelta
from ..database import get_db
from .. import models
from ..middleware.auth import get_current_user

router = APIRouter(prefix="/billing", tags=["Billing"])


class UpgradeRequest(BaseModel):
    plan: str


PLANS = {
    "starter": {
        "name": "Starter",
        "price": 99,
        "currency": "INR",
        "requests_per_day": 150,
        "features": [
            "Prompt Injection Detection",
            "PII & Secrets Scan",
            "Malicious Code Detection",
            "Data Flow Mapping",
            "Rogue Agent Detection",
        ],
    },
    "medium": {
        "name": "Medium",
        "price": 499,
        "currency": "INR",
        "requests_per_day": 1000,
        "features": [
            "Prompt Injection Detection",
            "PII & Secrets Scan",
            "Malicious Code Detection",
            "Data Flow Mapping",
            "Rogue Agent Detection",
            "Policy Enforcement Engine",
            "Hallucination Detection",
            "Response Safety Analysis",
        ],
    },
    "ultimate": {
        "name": "Ultimate",
        "price": 2199,
        "currency": "INR",
        "requests_per_day": 10000,
        "features": [
            "Prompt Injection Detection",
            "PII & Secrets Scan",
            "Malicious Code Detection",
            "Data Flow Mapping",
            "Rogue Agent Detection",
            "Policy Enforcement Engine",
            "Hallucination Detection",
            "Response Safety Analysis",
            "AI Thinking Monitor",
            "Vibe-Code Security Scanner",
            "Oracle Node — TaaS (VPI + Ledger + Escrow)",
        ],
    },
}


@router.get("/plans")
def list_plans():
    return PLANS


@router.post("/upgrade")
def upgrade_plan(
    req: UpgradeRequest,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    if req.plan not in PLANS:
        raise HTTPException(status_code=400, detail="Invalid plan")

    user = db.query(models.User).filter(models.User.id == current_user["user_id"]).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    user.plan = req.plan
    user.requests_today = 0

    if req.plan != "free":
        existing_sub = db.query(models.Subscription).filter(
            models.Subscription.user_id == user.id,
            models.Subscription.status == "active",
        ).first()
        if existing_sub:
            existing_sub.plan = req.plan
        else:
            sub = models.Subscription(
                user_id=user.id,
                plan=req.plan,
                status="active",
                current_period_start=datetime.utcnow(),
                current_period_end=datetime.utcnow() + timedelta(days=30),
            )
            db.add(sub)

    db.commit()

    return {
        "status": "upgraded",
        "plan": req.plan,
        "features": PLANS[req.plan]["features"],
        "price_monthly": PLANS[req.plan]["price"],
    }


@router.get("/subscription")
def get_subscription(
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    sub = db.query(models.Subscription).filter(
        models.Subscription.user_id == current_user["user_id"],
        models.Subscription.status == "active",
    ).first()
    if not sub:
        return {"plan": "free", "status": "active"}
    return {
        "plan": sub.plan,
        "status": sub.status,
        "current_period_end": sub.current_period_end.isoformat() if sub.current_period_end else None,
    }
