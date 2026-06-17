from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session
from typing import Optional
from datetime import datetime, timedelta
from ..database import get_db
from .. import models
from ..middleware.auth import get_current_user

router = APIRouter(prefix="/billing", tags=["Billing"])


class UpgradeRequest(BaseModel):
    plan: str


class PlanInfo(BaseModel):
    name: str
    price: float
    requests_per_day: int
    features: list


PLANS = {
    "free": PlanInfo(
        name="Free",
        price=0,
        requests_per_day=25,
        features=["Basic injection + PII scan", "CLI only", "7-day log retention"],
    ),
    "medium": PlanInfo(
        name="Medium",
        price=12.0,
        requests_per_day=500,
        features=["Full scanner suite", "Web dashboard", "Email alerts", "30-day retention"],
    ),
    "ultimate": PlanInfo(
        name="Ultimate",
        price=39.0,
        requests_per_day=10000,
        features=["Everything in Medium", "Agent governance", "Workflow monitoring",
                   "Custom policies", "Compliance reports", "Priority support", "1-year retention"],
    ),
}


@router.get("/plans")
def list_plans():
    return {name: plan.dict() for name, plan in PLANS.items()}


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
        "features": PLANS[req.plan].features,
        "price_monthly": PLANS[req.plan].price,
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
