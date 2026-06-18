from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session
from typing import Optional
from datetime import datetime
from ..database import get_db
from .. import models
from ..middleware.auth import get_current_user

router = APIRouter(prefix="/agents", tags=["Agents"])


class RegisterAgentRequest(BaseModel):
    agent_id: str
    name: str = ""
    metadata: dict = {}
    policies: dict = {}
    allowed_actions: list = []


class VerifyActionRequest(BaseModel):
    agent_id: str
    action: str
    cost: float = 0


@router.post("/register")
def register_agent(
    req: RegisterAgentRequest,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    existing = db.query(models.Agent).filter(
        models.Agent.agent_id == req.agent_id,
        models.Agent.user_id == current_user["user_id"],
    ).first()
    if existing:
        existing.metadata_json = req.metadata
        existing.policies = {**req.policies, "allowed_actions": req.allowed_actions}
        db.commit()
        return {"status": "updated", "agent_id": req.agent_id}

    agent = models.Agent(
        user_id=current_user["user_id"],
        agent_id=req.agent_id,
        name=req.name or req.agent_id,
        metadata_json=req.metadata,
        policies={**req.policies, "allowed_actions": req.allowed_actions},
    )
    db.add(agent)
    db.commit()
    return {"status": "registered", "agent_id": req.agent_id}


@router.post("/verify")
def verify_action(
    req: VerifyActionRequest,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    agent = db.query(models.Agent).filter(
        models.Agent.agent_id == req.agent_id,
        models.Agent.user_id == current_user["user_id"],
        models.Agent.is_active == True,
    ).first()

    if not agent:
        audit_entry = models.AuditEntry(
            user_id=current_user["user_id"],
            action="verify_failed",
            agent_id=req.agent_id,
            details={"reason": "agent_not_found", "requested_action": req.action},
            verifier="cloud",
            policy_violation=True,
        )
        db.add(audit_entry)
        db.commit()
        return {"verified": False, "reason": "Agent not found or inactive", "action": "block"}

    policies = agent.policies or {}
    allowed_actions = policies.get("allowed_actions", [])

    if allowed_actions and req.action not in allowed_actions:
        audit_entry = models.AuditEntry(
            user_id=current_user["user_id"],
            action="verify_blocked",
            agent_id=req.agent_id,
            details={"reason": "action_not_allowed", "requested_action": req.action, "allowed": allowed_actions},
            verifier="cloud",
            policy_violation=True,
        )
        db.add(audit_entry)
        db.commit()
        return {"verified": False, "reason": f"Action '{req.action}' not in allowed list", "action": "block"}

    audit_entry = models.AuditEntry(
        user_id=current_user["user_id"],
        action="verify_allowed",
        agent_id=req.agent_id,
        details={"requested_action": req.action, "cost": req.cost},
        verifier="cloud",
        policy_violation=False,
    )
    db.add(audit_entry)
    db.commit()

    return {"verified": True, "reason": "Action permitted by policy", "action": "allow"}


@router.get("/")
def list_agents(
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    agents = db.query(models.Agent).filter(
        models.Agent.user_id == current_user["user_id"],
        models.Agent.is_active == True,
    ).all()
    return [
        {
            "agent_id": a.agent_id,
            "name": a.name,
            "registered_at": a.registered_at.isoformat() if a.registered_at else None,
            "allowed_actions": (a.policies or {}).get("allowed_actions", []),
        }
        for a in agents
    ]
