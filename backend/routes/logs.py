from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session
from typing import Optional
from datetime import datetime
from ..database import get_db
from .. import models
from ..middleware.auth import get_current_user, check_rate_limit, verify_api_key

router = APIRouter(prefix="/logs", tags=["Logs"])


class ScanLogEntry(BaseModel):
    session_id: str = "default"
    agent_id: str = ""
    scanner_name: str
    passed: bool
    severity: str
    message: str = ""
    details: dict = {}
    suggestion: str = ""
    prompt_hash: str = ""
    response_hash: str = ""


@router.post("/ingest")
def ingest_log(
    entry: ScanLogEntry,
    db: Session = Depends(get_db),
    api_key: Optional[str] = Query(None),
):
    user = None
    if api_key:
        user = verify_api_key(api_key)
    if not user:
        raise HTTPException(status_code=401, detail="Valid API key required")

    if not check_rate_limit(user, db):
        raise HTTPException(status_code=429, detail="Daily request limit exceeded")

    db_user = db.query(models.User).filter(models.User.id == user["user_id"]).first()
    if db_user:
        db_user.requests_today += 1
        db_user.last_request_date = datetime.utcnow()

    log = models.ScanLog(
        user_id=user["user_id"],
        session_id=entry.session_id,
        agent_id=entry.agent_id,
        scanner_name=entry.scanner_name,
        passed=entry.passed,
        severity=entry.severity,
        message=entry.message,
        details=entry.details,
        suggestion=entry.suggestion,
        prompt_hash=entry.prompt_hash,
        response_hash=entry.response_hash,
    )
    db.add(log)
    db.commit()
    return {"status": "ok", "log_id": log.id}


@router.get("/")
def list_logs(
    limit: int = Query(50, le=100),
    severity: Optional[str] = None,
    agent_id: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    query = db.query(models.ScanLog).filter(models.ScanLog.user_id == current_user["user_id"])
    if severity:
        query = query.filter(models.ScanLog.severity == severity)
    if agent_id:
        query = query.filter(models.ScanLog.agent_id == agent_id)
    logs = query.order_by(models.ScanLog.id.desc()).limit(limit).all()
    return [
        {
            "id": l.id,
            "timestamp": l.timestamp.isoformat() if l.timestamp else None,
            "scanner": l.scanner_name,
            "passed": l.passed,
            "severity": l.severity,
            "message": l.message,
            "agent_id": l.agent_id,
        }
        for l in logs
    ]


@router.get("/stats")
def get_stats(
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    user_id = current_user["user_id"]
    total = db.query(models.ScanLog).filter(models.ScanLog.user_id == user_id).count()
    issues = db.query(models.ScanLog).filter(
        models.ScanLog.user_id == user_id,
        models.ScanLog.passed == False,
    ).count()
    return {"total_scans": total, "total_issues": issues, "plan": current_user["plan"]}
