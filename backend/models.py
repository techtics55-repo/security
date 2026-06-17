from sqlalchemy import Column, Integer, String, Float, Boolean, DateTime, Text, JSON
from sqlalchemy.sql import func
from .database import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    full_name = Column(String)
    plan = Column(String, default="free")
    is_active = Column(Boolean, default=True)
    api_key = Column(String, unique=True, index=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    stripe_customer_id = Column(String)
    requests_today = Column(Integer, default=0)
    last_request_date = Column(DateTime(timezone=True))


class ScanLog(Base):
    __tablename__ = "scan_logs"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, index=True)
    timestamp = Column(DateTime(timezone=True), server_default=func.now())
    session_id = Column(String, index=True)
    agent_id = Column(String, index=True)
    scanner_name = Column(String)
    passed = Column(Boolean)
    severity = Column(String)
    message = Column(String)
    details = Column(JSON)
    suggestion = Column(String)
    prompt_hash = Column(String)
    response_hash = Column(String)


class Agent(Base):
    __tablename__ = "agents"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, index=True)
    agent_id = Column(String, unique=True, index=True)
    name = Column(String)
    registered_at = Column(DateTime(timezone=True), server_default=func.now())
    metadata = Column(JSON)
    policies = Column(JSON)
    is_active = Column(Boolean, default=True)


class AuditEntry(Base):
    __tablename__ = "audit_trail"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, index=True)
    timestamp = Column(DateTime(timezone=True), server_default=func.now())
    action = Column(String)
    agent_id = Column(String, index=True)
    session_id = Column(String)
    details = Column(JSON)
    verifier = Column(String)
    policy_violation = Column(Boolean, default=False)


class Policy(Base):
    __tablename__ = "policies"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, index=True)
    name = Column(String)
    description = Column(String)
    rules = Column(JSON)
    action = Column(String, default="block")
    priority = Column(Integer, default=0)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())


class Subscription(Base):
    __tablename__ = "subscriptions"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, index=True)
    plan = Column(String)
    stripe_subscription_id = Column(String)
    status = Column(String, default="active")
    current_period_start = Column(DateTime(timezone=True))
    current_period_end = Column(DateTime(timezone=True))
    created_at = Column(DateTime(timezone=True), server_default=func.now())
