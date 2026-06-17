from datetime import datetime, timedelta
from collections import defaultdict
from typing import Optional


class WorkflowTracker:
    def __init__(self):
        self.sessions = defaultdict(lambda: {
            "steps": [],
            "started_at": None,
            "last_activity": None,
            "status": "idle",
            "step_count": 0,
            "tools_used": set(),
            "total_duration_ms": 0,
            "decisions": [],
        })
        self.workflow_completed = []

    def track_call(self, session_id: str, metadata: dict) -> dict:
        now = datetime.utcnow()
        session = self.sessions[session_id]

        if session["started_at"] is None:
            session["started_at"] = now
            session["status"] = "active"

        step = {
            "timestamp": now.isoformat(),
            "step_number": session["step_count"] + 1,
            "action": metadata.get("action", "unknown"),
            "model": metadata.get("model", "unknown"),
            "tool_calls": metadata.get("tool_calls", []),
            "duration_ms": metadata.get("duration_ms", 0),
            "tokens_used": metadata.get("tokens_used", 0),
        }

        if step["tool_calls"]:
            for tool in step["tool_calls"]:
                session["tools_used"].add(tool.get("name", "unknown"))

        session["steps"].append(step)
        session["step_count"] += 1
        session["last_activity"] = now
        session["total_duration_ms"] += step["duration_ms"]

        return self._analyze_workflow(session_id, session, step)

    def _analyze_workflow(self, session_id: str, session: dict, step: dict) -> dict:
        findings = []

        if session["step_count"] >= 3:
            duration = (session["last_activity"] - session["started_at"]).total_seconds()
            if duration < 10:
                findings.append({
                    "type": "rapid_workflow",
                    "detail": f"{session['step_count']} steps in {duration:.1f}s — automated pipeline",
                    "severity": "info",
                })

        if len(session["tools_used"]) > 3:
            findings.append({
                "type": "multi_tool_workflow",
                "detail": f"Using {len(session['tools_used'])} different tools — complex agent workflow",
                "severity": "info",
            })

        if session["total_duration_ms"] > 30000:
            findings.append({
                "type": "long_running",
                "detail": f"Workflow running for {session['total_duration_ms'] / 1000:.1f}s",
                "severity": "medium",
            })

        action = step.get("action", "")
        if any(kw in action.lower() for kw in ["delete", "remove", "destroy", "terminate"]):
            findings.append({
                "type": "destructive_action",
                "detail": f"Destructive action detected: {action}",
                "severity": "high",
            })

        return {
            "session_id": session_id,
            "step_count": session["step_count"],
            "tools_used": list(session["tools_used"]),
            "duration_ms": session["total_duration_ms"],
            "status": session["status"],
            "findings": findings,
            "current_step": step,
        }

    def complete_workflow(self, session_id: str, outcome: str = "completed") -> dict:
        session = self.sessions.get(session_id)
        if not session:
            return {"error": "Session not found"}

        session["status"] = "completed" if outcome == "completed" else "failed"
        session["completed_at"] = datetime.utcnow().isoformat()
        total_duration = (datetime.utcnow() - session["started_at"]).total_seconds()

        report = {
            "session_id": session_id,
            "total_steps": session["step_count"],
            "total_duration_s": total_duration,
            "tools_used": list(session["tools_used"]),
            "outcome": outcome,
            "status": session["status"],
        }

        self.workflow_completed.append(report)
        return report

    def get_workflow_status(self, session_id: str) -> Optional[dict]:
        session = self.sessions.get(session_id)
        if not session:
            return None
        return {
            "session_id": session_id,
            "step_count": session["step_count"],
            "status": session["status"],
            "last_activity": session["last_activity"].isoformat() if session["last_activity"] else None,
        }
