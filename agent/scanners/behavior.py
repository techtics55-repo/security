import json
import re
from pathlib import Path
from collections import defaultdict
from datetime import datetime, timedelta
from .base import BaseScanner, ScannerResult, Severity


class BehaviorAnalyzer(BaseScanner):
    name = "behavior_analysis"

    def __init__(self, rules_dir: str):
        super().__init__(rules_dir)
        self.call_history = defaultdict(list)
        self.agent_stats = defaultdict(lambda: {
            "total_calls": 0,
            "total_tokens": 0,
            "tool_calls": 0,
            "first_seen": None,
            "last_seen": None,
            "timestamps": [],
        })
        self.heuristics = self._load_heuristics()

    def _load_heuristics(self) -> dict:
        path = Path(self.rules_dir) / "agent_behavior.json"
        if not path.exists():
            return {}
        with open(path) as f:
            data = json.load(f)
            return data.get("behavioral_heuristics", {})

    def _detect_rapid_requests(self, session_id: str, timestamp: datetime) -> dict:
        stats = self.agent_stats[session_id]
        stats["timestamps"].append(timestamp)
        stats["total_calls"] += 1

        recent = [t for t in stats["timestamps"] if t > timestamp - timedelta(seconds=10)]
        if len(recent) > self.heuristics.get("max_requests_per_second", 10) * 10:
            return {
                "rapid_requests": True,
                "calls_in_10s": len(recent),
                "threshold": self.heuristics.get("max_requests_per_second", 10) * 10,
            }
        return {"rapid_requests": False}

    def _detect_automation_pattern(self, metadata: dict) -> dict:
        indicators = []
        headers = metadata.get("headers", {})
        user_agent = headers.get("User-Agent", headers.get("user-agent", ""))

        if "python-requests" in user_agent.lower():
            indicators.append("python requests library (likely scripted)")
        if "httpx" in user_agent.lower():
            indicators.append("httpx library (likely scripted)")
        if "curl" in user_agent.lower():
            indicators.append("curl (likely scripted)")

        interval_ms = metadata.get("time_since_last_call_ms", 0)
        if 0 < interval_ms < 200:
            indicators.append(f"sub-200ms call interval ({interval_ms}ms) — automated")

        content_type = metadata.get("content_type", "")
        if "json" in content_type and "chat" not in content_type:
            indicators.append("direct JSON API call (no chat interface)")

        return {
            "is_automated": len(indicators) > 0,
            "indicators": indicators,
        }

    def _detect_session_anomaly(self, session_id: str, metadata: dict) -> dict:
        if session_id not in self.agent_stats:
            self.agent_stats[session_id]["first_seen"] = datetime.utcnow()
        self.agent_stats[session_id]["last_seen"] = datetime.utcnow()

        anomalies = []
        stats = self.agent_stats[session_id]

        multi_user = metadata.get("user_id", None)
        if multi_user and len(set(multi_user)) > 1:
            anomalies.append("cross-user session activity detected")

        return {"anomalies": anomalies}

    def scan_request(self, prompt: str, metadata: dict) -> ScannerResult:
        session_id = metadata.get("session_id", "default")
        timestamp = datetime.utcnow()

        rapid = self._detect_rapid_requests(session_id, timestamp)
        automation = self._detect_automation_pattern(metadata)
        anomaly = self._detect_session_anomaly(session_id, metadata)

        findings = {}
        concerns = []

        if rapid.get("rapid_requests"):
            findings["rapid_requests"] = rapid
            concerns.append("abnormal request frequency")

        if automation.get("is_automated"):
            findings["automation"] = automation
            concerns.append("automation pattern detected")

        if anomaly.get("anomalies"):
            findings["anomalies"] = anomaly
            concerns.extend(anomaly["anomalies"])

        passed = len(concerns) == 0
        severity = Severity.MEDIUM if concerns else Severity.INFO

        return ScannerResult(
            scanner_name=self.name,
            passed=passed,
            severity=severity,
            message=f"{'Normal behavior' if passed else f'Behavioral concerns: {', '.join(concerns)}'}",
            details={
                "findings": findings,
                "session_id": session_id,
                "total_calls_this_session": self.agent_stats[session_id]["total_calls"],
            },
            suggestion="Investigate automated access patterns if unexpected." if not passed else None,
        )

    def scan_response(self, prompt: str, response: str, metadata: dict) -> ScannerResult:
        return ScannerResult(
            scanner_name=self.name,
            passed=True,
            severity=Severity.INFO,
            message="Response behavior analysis complete — no concerns",
        )
