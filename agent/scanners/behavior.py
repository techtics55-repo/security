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
            "total_cost": 0.0,
            "tool_calls": 0,
            "first_seen": None,
            "last_seen": None,
            "timestamps": [],
            "token_usage": [],
            "models_used": set(),
            "session_durations": [],
            "action_history": [],
        })
        self.heuristics = self._load_heuristics()

    def _load_heuristics(self) -> dict:
        path = Path(self.rules_dir) / "agent_behavior.json"
        if not path.exists():
            return {}
        with open(path) as f:
            data = json.load(f)
            return data.get("behavioral_heuristics", {})

    def _detect_rapid_requests(self, session_id: str, timestamp: datetime, metadata: dict) -> dict:
        stats = self.agent_stats[session_id]
        stats["timestamps"].append(timestamp)
        stats["total_calls"] += 1

        recent_10s = [t for t in stats["timestamps"] if t > timestamp - timedelta(seconds=10)]
        recent_60s = [t for t in stats["timestamps"] if t > timestamp - timedelta(seconds=60)]

        max_10s = self.heuristics.get("max_requests_per_second", 10) * 10

        findings = {}
        if len(recent_10s) > max_10s:
            findings["rapid_requests"] = {
                "calls_in_10s": len(recent_10s),
                "threshold": max_10s,
                "calls_per_second": round(len(recent_10s) / 10, 1),
            }

        if len(recent_60s) > max_10s * 4:
            findings["sustained_high_frequency"] = {
                "calls_in_60s": len(recent_60s),
                "threshold": max_10s * 4,
            }

        time_intervals = []
        for i in range(1, min(len(stats["timestamps"]), 20)):
            diff = (stats["timestamps"][-i] - stats["timestamps"][-i-1]).total_seconds()
            time_intervals.append(diff)
        if time_intervals and len(time_intervals) >= 5:
            avg_interval = sum(time_intervals) / len(time_intervals)
            if avg_interval < 0.1:
                findings["sub_100ms_interval"] = {
                    "average_interval_ms": round(avg_interval * 1000, 1),
                    "samples": len(time_intervals),
                }

        return findings

    def _detect_automation_pattern(self, metadata: dict) -> dict:
        indicators = []
        headers = metadata.get("headers", {})
        user_agent = headers.get("User-Agent", headers.get("user-agent", ""))

        ua_lower = user_agent.lower()
        if "python-requests" in ua_lower:
            indicators.append("python-requests library")
        if "httpx" in ua_lower:
            indicators.append("httpx library")
        if "curl/" in ua_lower or user_agent == "curl":
            indicators.append("curl")
        if "java/" in ua_lower:
            indicators.append("Java HTTP client")
        if "node" in ua_lower or "node-fetch" in ua_lower or "axios" in ua_lower:
            indicators.append("Node.js HTTP client")
        if "go-http-client" in ua_lower:
            indicators.append("Go HTTP client")
        if "okhttp" in ua_lower:
            indicators.append("OkHttp library")
        if "aiohttp" in ua_lower:
            indicators.append("aiohttp library")
        if "postman" in ua_lower:
            indicators.append("Postman (manual API client)")

        interval_ms = metadata.get("time_since_last_call_ms", 0)
        if 0 < interval_ms < 50:
            indicators.append(f"extremely fast interval: {interval_ms}ms")

        if "no-cache" in str(headers) and "no-store" in str(headers):
            pass

        return {
            "is_automated": len(indicators) > 0,
            "indicators": indicators,
        }

    def _track_token_anomaly(self, session_id: str, tokens_used: int, metadata: dict) -> dict:
        stats = self.agent_stats[session_id]
        if tokens_used > 0:
            stats["total_tokens"] += tokens_used
            stats["token_usage"].append({"tokens": tokens_used, "time": datetime.utcnow().isoformat()})

            recent_tokens = [t["tokens"] for t in stats["token_usage"][-20:]]
            if len(recent_tokens) >= 5:
                avg = sum(recent_tokens) / len(recent_tokens)
                if tokens_used > avg * 4 and tokens_used > 2000:
                    return {
                        "token_usage_anomaly": True,
                        "current_tokens": tokens_used,
                        "average_tokens": round(avg),
                        "deviation_ratio": round(tokens_used / avg, 1),
                    }
        return {}

    def _track_cost_anomaly(self, session_id: str, metadata: dict) -> dict:
        stats = self.agent_stats[session_id]
        model = metadata.get("model", "unknown")
        input_tokens = metadata.get("input_tokens", 0)
        output_tokens = metadata.get("output_tokens", 0)

        cost_map = {
            "gpt-4": (0.03, 0.06),
            "gpt-4-turbo": (0.01, 0.03),
            "gpt-3.5-turbo": (0.0015, 0.002),
            "claude-3-opus": (0.015, 0.075),
            "claude-3-sonnet": (0.003, 0.015),
            "claude-3-haiku": (0.00025, 0.00125),
        }
        input_rate, output_rate = cost_map.get(model, (0.001, 0.001))

        estimated_cost = (input_tokens / 1000 * input_rate) + (output_tokens / 1000 * output_rate)
        if estimated_cost > 0:
            stats["total_cost"] += estimated_cost
            if stats["total_cost"] > 10.0:
                return {
                    "cost_anomaly": True,
                    "estimated_total_cost": round(stats["total_cost"], 2),
                    "warning": "Total session cost exceeds $10.00",
                }
        return {}

    def _model_switching(self, session_id: str, model: str) -> dict:
        stats = self.agent_stats[session_id]
        if model != "unknown":
            stats["models_used"].add(model)
        if len(stats["models_used"]) > 3:
            return {
                "model_switching": True,
                "models": list(stats["models_used"]),
                "count": len(stats["models_used"]),
            }
        return {}

    def detect_session_anomaly(self, session_id: str, metadata: dict) -> dict:
        stats = self.agent_stats.get(session_id)
        if not stats:
            return {}

        anomalies = []
        now = datetime.utcnow()

        if stats["first_seen"]:
            session_duration = (now - stats["first_seen"]).total_seconds()
            if session_duration > 3600 and stats["total_calls"] < 2:
                anomalies.append("long_session_no_activity")

        models = list(stats["models_used"])
        if len(models) > 4:
            anomalies.append(f"excessive_model_switching ({len(models)} models)")

        return {"anomalies": anomalies}

    def scan_request(self, prompt: str, metadata: dict) -> ScannerResult:
        session_id = metadata.get("session_id", "default")
        timestamp = datetime.utcnow()
        stats = self.agent_stats[session_id]

        if stats["first_seen"] is None:
            stats["first_seen"] = timestamp
        stats["last_seen"] = timestamp

        rapid = self._detect_rapid_requests(session_id, timestamp, metadata)
        automation = self._detect_automation_pattern(metadata)
        token_anomaly = self._track_token_anomaly(session_id, metadata.get("tokens_used", 0), metadata)
        cost_anomaly = self._track_cost_anomaly(session_id, metadata)
        model_switch = self._model_switching(session_id, metadata.get("model", "unknown"))
        session_anomaly = self.detect_session_anomaly(session_id, metadata)

        all_findings = {}
        concerns = []

        if rapid:
            all_findings.update(rapid)
            for k in rapid:
                concerns.append(k.replace("_", " "))

        if automation.get("is_automated"):
            all_findings["automation"] = automation
            concerns.append("automation pattern")

        if token_anomaly:
            all_findings["token_usage"] = token_anomaly
            concerns.append("token usage anomaly")

        if cost_anomaly:
            all_findings["cost"] = cost_anomaly
            concerns.append("cost anomaly")

        if model_switch:
            all_findings["model_switch"] = model_switch
            concerns.append("model switching")

        if session_anomaly.get("anomalies"):
            all_findings["session"] = session_anomaly
            concerns.extend(session_anomaly["anomalies"])

        passed = len(concerns) == 0
        severity = Severity.MEDIUM if concerns else Severity.INFO

        sev_n = {"info":0,"low":1,"medium":2,"high":3,"critical":4}.get(severity.value,0)
        if any("rapid" in c or "sustained" in c for c in concerns):
            if sev_n < 3:
                severity = Severity.HIGH
        if any("cost" in c for c in concerns):
            if sev_n < 3:
                severity = Severity.HIGH

        return ScannerResult(
            scanner_name=self.name,
            passed=passed,
            severity=severity,
            message=f"{'Normal behavior' if passed else f'Behavioral concerns: {", ".join(concerns[:3])}'}",
            details={
                "findings": all_findings,
                "session_id": session_id,
                "total_calls_this_session": stats["total_calls"],
                "total_tokens_this_session": stats["total_tokens"],
                "session_duration_s": round((timestamp - stats["first_seen"]).total_seconds(), 1)
                if stats["first_seen"] else 0,
            },
            suggestion="Investigate unusual access patterns if unexpected." if not passed else None,
        )

    def scan_response(self, prompt: str, response: str, metadata: dict) -> ScannerResult:
        return ScannerResult(
            scanner_name=self.name,
            passed=True,
            severity=Severity.INFO,
            message="Response behavior analysis complete",
        )
