import json
import re
from pathlib import Path
from typing import Optional


class AgentDetector:
    def __init__(self, rules_dir: str):
        self.rules_dir = rules_dir
        self.signatures = self._load_signatures()
        self.agent_registry = {}

    def _load_signatures(self) -> list:
        path = Path(self.rules_dir) / "agent_behavior.json"
        if not path.exists():
            return []
        with open(path) as f:
            data = json.load(f)
            return data.get("agent_signatures", [])

    def detect_agent(self, prompt: str, metadata: dict) -> Optional[dict]:
        prompt_lower = prompt.lower()
        headers = metadata.get("headers", {})
        user_agent = headers.get("User-Agent", headers.get("user-agent", ""))

        matched = []
        for sig in self.signatures:
            try:
                if re.search(sig["pattern"], prompt_lower, re.IGNORECASE):
                    matched.append({
                        "id": sig["id"],
                        "framework": sig["description"],
                        "category": sig["category"],
                    })
                elif re.search(sig["pattern"], user_agent, re.IGNORECASE):
                    matched.append({
                        "id": sig["id"],
                        "framework": sig["description"],
                        "category": sig["category"],
                        "source": "user-agent",
                    })
            except re.error:
                continue

        workflow_hints = self._detect_workflow_hints(prompt_lower)
        if workflow_hints:
            matched.extend(workflow_hints)

        if not matched:
            return None

        categories = set(m["category"] for m in matched)
        is_autonomous = "agent" in categories or "workflow" in categories

        return {
            "agent_detected": True,
            "signatures": matched,
            "categories": list(categories),
            "is_autonomous": is_autonomous,
            "confidence": "high" if is_autonomous else "medium",
        }

    def _detect_workflow_hints(self, text: str) -> list:
        hints = []
        workflow_patterns = [
            ("step-1", r"step\s+(1|one|first)", "Workflow step indicator"),
            ("step-2", r"step\s+(2|two|second)", "Multi-step workflow"),
            ("task-1", r"task\s+(1|one|first)", "Task-based workflow"),
            ("automated", r"automated\s+(workflow|pipeline|process)", "Automation indicator"),
            ("scheduled", r"(schedule|cron|every\s+\d+\s+(hour|minute|day))", "Scheduled execution"),
            ("loop", r"(loop|iterate|for\s+each|batch\s+process)", "Batch processing pattern"),
        ]
        for pid, pattern, desc in workflow_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                hints.append({
                    "id": f"workflow-{pid}",
                    "framework": desc,
                    "category": "workflow",
                })
        return hints

    def register_agent(self, agent_id: str, metadata: dict) -> dict:
        self.agent_registry[agent_id] = {
            "agent_id": agent_id,
            "registered_at": __import__("datetime").datetime.utcnow().isoformat(),
            "policies": metadata.get("policies", {}),
            "allowed_actions": metadata.get("allowed_actions", []),
            "max_budget": metadata.get("max_budget", None),
            "human_owner": metadata.get("human_owner", None),
        }
        return self.agent_registry[agent_id]

    def verify_agent_action(self, agent_id: str, action: str, cost: float = 0) -> dict:
        if agent_id not in self.agent_registry:
            return {
                "verified": False,
                "reason": "Agent not registered",
                "action": "block",
            }

        agent = self.agent_registry[agent_id]
        allowed = agent.get("allowed_actions", [])
        max_budget = agent.get("max_budget")

        if allowed and action not in allowed:
            return {
                "verified": False,
                "reason": "Action not in allowed list",
                "action": "block",
                "agent_id": agent_id,
                "requested_action": action,
            }

        if max_budget is not None and cost > max_budget:
            return {
                "verified": False,
                "reason": f"Cost ${cost:.2f} exceeds max budget ${max_budget:.2f}",
                "action": "block",
                "agent_id": agent_id,
                "requested_action": action,
                "cost": cost,
                "budget": max_budget,
            }

        return {
            "verified": True,
            "reason": "Action permitted by policy",
            "action": "allow",
            "agent_id": agent_id,
            "requested_action": action,
        }
