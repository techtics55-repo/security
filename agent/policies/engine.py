import json
import re
import yaml
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional, Callable
from datetime import datetime


@dataclass
class PolicyRule:
    field: str
    operator: str
    value: any
    action: str = "block"

    def evaluate(self, context: dict) -> bool:
        actual = context.get(self.field)
        if self.operator == "equals":
            return actual == self.value
        elif self.operator == "not_equals":
            return actual != self.value
        elif self.operator == "contains":
            return self.value in str(actual)
        elif self.operator == "not_contains":
            return self.value not in str(actual)
        elif self.operator == "gt":
            return actual is not None and actual > self.value
        elif self.operator == "lt":
            return actual is not None and actual < self.value
        elif self.operator == "gte":
            return actual is not None and actual >= self.value
        elif self.operator == "lte":
            return actual is not None and actual <= self.value
        elif self.operator == "in":
            return actual in self.value
        elif self.operator == "not_in":
            return actual not in self.value
        elif self.operator == "matches":
            return bool(re.search(self.value, str(actual)))
        elif self.operator == "exists":
            return actual is not None
        return False


@dataclass
class Policy:
    name: str
    description: str
    rules: list = field(default_factory=list)
    action: str = "block"
    priority: int = 0

    def evaluate(self, context: dict) -> Optional[dict]:
        for rule in self.rules:
            if not isinstance(rule, PolicyRule):
                continue
            if rule.evaluate(context):
                return {
                    "policy": self.name,
                    "rule": rule.field,
                    "action": rule.action or self.action,
                    "reason": f"Rule '{rule.field} {rule.operator} {rule.value}' matched",
                }
        return None


class PolicyEngine:
    def __init__(self):
        self.policies = []
        self.on_block: Optional[Callable] = None

    def add_policy(self, policy: Policy):
        self.policies.append(policy)
        self.policies.sort(key=lambda p: p.priority, reverse=True)

    def add_policy_from_dict(self, data: dict):
        rules = []
        for r in data.get("rules", []):
            rules.append(PolicyRule(
                field=r["field"],
                operator=r["operator"],
                value=r["value"],
                action=r.get("action", "block"),
            ))
        policy = Policy(
            name=data["name"],
            description=data.get("description", ""),
            rules=rules,
            action=data.get("action", "block"),
            priority=data.get("priority", 0),
        )
        self.add_policy(policy)

    def load_policy_file(self, path: str):
        p = Path(path)
        if not p.exists():
            return
        if p.suffix in (".yaml", ".yml"):
            with open(p) as f:
                data = yaml.safe_load(f)
        elif p.suffix == ".json":
            with open(p) as f:
                data = json.load(f)
        else:
            return

        if isinstance(data, list):
            for item in data:
                self.add_policy_from_dict(item)
        elif isinstance(data, dict):
            self.add_policy_from_dict(data)

    def evaluate(self, context: dict) -> dict:
        for policy in self.policies:
            result = policy.evaluate(context)
            if result:
                if result["action"] == "block" and self.on_block:
                    self.on_block(result)
                return result
        return {"action": "allow", "reason": "no matching policies"}

    def create_default_policies(self) -> list:
        defaults = [
            Policy(
                name="block-critical-severity",
                description="Block any scan with critical severity",
                rules=[
                    PolicyRule(field="highest_severity", operator="equals", value="critical", action="block"),
                ],
                action="block",
                priority=100,
            ),
            Policy(
                name="block-unknown-endpoints",
                description="Block requests to unknown AI provider endpoints",
                rules=[
                    PolicyRule(field="known_provider", operator="equals", value=False, action="block"),
                ],
                action="block",
                priority=90,
            ),
            Policy(
                name="block-agent-without-registration",
                description="Block unregistered agents from performing actions",
                rules=[
                    PolicyRule(field="agent_registered", operator="equals", value=False, action="block"),
                ],
                action="block",
                priority=80,
            ),
            Policy(
                name="warn-high-severity",
                description="Warn on high severity findings",
                rules=[
                    PolicyRule(field="highest_severity", operator="equals", value="high", action="warn"),
                ],
                action="warn",
                priority=50,
            ),
        ]
        for p in defaults:
            self.add_policy(p)
        return defaults
