import json
import re
from pathlib import Path
from typing import List
from .base import BaseScanner, ScannerResult, Severity


class PIIScanner(BaseScanner):
    name = "pii_detection"

    def __init__(self, rules_dir: str):
        super().__init__(rules_dir)
        self.patterns = self._load_patterns()
        self.severity_map = {
            "low": Severity.LOW,
            "medium": Severity.MEDIUM,
            "high": Severity.HIGH,
            "critical": Severity.CRITICAL,
        }

    def _load_patterns(self) -> List[dict]:
        path = Path(self.rules_dir) / "pii_patterns.json"
        if not path.exists():
            return []
        with open(path) as f:
            data = json.load(f)
        compiled = []
        for p in data.get("patterns", []):
            try:
                compiled.append({
                    "id": p["id"],
                    "pattern": re.compile(p["pattern"]),
                    "description": p["description"],
                    "severity": p["severity"],
                })
            except re.error:
                continue
        return compiled

    def _scan_text(self, text: str, context: str) -> list:
        findings = []
        for p in self.patterns:
            matches = p["pattern"].findall(text)
            if matches:
                findings.append({
                    "id": p["id"],
                    "description": p["description"],
                    "severity": p["severity"],
                    "count": len(matches),
                    "context": context,
                    "sample": matches[0][:50] if isinstance(matches[0], str) else str(matches[0])[:50],
                })
        return findings

    def scan_request(self, prompt: str, metadata: dict) -> ScannerResult:
        findings = self._scan_text(prompt, "prompt")
        passed = len(findings) == 0
        severity = Severity.INFO
        sev_order = {"info":0,"low":1,"medium":2,"high":3,"critical":4}
        for f in findings:
            f_sev = self.severity_map.get(f["severity"], Severity.INFO)
            if sev_order.get(f_sev.value, 0) > sev_order.get(severity.value, 0):
                severity = f_sev
        return ScannerResult(
            scanner_name=self.name,
            passed=passed,
            severity=severity,
            message=f"{'No PII detected' if passed else f'Found {len(findings)} PII item(s) in prompt'}",
            details={"findings": findings, "scan_type": "prompt"},
            suggestion="Remove sensitive data from prompts before sending to AI providers."
            if not passed else None,
        )

    def scan_response(self, prompt: str, response: str, metadata: dict) -> ScannerResult:
        findings = self._scan_text(response, "response")
        passed = len(findings) == 0
        severity = Severity.INFO
        sev_order = {"info":0,"low":1,"medium":2,"high":3,"critical":4}
        for f in findings:
            f_sev = self.severity_map.get(f["severity"], Severity.INFO)
            if sev_order.get(f_sev.value, 0) > sev_order.get(severity.value, 0):
                severity = f_sev
        return ScannerResult(
            scanner_name=self.name,
            passed=passed,
            severity=severity,
            message=f"{'No PII detected' if passed else f'Found {len(findings)} PII item(s) in response'}",
            details={"findings": findings, "scan_type": "response"},
            suggestion="Review if AI response should contain this sensitive information."
            if not passed else None,
        )
