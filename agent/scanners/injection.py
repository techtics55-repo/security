import json
import re
from pathlib import Path
from typing import List, Optional
from .base import BaseScanner, ScannerResult, Severity


class InjectionScanner(BaseScanner):
    name = "prompt_injection"

    def __init__(self, rules_dir: str):
        super().__init__(rules_dir)
        self.patterns = self._load_patterns()
        self.severity_map = {
            "info": Severity.INFO,
            "low": Severity.LOW,
            "medium": Severity.MEDIUM,
            "high": Severity.HIGH,
            "critical": Severity.CRITICAL,
        }

    def _load_patterns(self) -> List[dict]:
        path = Path(self.rules_dir) / "injection_patterns.json"
        if not path.exists():
            return []
        with open(path) as f:
            data = json.load(f)
        compiled = []
        for p in data.get("patterns", []):
            try:
                compiled.append({
                    "id": p["id"],
                    "pattern": re.compile(p["pattern"], re.IGNORECASE),
                    "description": p["description"],
                    "severity": p["severity"],
                })
            except re.error:
                continue
        return compiled

    def _check_encoding_suspicious(self, text: str) -> Optional[dict]:
        suspicious = 0
        reasons = []

        base64_chars = sum(1 for c in text if c in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
        if len(text) > 50 and base64_chars / len(text) > 0.85:
            suspicious += 1
            reasons.append("high base64 character density")

        hex_chars = sum(1 for c in text if c in "0123456789abcdefABCDEF")
        if len(text) > 40 and hex_chars / len(text) > 0.90:
            suspicious += 1
            reasons.append("high hex character density")

        unicode_controls = sum(1 for c in text if ord(c) in range(0x200B, 0x200F) or ord(c) in (0xFEFF, 0x202E))
        if unicode_controls > 0:
            suspicious += 2
            reasons.append("unicode control characters detected")

        morse_like = sum(1 for c in text if c in ".-/ ")
        if len(text) > 30 and morse_like / len(text) > 0.60:
            suspicious += 1
            reasons.append("high morse-code-like character density")

        if suspicious >= 2:
            return {"suspicious_encoding": True, "reasons": reasons, "score": suspicious}
        return None

    def scan_request(self, prompt: str, metadata: dict) -> ScannerResult:
        findings = []
        severity = Severity.INFO

        for p in self.patterns:
            matches = p["pattern"].findall(prompt)
            if matches:
                finding = {
                    "id": p["id"],
                    "description": p["description"],
                    "matches": matches[:5],
                    "count": len(matches),
                }
                findings.append(finding)
                pattern_severity = self.severity_map.get(p["severity"], Severity.MEDIUM)
                if pattern_severity.value > severity.value:
                    severity = pattern_severity

        encoding_check = self._check_encoding_suspicious(prompt)
        if encoding_check:
            findings.append(encoding_check)
            severity = Severity.HIGH

        passed = len(findings) == 0

        return ScannerResult(
            scanner_name=self.name,
            passed=passed,
            severity=severity,
            message=f"{'No injection detected' if passed else f'Found {len(findings)} injection pattern(s)'}",
            details={"findings": findings, "prompt_length": len(prompt)},
            suggestion="Review flagged patterns. Some may be false positives depending on context."
            if not passed else None,
        )

    def scan_response(self, prompt: str, response: str, metadata: dict) -> ScannerResult:
        data_leak_findings = []
        for p in self.patterns:
            if p["id"] in ("token-leak-1", "token-leak-2", "token-leak-3"):
                matches = p["pattern"].findall(response)
                if matches:
                    data_leak_findings.append({
                        "id": p["id"],
                        "description": p["description"],
                        "found_in_response": True,
                    })

        if data_leak_findings:
            return ScannerResult(
                scanner_name=self.name,
                passed=False,
                severity=Severity.CRITICAL,
                message="Sensitive data detected in AI response",
                details={"findings": data_leak_findings},
                suggestion="AI response contains API keys or secrets. Check if this is expected.",
            )

        return ScannerResult(
            scanner_name=self.name,
            passed=True,
            severity=Severity.INFO,
            message="No data leakage detected in response",
        )
