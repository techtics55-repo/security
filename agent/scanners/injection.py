import json
import re
import math
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
                    "pattern": re.compile(p["pattern"], re.IGNORECASE | re.DOTALL),
                    "description": p["description"],
                    "severity": p["severity"],
                })
            except re.error:
                continue
        return compiled

    def _shannon_entropy(self, text: str) -> float:
        if not text:
            return 0.0
        entropy = 0.0
        for char in set(text):
            prob = text.count(char) / len(text)
            if prob > 0:
                entropy -= prob * math.log2(prob)
        return entropy

    def _detect_encoding_suspicious(self, text: str) -> Optional[dict]:
        suspicious = 0
        reasons = []

        base64_chars = sum(1 for c in text if c in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
        if len(text) > 30 and base64_chars / max(len(text), 1) > 0.85:
            suspicious += 3
            reasons.append("high base64 character density (possible encoded payload)")

        hex_chars = sum(1 for c in text if c in "0123456789abcdefABCDEF")
        if len(text) > 20 and hex_chars / max(len(text), 1) > 0.92:
            suspicious += 2
            reasons.append("high hex character density (possible encoded payload)")

        entropy = self._shannon_entropy(text)
        if len(text) > 60 and entropy > 5.5:
            suspicious += 1
            reasons.append(f"high entropy ({entropy:.1f}) — possibly encrypted/obfuscated")

        unicode_controls = sum(1 for c in text if ord(c) in (
            set(range(0x200B, 0x200F + 1)) | {0x202A, 0x202B, 0x202C, 0x202D, 0x202E,
            0x2060, 0x2061, 0x2062, 0x2063, 0x2064, 0xFEFF, 0x00AD}))
        if unicode_controls > 0:
            suspicious += 3
            reasons.append(f"{unicode_controls} unicode control/invisible characters (bypass attempt)")

        marker_ratio = sum(1 for c in text if c in ".-/|\\!_+") / max(len(text), 1)
        if len(text) > 30 and marker_ratio > 0.35:
            suspicious += 1
            reasons.append("high separator character density (possible token smuggling)")

        if len(text) > 20:
            alpha_ratio = sum(1 for c in text if c.isalpha()) / max(len(text), 1)
            if alpha_ratio < 0.3 and len(re.findall(r'\w+', text)) < 3:
                suspicious += 1
                reasons.append("unusually low alphabetic content (possible binary/code payload)")

        if suspicious >= 2:
            return {
                "encoding_suspicious": True,
                "score": suspicious,
                "reasons": reasons,
                "entropy": round(entropy, 2),
            }
        return None

    def _detect_instruction_hijack(self, text: str) -> list:
        hijack_patterns = [
            (r"(?:^|\n)\s*(?:new\s+)?(?:instructions?|directive|rule|command|order)[\s:]+\n?", "instruction_setup"),
            (r"(?:^|\n)\s*---+\s*(?:instructions?|directive|rule)[\s:]+\n?", "instruction_separator"),
            (r"(?:^|\n)\s*#{3,}\s+(?:instructions?|directive|rule|override)", "instruction_markdown"),
            (r"(?:^|\n)\s*>\s*(?:instructions?|directive|rule|note|important)", "instruction_blockquote"),
            (r"(?:^|\n)\s*(?:important|critical|key|primary)[\s:]+\n?", "important_prefix"),
        ]
        findings = []
        for pattern, name in hijack_patterns:
            matches = re.findall(pattern, text)
            if matches:
                findings.append({"type": name, "count": len(matches)})
        return findings

    def _detect_multistage(self, text: str) -> list:
        stages = []
        stage_indicators = re.findall(
            r"(?:step|stage|phase|round|part)\s+(?:1|one|first|two|2|second|three|3|third|next|final|last)",
            text, re.IGNORECASE
        )
        if len(stage_indicators) >= 2:
            stages.append({
                "type": "multistage_prompt",
                "stage_count": len(stage_indicators),
                "indicators": stage_indicators[:5],
            })
        return stages

    def _detect_payload_containers(self, text: str) -> list:
        containers = []
        base64_blocks = re.findall(r"[A-Za-z0-9+/]{40,}={0,2}", text)
        if base64_blocks and any(len(b) > 80 for b in base64_blocks):
            containers.append({
                "type": "large_base64_block",
                "count": len(base64_blocks),
                "max_length": max(len(b) for b in base64_blocks),
            })
        hex_blocks = re.findall(r"[0-9a-fA-F]{40,}", text)
        if hex_blocks and any(len(b) > 60 for b in hex_blocks):
            containers.append({
                "type": "large_hex_block",
                "count": len(hex_blocks),
                "max_length": max(len(b) for b in hex_blocks),
            })
        return containers

    def _sev_val(self, sev: Severity) -> int:
        return {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}.get(sev.value, 0)

    def scan_request(self, prompt: str, metadata: dict) -> ScannerResult:
        findings = []
        severity = Severity.INFO

        for p in self.patterns:
            try:
                matches = p["pattern"].findall(prompt)
                if matches:
                    finding = {
                        "id": p["id"],
                        "description": p["description"],
                        "matches": [m[:50] if isinstance(m, str) else str(m)[:50] for m in matches[:3]],
                        "count": len(matches),
                    }
                    findings.append(finding)
                    pattern_severity = self.severity_map.get(p["severity"], Severity.MEDIUM)
                    if self._sev_val(pattern_severity) > self._sev_val(severity):
                        severity = pattern_severity
            except re.error:
                continue

        encoding_check = self._detect_encoding_suspicious(prompt)
        if encoding_check:
            findings.append(encoding_check)
            if self._sev_val(severity) < 3:
                severity = Severity.HIGH

        hijack_findings = self._detect_instruction_hijack(prompt)
        if hijack_findings:
            findings.append({"instruction_hijack": hijack_findings})
            if self._sev_val(severity) < 3:
                severity = Severity.HIGH

        stage_findings = self._detect_multistage(prompt)
        if stage_findings:
            findings.append({"multistage": stage_findings})
            if self._sev_val(severity) < 2:
                severity = Severity.MEDIUM

        payload_containers = self._detect_payload_containers(prompt)
        if payload_containers:
            findings.append({"payload_containers": payload_containers})
            if self._sev_val(severity) < 3:
                severity = Severity.HIGH

        passed = len(findings) == 0

        return ScannerResult(
            scanner_name=self.name,
            passed=passed,
            severity=severity,
            message=f"{'No injection detected' if passed else f'Found {len(findings)} injection indicator(s)'}",
            details={"findings": findings, "prompt_length": len(prompt)},
            suggestion="Review flagged patterns. Some may be false positives depending on context."
            if not passed else None,
        )

    def scan_response(self, prompt: str, response: str, metadata: dict) -> ScannerResult:
        data_leak_findings = []
        for p in self.patterns:
            if p["id"].startswith("token-leak") or p["id"].startswith("api-key"):
                try:
                    matches = p["pattern"].findall(response)
                    if matches:
                        data_leak_findings.append({
                            "id": p["id"],
                            "description": p["description"],
                            "found_in_response": True,
                            "count": len(matches),
                        })
                except re.error:
                    continue

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
