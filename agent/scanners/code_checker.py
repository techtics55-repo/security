import json
import re
from pathlib import Path
from .base import BaseScanner, ScannerResult, Severity


class CodeChecker(BaseScanner):
    name = "malicious_code"

    def __init__(self, rules_dir: str):
        super().__init__(rules_dir)
        self.patterns = self._load_patterns()
        self.severity_map = {
            "low": Severity.LOW,
            "medium": Severity.MEDIUM,
            "high": Severity.HIGH,
            "critical": Severity.CRITICAL,
        }

    def _load_patterns(self) -> dict:
        path = Path(self.rules_dir) / "dangerous_code.json"
        if not path.exists():
            return {"python_patterns": [], "shell_patterns": [], "javascript_patterns": []}
        with open(path) as f:
            return json.load(f)

    def _scan_code_block(self, code: str, language: str, patterns: list) -> list:
        findings = []
        for p in patterns:
            try:
                regex = re.compile(p["pattern"], re.IGNORECASE)
                matches = regex.findall(code)
                if matches:
                    findings.append({
                        "id": p["id"],
                        "description": p["description"],
                        "severity": p["severity"],
                        "count": len(matches),
                        "language": language,
                        "matched_text": matches[0][:80] if isinstance(matches[0], str) else str(matches[0])[:80],
                    })
            except re.error:
                continue
        return findings

    def _extract_code_blocks(self, text: str) -> list:
        blocks = []
        pattern = re.compile(r"```(\w*)\n(.*?)```", re.DOTALL)
        for match in pattern.finditer(text):
            lang = match.group(1).lower() if match.group(1) else "unknown"
            code = match.group(2)
            blocks.append((lang, code))
        inline_pattern = re.compile(r"`([^`]+)`")
        for match in inline_pattern.finditer(text):
            code = match.group(1)
            blocks.append(("inline", code))
        return blocks

    def _classify_language(self, lang: str) -> str:
        if lang in ("python", "py", "python3", "inline"):
            return "python"
        if lang in ("bash", "sh", "shell", "zsh", "powershell", "cmd", "batch"):
            return "shell"
        if lang in ("javascript", "js", "node", "nodejs", "typescript", "ts"):
            return "javascript"
        return "unknown"

    def scan_request(self, prompt: str, metadata: dict) -> ScannerResult:
        prompt_lower = prompt.lower()
        dangerous_requests = [
            "write code", "generate code", "create a script", "write a program",
            "write a function", "create a python script", "give me code",
            "code that", "script that", "program that",
        ]
        code_requested = any(phrase in prompt_lower for phrase in dangerous_requests)
        return ScannerResult(
            scanner_name=self.name,
            passed=True,
            severity=Severity.INFO,
            message="Prompt requested code generation" if code_requested else "No code generation requested",
            details={"code_requested": code_requested},
        )

    def scan_response(self, prompt: str, response: str, metadata: dict) -> ScannerResult:
        code_blocks = self._extract_code_blocks(response)
        all_findings = []
        highest_severity = Severity.INFO

        for lang, code in code_blocks:
            lang_type = self._classify_language(lang)
            if lang_type == "unknown":
                lang_type = "python"
            patterns_key = f"{lang_type}_patterns"
            patterns = self.patterns.get(patterns_key, [])
            findings = self._scan_code_block(code, lang_type, patterns)
            for f in findings:
                f_sev = self.severity_map.get(f["severity"], Severity.INFO)
                if f_sev.value > highest_severity.value:
                    highest_severity = f_sev
            all_findings.extend(findings)

        passed = len(all_findings) == 0
        return ScannerResult(
            scanner_name=self.name,
            passed=passed,
            severity=highest_severity,
            message=f"{'No dangerous code patterns found' if passed else f'Found {len(all_findings)} dangerous code pattern(s) in AI output'}",
            details={
                "findings": all_findings,
                "code_blocks_found": len(code_blocks),
            },
            suggestion="Review the AI-generated code for safety before execution." if not passed else None,
        )
