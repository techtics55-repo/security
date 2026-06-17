from dataclasses import dataclass, field
from typing import Any, Optional
from enum import Enum


class Severity(Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class ScannerResult:
    scanner_name: str
    passed: bool
    severity: Severity
    message: str
    details: dict = field(default_factory=dict)
    suggestion: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "scanner": self.scanner_name,
            "passed": self.passed,
            "severity": self.severity.value,
            "message": self.message,
            "details": self.details,
            "suggestion": self.suggestion,
        }


class BaseScanner:
    name: str = "base"

    def __init__(self, rules_dir: str):
        self.rules_dir = rules_dir

    def scan_request(self, prompt: str, metadata: dict) -> ScannerResult:
        raise NotImplementedError

    def scan_response(self, prompt: str, response: str, metadata: dict) -> ScannerResult:
        raise NotImplementedError
