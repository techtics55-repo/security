import re
from typing import List, Tuple
from .base import BaseScanner, ScannerResult, Severity


class ResponseSafetyScanner(BaseScanner):
    name = "response_safety"

    def __init__(self, rules_dir: str):
        super().__init__(rules_dir)
        self.critical_categories = self._build_critical_patterns()
        self.high_categories = self._build_high_patterns()
        self.medium_categories = self._build_medium_patterns()

    def _build_critical_patterns(self) -> List[Tuple[str, str]]:
        return [
            ("self_harm_methods", r"(?:how\s+to|ways\s+to|methods?\s+for|techniques?\s+for)\s+(?:commit\s+suicide|kill\s+(?:yourself|myself)|self[-\s]harm|end\s+(?:your|my)\s+life)"),
            ("child_exploit", r"(?:child\s+(?:porn|abuse|exploit|grooming)|minor\s+(?:abuse|exploit)|cp\s+(?:content|material))"),
            ("violent_extremism", r"(?:bomb[-\s]?making|explosive\s+(?:device|making|manufacture)|terrorist\s+(?:attack|act|recruit)|radicali[sz]ation)"),
            ("dangerous_instructions", r"(?:step[-\s]?by[-\s]?step\s+(?:guide|instruction|tutorial)\s+(?:on\s+)?(?:how\s+to\s+)?(?:make|build|create|manufacture)\s+(?:a\s+)?(?:bomb|explosive|weapon|poison|drug|nerve\s+agent))"),
            ("weapon_manufacture", r"(?:3[dD]\s*(?:print|manufactur).{0,30}(?:gun|firearm|weapon|receiver|magazine)|ghost\s+gun|printed\s+receiver)"),
        ]

    def _build_high_patterns(self) -> List[Tuple[str, str]]:
        return [
            ("hate_speech", r"(?:racial\s+slur|ethnic\s+cleansing|white\s+supremacy|neo[-\s]?nazi|racial\s+purif|race\s+war|hate\s+crime)"),
            ("harassment", r"(?:threaten\s+(?:to\s+)?(?:kill|harm|hurt|attack|assault)|death\s+threat|direct\s+threat)"),
            ("harmful_medical", r"(?:how\s+to\s+(?:cause|induce|trigger)\s+(?:a\s+)?(?:heart\s+attack|stroke|seizure|allergic\s+reaction|overdose))"),
            ("harmful_psych", r"(?:trigger\s+(?:eating\s+disorder|anorexia|bulimia|self[-\s]harm|suicid))"),
            ("illegal_act", r"(?:how\s+to\s+(?:commit|get\s+away\s+with)\s+(?:murder|theft|robbery|fraud|kidnapping|assault|arson|human\s+trafficking))"),
            ("harmful_drug_info", r"(?:how\s+to\s+(?:synthesize|manufacture|extract|produce|cook|make).{0,30}(?:meth|cocaine|heroin|lsd|mdma|fentanyl|opium|morphine|crack))"),
            ("criminal_skill", r"(?:how\s+to\s+(?:pick\s+(?:a\s+)?lock|bypass\s+(?:a\s+)?(?:alarm|security\s+system|safe)|disable\s+(?:a\s+)?(?:tracking|GPS|monitoring)|shoplift|carding|skimming))"),
        ]

    def _build_medium_patterns(self) -> List[Tuple[str, str]]:
        return [
            ("profanity_excessive", r"(?:\b[fF][uU][cC][kK]\b|\b[sS][hH][iI][tT]\b|\b[aA][sS][sS]\b|\b[bB][iI][tT][cC][hH]\b|\b[dD][aA][mM][nN]\b){3,}"),
            ("nsfw_content", r"(?:nsfw|not\s+safe\s+for\s+work|explicit\s+(?:content|material|language)|adult\s+(?:content|material))"),
            ("personally_identifying", r"(?:my\s+(?:email|phone|address|ssn|credit\s+card)\s+is\s+[\"']?\s*[a-zA-Z0-9@.\\-]+)"),
            ("financial_risk", r"(?:i\s+(?:need|want|require)\s+you\s+to\s+(?:transfer|send|pay|donate|give)\s+(?:me\s+)?(?:money|funds|cash|\$)\s*\d+)"),
        ]

    def scan_request(self, prompt: str, metadata: dict) -> ScannerResult:
        matched_critical = []
        matched_high = []
        matched_medium = []

        prompt_lower = prompt.lower()

        for name, pattern in self.critical_categories:
            if re.search(pattern, prompt_lower, re.IGNORECASE):
                matched_critical.append(name)

        for name, pattern in self.high_categories:
            if re.search(pattern, prompt_lower, re.IGNORECASE):
                matched_high.append(name)

        for name, pattern in self.medium_categories:
            if re.search(pattern, prompt_lower, re.IGNORECASE):
                matched_medium.append(name)

        all_findings = []
        for name in matched_critical:
            all_findings.append({"category": name, "severity": "critical"})
        for name in matched_high:
            all_findings.append({"category": name, "severity": "high"})
        for name in matched_medium:
            all_findings.append({"category": name, "severity": "medium"})

        passed = len(all_findings) == 0

        if matched_critical:
            sev = Severity.CRITICAL
        elif matched_high:
            sev = Severity.HIGH
        elif matched_medium:
            sev = Severity.MEDIUM
        else:
            sev = Severity.INFO

        return ScannerResult(
            scanner_name=self.name,
            passed=passed,
            severity=sev,
            message=f"{'Prompt appears safe' if passed else f'Found {len(all_findings)} safety concern(s)'}",
            details={"findings": all_findings},
            suggestion="Review flagged content. Consider if this prompt is appropriate for the AI provider's usage policy."
            if not passed else None,
        )

    def scan_response(self, prompt: str, response: str, metadata: dict) -> ScannerResult:
        response_lower = response.lower()

        matched = []
        for name, pattern in self.critical_categories + self.high_categories:
            if re.search(pattern, response_lower, re.IGNORECASE):
                matched.append({"category": name, "severity": "critical" if name in [c[0] for c in self.critical_categories] else "high"})

        passed = len(matched) == 0
        if matched:
            sev = Severity.CRITICAL if any(m["severity"] == "critical" for m in matched) else Severity.HIGH
        elif len(response) > 5000:
            sev = Severity.INFO
            matched.append({"note": "unusually long response"})
        else:
            sev = Severity.INFO

        return ScannerResult(
            scanner_name=self.name,
            passed=passed,
            severity=sev,
            message=f"{'Response appears safe' if passed else 'Response contains potentially harmful content'}",
            details={"findings": matched, "response_length": len(response)},
            suggestion="Review AI response for content policy violations." if not passed else None,
        )
