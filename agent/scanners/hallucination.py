import re
from typing import Optional
from .base import BaseScanner, ScannerResult, Severity


class HallucinationDetector(BaseScanner):
    name = "hallucination_detection"

    def __init__(self, rules_dir: str):
        super().__init__(rules_dir)

    def _detect_self_contradiction(self, response: str) -> list:
        contradictions = []

        yes_no_patterns = [
            (r"(?:^|\b)yes(?:\b|[.,!?])", r"(?:^|\b)no(?:\b|[.,!?])"),
        ]

        for pos_pat, neg_pat in yes_no_patterns:
            positives = list(re.finditer(pos_pat, response, re.IGNORECASE))
            negatives = list(re.finditer(neg_pat, response, re.IGNORECASE))
            for pos in positives:
                for neg in negatives:
                    distance = abs(pos.start() - neg.start())
                    if 20 < distance < 2000:
                        contradictions.append({
                            "type": "yes_no_contradiction",
                            "distance_chars": distance,
                            "context": response[max(0, pos.start()-50):max(neg.end()+50, pos.end()+50)][:100],
                        })
                        break

        numerical_patterns = re.findall(r"(\d+[,.]?\d*)\s*(?:million|billion|trillion|percent|%)", response, re.IGNORECASE)
        if len(numerical_patterns) >= 2:
            unique_vals = set(numerical_patterns)
            if len(unique_vals) < len(numerical_patterns):
                contradictions.append({
                    "type": "repeated_contradictory_numbers",
                    "values": numerical_patterns,
                })

        return contradictions

    def _detect_vague_hedging(self, response: str) -> list:
        hedging_patterns = [
            (r"i\s+(?:think|believe|guess|suppose|assume|would\s+say|might\s+be\s+wrong)", "speculative_language"),
            (r"(?:to\s+the\s+best\s+of\s+my\s+knowledge|as\s+far\s+as\s+i\s+know)", "knowledge_limitation"),
            (r"i['']m\s+(?:not\s+(?:entirely|completely|100%)\s+sure|not\s+(?:entirely|fully)\s+confident|uncertain|unsure)", "uncertainty"),
            (r"(?:i\s+could\s+be\s+wrong|this\s+may\s+not\s+be\s+accurate|this\s+might\s+be\s+incorrect)", "error_admission"),
            (r"i\s+don['']t\s+(?:have\s+(?:access\s+to|information\s+about|the\s+most\s+recent)|know\s+the\s+(?:exact|precise)|have\s+real[-\s]?time)", "knowledge_gap"),
        ]

        findings = []
        for pattern, name in hedging_patterns:
            if re.search(pattern, response, re.IGNORECASE):
                findings.append({"pattern": name, "severity": "low"})

        return findings

    def _detect_confidence_inconsistency(self, response: str) -> list:
        high_conf = re.search(r"(?:certainly|definitely|undoubtedly|absolutely|without\s+doubt|i['']m\s+(?:certain|sure|confident))\s*(?:that|this|it)", response, re.IGNORECASE)
        low_conf = re.search(r"(?:i['']m\s+not\s+sure|i\s+think|maybe|perhaps|possibly|could\s+be\s+wrong)", response, re.IGNORECASE)

        if high_conf and low_conf:
            return [{
                "type": "confidence_inconsistency",
                "high_conf_example": high_conf.group()[:80],
                "low_conf_example": low_conf.group()[:80],
            }]
        return []

    def _detect_missing_disclaimer(self, response: str) -> bool:
        high_risk_topics = [
            r"(?:medical|health|diagnos|treatment|surgery|prescription|medication)",
            r"(?:legal|attorney|lawyer|sue|lawsuit|legal\s+advice|legal\s+opinion)",
            r"(?:financial|investment|stock|trading|tax\s+advice|retirement\s+planning)",
            r"(?:psychiatric|psycholog|therapist|therapy|counseling)",

        ]

        has_disclaimer = bool(re.search(
            r"(?:not\s+(?:a\s+)?(?:medical|legal|financial|professional)\s+advice|"
            r"consult\s+(?:a\s+)?(?:professional|doctor|lawyer|attorney|advisor)|"
            r"seek\s+professional|i\s*m\s+(?:not\s+)?(?:a\s+)?(?:AI|assistant|chatbot))",
            response, re.IGNORECASE
        ))

        for topic in high_risk_topics:
            if re.search(topic, response, re.IGNORECASE):
                return not has_disclaimer

        return False

    def _detect_impossible_claims(self, response: str) -> list:
        claims = []

        patterns = [
            (r"(?:I\s+am|I['']m)\s+.*(?:human|person|real\s+person|actual\s+human)", "ai_claiming_humanity"),
            (r"(?:I\s+can|I['']m\s+able\s+to)\s+(?:see|watch|look\s+at)\s+(?:images?\s+in\s+real[-\s]?time|live\s+(?:video|feed|camera))", "impossible_visual_claim"),
            (r"(?:I\s+remember|I\s+recall)\s+(?:you|our\s+previous|our\s+earlier|our\s+past)\s+(?:conversation|chat|discussion|session).{0,30}(?:from|last|earlier)", "false_memory_claim"),
        ]

        for pattern, name in patterns:
            if re.search(pattern, response, re.IGNORECASE):
                claims.append({"type": name, "severity": "high"})

        return claims

    def _detect_knowledge_cutoff_violation(self, prompt: str, response: str) -> list:
        current_year = "2026"
        recent_events = re.findall(r"(?:in\s+)?(20(?:2[2-6]|2[2-6]))", prompt, re.IGNORECASE)
        if not recent_events:
            return []

        response_claims_knowledge = re.search(
            r"(?:I\s+(?:know|have|can\s+tell\s+you)\s+(?:about|the|what)|"
            r"according\s+to\s+(?:the\s+)?(?:latest|recent|current|202[456]))",
            response, re.IGNORECASE
        )
        if response_claims_knowledge:
            return [{
                "type": "potential_cutoff_violation",
                "prompt_references": recent_events,
                "detail": "AI may claim knowledge of recent events beyond training cutoff",
            }]
        return []

    def scan_request(self, prompt: str, metadata: dict) -> ScannerResult:
        fact_check_patterns = re.findall(
            r"(?:is\s+it\s+true|fact[\s-]?check|verify|correct\s+or\s+not|accurate|legitimate)",
            prompt, re.IGNORECASE
        )
        return ScannerResult(
            scanner_name=self.name,
            passed=True,
            severity=Severity.INFO,
            message="Fact-checking request detected" if fact_check_patterns else "No fact-checking requested",
            details={"fact_check_requested": len(fact_check_patterns) > 0},
        )

    def scan_response(self, prompt: str, response: str, metadata: dict) -> ScannerResult:
        findings = []
        severity = Severity.INFO

        contradictions = self._detect_self_contradiction(response)
        if contradictions:
            findings.extend({"type": c["type"], "detail": str(c.get("context", "")[:80])} for c in contradictions)
            severity = Severity.MEDIUM

        impossible_claims = self._detect_impossible_claims(response)
        if impossible_claims:
            findings.extend(impossible_claims)
            severity = Severity.HIGH

        sev_n = {"info":0,"low":1,"medium":2,"high":3,"critical":4}.get(severity.value,0)
        cutoff_violations = self._detect_knowledge_cutoff_violation(prompt, response)
        if cutoff_violations:
            findings.extend(cutoff_violations)
            if sev_n < 2:
                severity = Severity.MEDIUM

        hedging = self._detect_vague_hedging(response)
        if hedging:
            findings.extend(h for h in hedging)

        confidence_issues = self._detect_confidence_inconsistency(response)
        if confidence_issues:
            findings.extend(confidence_issues)
            if sev_n < 2:
                severity = Severity.MEDIUM

        missing_disclaimer = self._detect_missing_disclaimer(response)
        if missing_disclaimer:
            findings.append({"type": "missing_professional_disclaimer", "severity": "medium"})
            if sev_n < 2:
                severity = Severity.MEDIUM

        passed = len(findings) == 0

        return ScannerResult(
            scanner_name=self.name,
            passed=passed,
            severity=severity,
            message=f"{'No hallucination indicators found' if passed else f'Found {len(findings)} potential issue(s)'}",
            details={"findings": findings, "response_length": len(response)},
            suggestion="Verify factual claims in AI response, especially for critical applications."
            if not passed else None,
        )
