import json
import re
from pathlib import Path
from urllib.parse import urlparse
from .base import BaseScanner, ScannerResult, Severity


class DataFlowTracker(BaseScanner):
    name = "data_flow"

    def __init__(self, rules_dir: str):
        super().__init__(rules_dir)
        self.known_providers = {
            "api.openai.com": "OpenAI",
            "api.anthropic.com": "Anthropic",
            "api.gemini.com": "Google Gemini",
            "generativelanguage.googleapis.com": "Google Gemini",
            "api.deepseek.com": "DeepSeek",
            "api.mistral.ai": "Mistral AI",
            "api.cohere.ai": "Cohere",
            "api.together.xyz": "Together AI",
            "api.replicate.com": "Replicate",
            "inference.ai.azure.com": "Azure AI",
            "bedrock-runtime.us-east-1.amazonaws.com": "AWS Bedrock",
        }
        self.suspicious_domains = self._load_suspicious_domains()

    def _load_suspicious_domains(self) -> list:
        path = Path(self.rules_dir) / "data_endpoints.json"
        if not path.exists():
            return []
        with open(path) as f:
            data = json.load(f)
            return data.get("suspicious_domains", [])

    def _extract_urls(self, text: str) -> list:
        url_pattern = re.compile(r"https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+(?::\d+)?(?:/[-\w$.+!*'(),;:@&=?/~#%]*)?")
        return url_pattern.findall(text)

    def _inspect_headers(self, metadata: dict) -> dict:
        headers = metadata.get("headers", {})
        concerns = []
        ssl_verified = headers.get("ssl_verified", True)

        if not ssl_verified:
            concerns.append("SSL verification disabled")

        user_agent = headers.get("User-Agent", headers.get("user-agent", ""))
        if not user_agent:
            concerns.append("No User-Agent header (potentially automated)")

        return {"ssl_verified": ssl_verified, "concerns": concerns}

    def _assess_endpoint(self, url: str) -> dict:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        if ":" in domain:
            domain = domain.split(":")[0]

        result = {
            "domain": domain,
            "known_provider": self.known_providers.get(domain, None),
            "encrypted": parsed.scheme == "https",
            "suspicious": False,
            "reasons": [],
        }

        if not result["encrypted"]:
            result["reasons"].append("Unencrypted HTTP connection")
            result["suspicious"] = True

        if domain in self.suspicious_domains:
            result["reasons"].append(f"Domain known for suspicious activity")
            result["suspicious"] = True

        if result["known_provider"] is None and domain not in ("127.0.0.1", "localhost"):
            result["reasons"].append("Unknown AI provider endpoint")
            result["suspicious"] = True

        return result

    def scan_request(self, prompt: str, metadata: dict) -> ScannerResult:
        findings = []
        urls_in_prompt = self._extract_urls(prompt)
        endpoint = metadata.get("endpoint", "")
        header_info = self._inspect_headers(metadata)

        if endpoint:
            endpoint_assessment = self._assess_endpoint(endpoint)
            findings.append(endpoint_assessment)

        for url in urls_in_prompt:
            assessment = self._assess_endpoint(url)
            assessment["location"] = "prompt"
            findings.append(assessment)

        suspicious = [f for f in findings if f.get("suspicious")]
        passed = len(suspicious) == 0

        return ScannerResult(
            scanner_name=self.name,
            passed=passed,
            severity=Severity.HIGH if suspicious else Severity.INFO,
            message=f"{'No data flow concerns' if passed else f'Found {len(suspicious)} suspicious endpoint(s)'}",
            details={
                "findings": findings,
                "header_concerns": header_info["concerns"],
                "data_disclosed": {
                    "prompt_length": len(prompt),
                    "urls_in_prompt": len(urls_in_prompt),
                },
            },
            suggestion="Review endpoints where data is being sent. Ensure only trusted AI providers receive your data."
            if not passed else None,
        )

    def scan_response(self, prompt: str, response: str, metadata: dict) -> ScannerResult:
        urls_in_response = self._extract_urls(response)
        if not urls_in_response:
            return ScannerResult(
                scanner_name=self.name,
                passed=True,
                severity=Severity.INFO,
                message="No URLs in response",
            )

        findings = []
        for url in urls_in_response:
            assessment = self._assess_endpoint(url)
            assessment["location"] = "response"
            findings.append(assessment)

        suspicious = [f for f in findings if f.get("suspicious")]
        return ScannerResult(
            scanner_name=self.name,
            passed=len(suspicious) == 0,
            severity=Severity.MEDIUM if suspicious else Severity.INFO,
            message=f"Response contains {'suspicious' if suspicious else 'external'} URLs",
            details={"urls_found": findings},
            suggestion="Review URLs in AI response to ensure safe navigation." if suspicious else None,
        )
