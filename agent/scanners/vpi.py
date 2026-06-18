import hashlib
import json
import time
from dataclasses import dataclass, asdict
from typing import Optional
from .base import BaseScanner, ScannerResult, Severity


@dataclass
class VPIProof:
    version: str = "1.0"
    prompt_hash: str = ""
    response_hash: str = ""
    intent_statement: str = ""
    timestamp: float = 0.0
    chain_hash: str = ""
    nonce: str = ""

    def generate(self, prompt: str, response: str, intent: str = "", prev_hash: str = "") -> "VPIProof":
        self.prompt_hash = hashlib.sha256(prompt.encode()).hexdigest()
        self.response_hash = hashlib.sha256(response.encode()).hexdigest()
        self.intent_statement = intent or hashlib.sha256((prompt + response).encode()).hexdigest()
        self.timestamp = time.time()
        self.nonce = hashlib.sha256(f"{self.timestamp}{prompt}{response}".encode()).hexdigest()[:16]
        combined = f"{self.prompt_hash}{self.response_hash}{self.intent_statement}{self.timestamp}{self.nonce}{prev_hash}"
        self.chain_hash = hashlib.sha256(combined.encode()).hexdigest()
        return self

    def verify(self, prev_hash: str = "") -> bool:
        combined = f"{self.prompt_hash}{self.response_hash}{self.intent_statement}{self.timestamp}{self.nonce}{prev_hash}"
        expected = hashlib.sha256(combined.encode()).hexdigest()
        return self.chain_hash == expected


class VPIScanner(BaseScanner):
    name = "verifiable_proof_of_intent"

    def __init__(self, rules_dir: str):
        super().__init__(rules_dir)
        self.proof_chain: list[VPIProof] = []

    def scan_request(self, prompt: str, metadata: dict) -> ScannerResult:
        intent_statement = metadata.get("intent_statement", "")
        proof = VPIProof().generate(
            prompt=prompt,
            response="",  # will be updated on response
            intent=intent_statement,
            prev_hash=self.proof_chain[-1].chain_hash if self.proof_chain else "",
        )
        return ScannerResult(
            scanner_name=self.name,
            passed=True,
            severity=Severity.INFO,
            message="VPI certificate generated for request intent",
            details={
                "proof": asdict(proof),
                "chain_length": len(self.proof_chain) + 1,
            },
            suggestion=None,
        )

    def scan_response(self, prompt: str, response: str, metadata: dict) -> ScannerResult:
        intent_statement = metadata.get("intent_statement", "")
        prev_hash = self.proof_chain[-1].chain_hash if self.proof_chain else ""
        proof = VPIProof().generate(
            prompt=prompt,
            response=response,
            intent=intent_statement,
            prev_hash=prev_hash,
        )
        self.proof_chain.append(proof)
        tamper_check = proof.verify(prev_hash)
        return ScannerResult(
            scanner_name=self.name,
            passed=tamper_check,
            severity=Severity.INFO if tamper_check else Severity.CRITICAL,
            message="VPI certificate verified" if tamper_check else "VPI certificate TAMPERED",
            details={
                "proof": asdict(proof),
                "chain_length": len(self.proof_chain),
                "tampered": not tamper_check,
            },
            suggestion="The proof chain hash mismatch indicates evidence tampering." if not tamper_check else None,
        )
