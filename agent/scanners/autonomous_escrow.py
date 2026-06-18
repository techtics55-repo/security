import hashlib
import json
import time
import uuid
from dataclasses import dataclass, asdict
from enum import Enum
from typing import Optional
from cryptography.fernet import Fernet
from .base import BaseScanner, ScannerResult, Severity


class EscrowStatus(str, Enum):
    PENDING = "pending"
    DEPOSITED = "deposited"
    VERIFIED = "verified"
    RELEASED = "released"
    DISPUTED = "disputed"
    REFUNDED = "refunded"

    def __str__(self):
        return self.value


@dataclass
class EscrowAgreement:
    id: str = ""
    agent_a: str = ""
    agent_b: str = ""
    prompt_hash: str = ""
    expected_response_hash: str = ""
    actual_response_hash: str = ""
    status: EscrowStatus = EscrowStatus.PENDING
    created_at: float = 0.0
    updated_at: float = 0.0
    encrypted_terms: str = ""
    signature_a: str = ""
    signature_b: str = ""
    dispute_reason: str = ""

    def sign(self, party: str, key: str) -> str:
        payload = f"{self.id}{self.agent_a}{self.agent_b}{self.prompt_hash}{self.expected_response_hash}{party}{key}"
        return hashlib.sha256(payload.encode()).hexdigest()

    def verify_fulfillment(self) -> bool:
        return self.actual_response_hash == self.expected_response_hash


class AutonomousEscrow(BaseScanner):
    name = "autonomous_escrow"

    def __init__(self, rules_dir: str):
        super().__init__(rules_dir)
        self.key = Fernet.generate_key()
        self.cipher = Fernet(self.key)
        self.agreements: dict[str, EscrowAgreement] = {}
        self._escrow_lock = str(uuid.uuid4())

    def create_agreement(self, agent_a: str, agent_b: str, prompt: str, expected_response: str, terms: dict = None) -> EscrowAgreement:
        escrow_id = hashlib.sha256(f"{agent_a}{agent_b}{time.time()}{uuid.uuid4()}".encode()).hexdigest()[:16]
        terms_encrypted = self.cipher.encrypt(json.dumps(terms or {}).encode()).decode()
        agreement = EscrowAgreement(
            id=escrow_id,
            agent_a=agent_a,
            agent_b=agent_b,
            prompt_hash=hashlib.sha256(prompt.encode()).hexdigest(),
            expected_response_hash=hashlib.sha256(expected_response.encode()).hexdigest(),
            status=EscrowStatus.PENDING,
            created_at=time.time(),
            updated_at=time.time(),
            encrypted_terms=terms_encrypted,
            signature_a=agreement.sign("agent_a", self.key.decode()[:16]),
        )
        self.agreements[escrow_id] = agreement
        return agreement

    def deposit(self, escrow_id: str) -> Optional[EscrowAgreement]:
        agreement = self.agreements.get(escrow_id)
        if agreement and agreement.status == EscrowStatus.PENDING:
            agreement.status = EscrowStatus.DEPOSITED
            agreement.updated_at = time.time()
            agreement.signature_b = agreement.sign("agent_b", self.key.decode()[:16])
        return agreement

    def verify_response(self, escrow_id: str, actual_response: str) -> ScannerResult:
        agreement = self.agreements.get(escrow_id)
        if not agreement or agreement.status != EscrowStatus.DEPOSITED:
            return ScannerResult(
                scanner_name=self.name, passed=False, severity=Severity.ERROR,
                message="Escrow not found or not in deposited state",
                details={"escrow_id": escrow_id},
            )
        agreement.actual_response_hash = hashlib.sha256(actual_response.encode()).hexdigest()
        fulfilled = agreement.verify_fulfillment()
        if fulfilled:
            agreement.status = EscrowStatus.RELEASED
        else:
            agreement.status = EscrowStatus.DISPUTED
        agreement.updated_at = time.time()
        return ScannerResult(
            scanner_name=self.name,
            passed=fulfilled,
            severity=Severity.INFO if fulfilled else Severity.HIGH,
            message=f"Escrow {escrow_id}: {'RELEASED (fulfilled)' if fulfilled else 'DISPUTED (mismatch)'}",
            details=asdict(agreement),
            suggestion="Response did not match escrow terms. Review and resolve dispute." if not fulfilled else None,
        )

    def escalate_dispute(self, escrow_id: str, reason: str) -> Optional[EscrowAgreement]:
        agreement = self.agreements.get(escrow_id)
        if agreement and agreement.status == EscrowStatus.DISPUTED:
            agreement.dispute_reason = reason
            agreement.updated_at = time.time()
        return agreement

    def refund(self, escrow_id: str) -> Optional[EscrowAgreement]:
        agreement = self.agreements.get(escrow_id)
        if agreement and agreement.status in (EscrowStatus.DISPUTED, EscrowStatus.DEPOSITED):
            agreement.status = EscrowStatus.REFUNDED
            agreement.updated_at = time.time()
        return agreement

    def scan_request(self, prompt: str, metadata: dict) -> ScannerResult:
        agent_a = metadata.get("agent_a", "unknown")
        agent_b = metadata.get("agent_b", "unknown")
        expected_response = metadata.get("expected_response", "")
        terms = metadata.get("terms", {})
        if expected_response:
            agreement = self.create_agreement(agent_a, agent_b, prompt, expected_response, terms)
            self.deposit(agreement.id)
            return ScannerResult(
                scanner_name=self.name,
                passed=True,
                severity=Severity.INFO,
                message=f"Escrow {agreement.id} created and deposited",
                details=asdict(agreement),
            )
        return ScannerResult(
            scanner_name=self.name,
            passed=True,
            severity=Severity.INFO,
            message="No escrow triggered (no expected_response in metadata)",
            details={"note": "Pass expected_response in metadata to create escrow"},
        )

    def scan_response(self, prompt: str, response: str, metadata: dict) -> ScannerResult:
        escrow_id = metadata.get("escrow_id", "")
        if escrow_id and escrow_id in self.agreements:
            return self.verify_response(escrow_id, response)
        return ScannerResult(
            scanner_name=self.name,
            passed=True,
            severity=Severity.INFO,
            message="No escrow to verify (no escrow_id in metadata)",
            details={"note": "Pass escrow_id in metadata to verify"},
        )
