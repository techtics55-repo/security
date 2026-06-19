import hashlib
import json
import time
import uuid
from dataclasses import dataclass, asdict
from enum import Enum
from decimal import Decimal, ROUND_HALF_UP
from typing import Optional
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature
from .base import BaseScanner, ScannerResult, Severity


class EscrowStatus(str, Enum):
    DRAFT = "draft"
    FUNDING = "funding"
    FUNDED = "funded"
    LOCKED = "locked"
    IN_PROGRESS = "in_progress"
    VERIFYING = "verifying"
    RELEASED = "released"
    DISPUTED = "disputed"
    ARBITRATION = "arbitration"
    REFUNDED = "refunded"
    CANCELLED = "cancelled"

    def __str__(self):
        return self.value


@dataclass
class EscrowTerms:
    amount: float = 0.0
    currency: str = "USD"
    oracle_commission_rate: float = 0.025
    commission_amount: float = 0.0
    net_settlement: float = 0.0
    deadline_seconds: int = 86400
    verification_threshold: float = 0.95
    arbitration_fee: float = 0.0
    dispute_resolution: str = "oracle_mediation"

    def calculate_commission(self) -> "EscrowTerms":
        self.commission_amount = float(Decimal(str(self.amount)) * Decimal(str(self.oracle_commission_rate)))
        self.commission_amount = float(Decimal(str(self.commission_amount)).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP))
        self.net_settlement = float(Decimal(str(self.amount)) - Decimal(str(self.commission_amount)))
        self.net_settlement = float(Decimal(str(self.net_settlement)).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP))
        return self


@dataclass
class EscrowAgreement:
    id: str = ""
    title: str = ""
    human_id: str = ""
    agent_id: str = ""
    oracle_node_id: str = ""
    terms: dict = None
    status: EscrowStatus = EscrowStatus.DRAFT
    balance_held: float = 0.0
    created_at: float = 0.0
    updated_at: float = 0.0
    expires_at: float = 0.0
    encrypted_terms: str = ""
    human_signature: str = ""
    agent_signature: str = ""
    oracle_signature: str = ""
    oracle_commission_earned: float = 0.0
    human_outcome: float = 0.0
    dispute_reason: str = ""
    arbitration_notes: str = ""
    task_completion_proof: str = ""

    def sign_human(self, private_key_pem: str) -> str:
        payload = f"{self.id}{self.human_id}{self.balance_held}{self.terms}{self.created_at}"
        return hashlib.sha3_256(payload.encode()).hexdigest()

    def sign_agent(self, agent_key: str) -> str:
        payload = f"{self.id}{self.agent_id}{self.balance_held}{self.terms}{self.created_at}"
        return hashlib.sha3_256(payload.encode()).hexdigest()

    def sign_oracle(self, private_key) -> str:
        payload = f"{self.id}{self.oracle_node_id}{self.balance_held}{json.dumps(self.terms, sort_keys=True)}{self.created_at}{self.human_signature}{self.agent_signature}"
        signature = private_key.sign(
            payload.encode(),
            ec.ECDSA(hashes.SHA3_256())
        )
        r, s = decode_dss_signature(signature)
        return f"{r:x}:{s:x}"


class AutonomousEscrow(BaseScanner):
    name = "autonomous_escrow"

    def __init__(self, rules_dir: str):
        super().__init__(rules_dir)
        self.key = Fernet.generate_key()
        self.cipher = Fernet(self.key)
        self.agreements: dict[str, EscrowAgreement] = {}
        self.oracle_private_key = ec.generate_private_key(ec.SECP256R1())
        self.oracle_node_id = hashlib.sha3_256(f"oracle-escrow-{time.time()}".encode()).hexdigest()[:16]
        self.total_commission_earned: float = 0.0
        self.total_value_secured: float = 0.0

    def create_escrow(self, human_id: str, agent_id: str, title: str,
                      amount: float, currency: str = "USD",
                      commission_rate: float = 0.025,
                      deadline_seconds: int = 86400) -> EscrowAgreement:
        escrow_id = hashlib.sha3_256(f"{human_id}{agent_id}{title}{amount}{time.time()}{uuid.uuid4()}".encode()).hexdigest()[:24]
        escrow_terms = EscrowTerms(
            amount=amount,
            currency=currency,
            oracle_commission_rate=commission_rate,
            deadline_seconds=deadline_seconds,
        ).calculate_commission()
        terms_encrypted = self.cipher.encrypt(json.dumps(asdict(escrow_terms)).encode()).decode()
        now = time.time()
        agreement = EscrowAgreement(
            id=escrow_id,
            title=title,
            human_id=human_id,
            agent_id=agent_id,
            oracle_node_id=self.oracle_node_id,
            terms=asdict(escrow_terms),
            status=EscrowStatus.DRAFT,
            balance_held=0.0,
            created_at=now,
            updated_at=now,
            expires_at=now + deadline_seconds,
            encrypted_terms=terms_encrypted,
            oracle_commission_earned=escrow_terms.commission_amount,
            human_outcome=escrow_terms.net_settlement,
        )
        self.agreements[escrow_id] = agreement
        return agreement

    def fund_escrow(self, escrow_id: str, amount: float) -> Optional[EscrowAgreement]:
        agreement = self.agreements.get(escrow_id)
        if not agreement or agreement.status != EscrowStatus.DRAFT:
            return None
        if amount < agreement.terms.get("amount", 0):
            return None
        agreement.balance_held = amount
        agreement.status = EscrowStatus.FUNDED
        agreement.updated_at = time.time()
        agreement.human_signature = agreement.sign_human("")
        self.total_value_secured += amount
        return agreement

    def lock_escrow(self, escrow_id: str, agent_key: str) -> Optional[EscrowAgreement]:
        agreement = self.agreements.get(escrow_id)
        if not agreement or agreement.status != EscrowStatus.FUNDED:
            return None
        agreement.status = EscrowStatus.LOCKED
        agreement.updated_at = time.time()
        agreement.agent_signature = agreement.sign_agent(agent_key)
        agreement.oracle_signature = agreement.sign_oracle(self.oracle_private_key)
        return agreement

    def begin_work(self, escrow_id: str) -> Optional[EscrowAgreement]:
        agreement = self.agreements.get(escrow_id)
        if not agreement or agreement.status != EscrowStatus.LOCKED:
            return None
        agreement.status = EscrowStatus.IN_PROGRESS
        agreement.updated_at = time.time()
        return agreement

    def submit_completion(self, escrow_id: str, completion_proof: str) -> Optional[EscrowAgreement]:
        agreement = self.agreements.get(escrow_id)
        if not agreement or agreement.status != EscrowStatus.IN_PROGRESS:
            return None
        agreement.task_completion_proof = completion_proof
        agreement.status = EscrowStatus.VERIFYING
        agreement.updated_at = time.time()
        return agreement

    def verify_and_release(self, escrow_id: str, verified: bool = True) -> Optional[EscrowAgreement]:
        agreement = self.agreements.get(escrow_id)
        if not agreement or agreement.status != EscrowStatus.VERIFYING:
            return None
        if verified:
            agreement.status = EscrowStatus.RELEASED
            self.total_commission_earned += agreement.oracle_commission_earned
        else:
            agreement.status = EscrowStatus.DISPUTED
        agreement.updated_at = time.time()
        return agreement

    def dispute(self, escrow_id: str, reason: str) -> Optional[EscrowAgreement]:
        agreement = self.agreements.get(escrow_id)
        if not agreement or agreement.status not in (EscrowStatus.VERIFYING, EscrowStatus.IN_PROGRESS, EscrowStatus.LOCKED):
            return None
        agreement.status = EscrowStatus.DISPUTED
        agreement.dispute_reason = reason
        agreement.updated_at = time.time()
        return agreement

    def arbitrate(self, escrow_id: str, decision: str, notes: str = "") -> Optional[EscrowAgreement]:
        agreement = self.agreements.get(escrow_id)
        if not agreement or agreement.status != EscrowStatus.DISPUTED:
            return None
        agreement.status = EscrowStatus.ARBITRATION
        agreement.arbitration_notes = notes
        agreement.updated_at = time.time()
        if decision == "release":
            agreement.status = EscrowStatus.RELEASED
            self.total_commission_earned += agreement.oracle_commission_earned * Decimal("0.5")
        elif decision == "refund":
            agreement.status = EscrowStatus.REFUNDED
        return agreement

    def refund(self, escrow_id: str) -> Optional[EscrowAgreement]:
        agreement = self.agreements.get(escrow_id)
        if not agreement or agreement.status in (EscrowStatus.RELEASED, EscrowStatus.REFUNDED):
            return None
        agreement.status = EscrowStatus.REFUNDED
        agreement.updated_at = time.time()
        return agreement

    def cancel(self, escrow_id: str) -> Optional[EscrowAgreement]:
        agreement = self.agreements.get(escrow_id)
        if not agreement or agreement.status not in (EscrowStatus.DRAFT, EscrowStatus.FUNDING, EscrowStatus.FUNDED):
            return None
        agreement.status = EscrowStatus.CANCELLED
        agreement.updated_at = time.time()
        return agreement

    def get_trust_gap_report(self) -> dict:
        active = [a for a in self.agreements.values() if a.status in (
            EscrowStatus.FUNDED, EscrowStatus.LOCKED, EscrowStatus.IN_PROGRESS, EscrowStatus.VERIFYING)]
        return {
            "oracle_node_id": self.oracle_node_id,
            "total_escrows_created": len(self.agreements),
            "active_escrows": len(active),
            "total_value_secured": self.total_value_secured,
            "total_commission_earned": float(self.total_commission_earned),
            "trust_gap_resolved": len([a for a in self.agreements.values() if a.status == EscrowStatus.RELEASED]),
            "dispute_rate": len([a for a in self.agreements.values() if a.status in (EscrowStatus.DISPUTED, EscrowStatus.ARBITRATION)]) / max(len(self.agreements), 1),
            "status": "operational",
        }

    def scan_request(self, prompt: str, metadata: dict) -> ScannerResult:
        human_id = metadata.get("human_id", "anonymous")
        agent_id = metadata.get("agent_id", "unknown")
        title = metadata.get("escrow_title", "AI Task Escrow")
        amount = metadata.get("escrow_amount", 0)
        if amount > 0:
            agreement = self.create_escrow(human_id, agent_id, title, amount)
            return ScannerResult(
                scanner_name=self.name,
                passed=True,
                severity=Severity.INFO,
                message=f"Escrow {agreement.id} created for ${amount}. Oracle commission: ${agreement.oracle_commission_earned}",
                details={
                    "escrow_id": agreement.id,
                    "amount": amount,
                    "commission": agreement.oracle_commission_earned,
                    "net_to_agent": agreement.human_outcome,
                    "status": agreement.status.value,
                    "trust_gap": f"${amount} secured by Oracle Node {self.oracle_node_id[:8]}",
                },
            )
        return ScannerResult(
            scanner_name=self.name,
            passed=True,
            severity=Severity.INFO,
            message="No escrow triggered. Pass escrow_amount > 0 in metadata to create escrow.",
            details={"note": "Escrow creation requires escrow_amount in metadata"},
        )

    def scan_response(self, prompt: str, response: str, metadata: dict) -> ScannerResult:
        escrow_id = metadata.get("escrow_id", "")
        action = metadata.get("escrow_action", "")
        if escrow_id and escrow_id in self.agreements:
            agreement = self.agreements[escrow_id]
            if action == "fund":
                amount = metadata.get("amount", agreement.terms.get("amount", 0))
                self.fund_escrow(escrow_id, amount)
                return ScannerResult(
                    scanner_name=self.name, passed=True, severity=Severity.INFO,
                    message=f"Escrow {escrow_id[:12]} funded: ${amount}",
                    details={"escrow_id": escrow_id, "balance": amount, "status": EscrowStatus.FUNDED.value},
                )
            elif action == "verify":
                verified = metadata.get("verified", True)
                self.verify_and_release(escrow_id, verified)
                return ScannerResult(
                    scanner_name=self.name, passed=verified, severity=Severity.INFO if verified else Severity.HIGH,
                    message=f"Escrow {escrow_id[:12]}: {'RELEASED' if verified else 'DISPUTED'}",
                    details={"escrow_id": escrow_id, "status": agreement.status.value,
                             "commission_earned": agreement.oracle_commission_earned},
                )
            elif action == "dispute":
                reason = metadata.get("reason", "Unspecified")
                self.dispute(escrow_id, reason)
                return ScannerResult(
                    scanner_name=self.name, passed=False, severity=Severity.HIGH,
                    message=f"Escrow {escrow_id[:12]} disputed: {reason}",
                    details={"escrow_id": escrow_id, "reason": reason, "status": EscrowStatus.DISPUTED.value},
                )
        return ScannerResult(
            scanner_name=self.name, passed=True, severity=Severity.INFO,
            message="No escrow action performed",
            details={"note": "Pass escrow_id and escrow_action in metadata"},
        )
