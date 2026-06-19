import hashlib
import json
import time
import uuid
from dataclasses import dataclass, asdict
from typing import Optional
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature
from cryptography.exceptions import InvalidSignature
from .base import BaseScanner, ScannerResult, Severity


@dataclass
class IdentityCertificate:
    human_id: str = ""
    human_name: str = ""
    public_key_pem: str = ""
    issued_at: float = 0.0
    issuer: str = "Oracle Node"
    cert_hash: str = ""

    def generate(self, human_id: str, human_name: str, public_key_pem: str) -> "IdentityCertificate":
        self.human_id = human_id
        self.human_name = human_name
        self.public_key_pem = public_key_pem
        self.issued_at = time.time()
        raw = f"{self.human_id}{self.human_name}{self.public_key_pem}{self.issued_at}{self.issuer}"
        self.cert_hash = hashlib.sha3_256(raw.encode()).hexdigest()
        return self


@dataclass
class InstructionMandate:
    mandate_id: str = ""
    human_id: str = ""
    instructions_hash: str = ""
    exact_instructions: str = ""
    boundary_rules: list = None
    timestamp: float = 0.0
    mandate_hash: str = ""

    def __post_init__(self):
        if self.boundary_rules is None:
            self.boundary_rules = []

    def generate(self, human_id: str, instructions: str, boundary_rules: list = None) -> "InstructionMandate":
        self.mandate_id = hashlib.sha3_256(f"{human_id}{instructions}{time.time()}{uuid.uuid4()}".encode()).hexdigest()[:24]
        self.human_id = human_id
        self.exact_instructions = instructions
        self.instructions_hash = hashlib.sha3_256(instructions.encode()).hexdigest()
        self.boundary_rules = boundary_rules or []
        self.timestamp = time.time()
        raw = f"{self.mandate_id}{self.human_id}{self.instructions_hash}{json.dumps(self.boundary_rules, sort_keys=True)}{self.timestamp}"
        self.mandate_hash = hashlib.sha3_256(raw.encode()).hexdigest()
        return self

    def check_response_compliance(self, response: str) -> tuple[bool, list]:
        violations = []
        response_lower = response.lower()
        for rule in self.boundary_rules:
            keyword = rule.get("keyword", "").lower()
            if keyword and keyword in response_lower:
                if rule.get("type") == "forbid":
                    violations.append(f"Response contains forbidden keyword: '{keyword}'")
                elif rule.get("type") == "require":
                    violations.append(f"Response missing required keyword: '{keyword}'")
        complied = len(violations) == 0
        return complied, violations


@dataclass
class VPIProof:
    version: str = "2.0"
    proof_id: str = ""
    human_id: str = ""
    mandate_hash: str = ""
    prompt_hash: str = ""
    response_hash: str = ""
    response_compliant: bool = True
    compliance_violations: list = None
    timestamp: float = 0.0
    nonce: str = ""
    oracle_signature: str = ""
    chain_hash: str = ""
    prev_chain_hash: str = ""

    def __post_init__(self):
        if self.compliance_violations is None:
            self.compliance_violations = []

    def generate(self, human_id: str, mandate_hash: str, prompt: str, response: str,
                 prev_chain_hash: str = "", private_key=None) -> "VPIProof":
        self.proof_id = hashlib.sha3_256(f"{human_id}{mandate_hash}{prompt}{response}{time.time()}".encode()).hexdigest()[:24]
        self.human_id = human_id
        self.mandate_hash = mandate_hash
        self.prompt_hash = hashlib.sha3_256(prompt.encode()).hexdigest()
        self.response_hash = hashlib.sha3_256(response.encode()).hexdigest()
        self.timestamp = time.time()
        self.nonce = hashlib.sha3_256(f"{self.timestamp}{prompt}{response}{uuid.uuid4()}".encode()).hexdigest()[:16]
        self.prev_chain_hash = prev_chain_hash
        combined = f"{self.version}{self.proof_id}{self.human_id}{self.mandate_hash}{self.prompt_hash}{self.response_hash}{self.response_compliant}{self.timestamp}{self.nonce}{self.prev_chain_hash}"
        self.chain_hash = hashlib.sha3_256(combined.encode()).hexdigest()
        if private_key:
            signature = private_key.sign(
                self.chain_hash.encode(),
                ec.ECDSA(hashes.SHA3_256())
            )
            r, s = decode_dss_signature(signature)
            self.oracle_signature = f"{r:x}:{s:x}"
        return self

    def verify_oracle_signature(self, public_key_pem: str) -> bool:
        if not self.oracle_signature or not public_key_pem:
            return False
        try:
            public_key = serialization.load_pem_public_key(public_key_pem.encode())
            r_hex, s_hex = self.oracle_signature.split(":")
            signature = encode_dss_signature(int(r_hex, 16), int(s_hex, 16))
            public_key.verify(signature, self.chain_hash.encode(), ec.ECDSA(hashes.SHA3_256()))
            return True
        except (InvalidSignature, Exception):
            return False

    def verify_link(self, prev_chain_hash: str = "") -> bool:
        combined = f"{self.version}{self.proof_id}{self.human_id}{self.mandate_hash}{self.prompt_hash}{self.response_hash}{self.response_compliant}{self.timestamp}{self.nonce}{prev_chain_hash}"
        expected = hashlib.sha3_256(combined.encode()).hexdigest()
        return self.chain_hash == expected


class OracleNodeIdentity:
    def __init__(self):
        self.private_key = ec.generate_private_key(ec.SECP256R1())
        self.public_key = self.private_key.public_key()
        self.node_id = hashlib.sha3_256(str(time.time()).encode()).hexdigest()[:16]
        self.identities: dict[str, IdentityCertificate] = {}

    def register_human(self, human_id: str, human_name: str) -> tuple[str, IdentityCertificate]:
        human_key = ec.generate_private_key(ec.SECP256R1())
        pub_pem = human_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
        cert = IdentityCertificate().generate(human_id, human_name, pub_pem)
        self.identities[human_id] = cert
        return human_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode(), cert

    def get_certificate(self, human_id: str) -> Optional[IdentityCertificate]:
        return self.identities.get(human_id)


class VPIScanner(BaseScanner):
    name = "verifiable_proof_of_intent"

    def __init__(self, rules_dir: str):
        super().__init__(rules_dir)
        self.oracle = OracleNodeIdentity()
        self.proof_chain: list[VPIProof] = []
        self.mandates: dict[str, InstructionMandate] = {}

    def issue_mandate(self, human_id: str, instructions: str, boundary_rules: list = None) -> InstructionMandate:
        mandate = InstructionMandate().generate(human_id, instructions, boundary_rules)
        self.mandates[mandate.mandate_hash] = mandate
        return mandate

    def create_proof(self, human_id: str, mandate_hash: str, prompt: str,
                     response: str, mandate: InstructionMandate = None) -> VPIProof:
        compliant = True
        violations = []
        if mandate:
            compliant, violations = mandate.check_response_compliance(response)
        prev_hash = self.proof_chain[-1].chain_hash if self.proof_chain else ""
        proof = VPIProof().generate(
            human_id=human_id,
            mandate_hash=mandate_hash,
            prompt=prompt,
            response=response,
            prev_chain_hash=prev_hash,
            private_key=self.oracle.private_key,
        )
        proof.response_compliant = compliant
        proof.compliance_violations = violations
        self.proof_chain.append(proof)
        return proof

    def scan_request(self, prompt: str, metadata: dict) -> ScannerResult:
        human_id = metadata.get("human_id", "anonymous")
        instructions = metadata.get("instructions", "")
        boundary_rules = metadata.get("boundary_rules", [])
        mandate = None
        if instructions:
            mandate = self.issue_mandate(human_id, instructions, boundary_rules)
        return ScannerResult(
            scanner_name=self.name,
            passed=True,
            severity=Severity.INFO,
            message=f"VPI mandate issued: {mandate.mandate_id if mandate else 'none (no instructions)'}",
            details=asdict(mandate) if mandate else {"human_id": human_id, "note": "No instructions provided"},
        )

    def scan_response(self, prompt: str, response: str, metadata: dict) -> ScannerResult:
        human_id = metadata.get("human_id", "anonymous")
        mandate_hash = metadata.get("mandate_hash", "")
        mandate = self.mandates.get(mandate_hash)
        proof = self.create_proof(human_id, mandate_hash, prompt, response, mandate)
        tamper_check = proof.verify_link(self.proof_chain[-2].chain_hash if len(self.proof_chain) > 1 else "")
        sig_ok = proof.verify_oracle_signature(self.oracle.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode())
        overall_pass = tamper_check and sig_ok and proof.response_compliant
        return ScannerResult(
            scanner_name=self.name,
            passed=overall_pass,
            severity=Severity.CRITICAL if not tamper_check else Severity.HIGH if not proof.response_compliant else Severity.INFO,
            message="VPI proof verified with mandate compliance" if overall_pass
            else "VPI proof FAILED: " + ("tampered" if not tamper_check else "signature invalid" if not sig_ok else "mandate violation"),
            details={
                "proof": asdict(proof),
                "chain_length": len(self.proof_chain),
                "oracle_signed": sig_ok,
                "tampered": not tamper_check,
                "compliant": proof.response_compliant,
                "violations": proof.compliance_violations,
            },
            suggestion="Investigate mandate boundary violation in AI response." if not proof.response_compliant else
                       "Chain integrity breach detected. Evidence may have been tampered." if not tamper_check else None,
        )
