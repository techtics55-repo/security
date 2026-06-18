import hashlib
import json
import time
from dataclasses import dataclass, asdict
from typing import Optional
from cryptography.fernet import Fernet
from .base import BaseScanner, ScannerResult, Severity


@dataclass
class LedgerEntry:
    index: int = 0
    timestamp: float = 0.0
    scanner: str = ""
    event_type: str = ""
    data_hash: str = ""
    encrypted_payload: str = ""
    previous_hash: str = ""
    hash: str = ""
    nonce: int = 0

    def compute_hash(self) -> str:
        raw = f"{self.index}{self.timestamp}{self.scanner}{self.event_type}{self.data_hash}{self.encrypted_payload}{self.previous_hash}{self.nonce}"
        return hashlib.sha256(raw.encode()).hexdigest()

    def mine(self, difficulty: int = 2) -> "LedgerEntry":
        target = "0" * difficulty
        while not self.hash.startswith(target):
            self.nonce += 1
            self.hash = self.compute_hash()
        return self

    def verify(self, difficulty: int = 2) -> bool:
        target = "0" * difficulty
        return self.hash.startswith(target) and self.hash == self.compute_hash()


class BlackBoxLedger(BaseScanner):
    name = "black_box_ledger"

    def __init__(self, rules_dir: str):
        super().__init__(rules_dir)
        self.key = Fernet.generate_key()
        self.cipher = Fernet(self.key)
        self.chain: list[LedgerEntry] = []
        self.difficulty = 2
        genesis = LedgerEntry(
            index=0, timestamp=time.time(), scanner="genesis",
            event_type="init", data_hash="0" * 64,
            encrypted_payload=self.cipher.encrypt(b"genesis").decode(),
            previous_hash="0" * 64,
        ).mine(self.difficulty)
        self.chain.append(genesis)

    def _add_entry(self, scanner: str, event_type: str, data: dict) -> LedgerEntry:
        payload = json.dumps(data, sort_keys=True).encode()
        encrypted = self.cipher.encrypt(payload).decode()
        prev = self.chain[-1]
        data_hash = hashlib.sha256(payload).hexdigest()
        entry = LedgerEntry(
            index=len(self.chain),
            timestamp=time.time(),
            scanner=scanner,
            event_type=event_type,
            data_hash=data_hash,
            encrypted_payload=encrypted,
            previous_hash=prev.hash,
        ).mine(self.difficulty)
        self.chain.append(entry)
        return entry

    def scan_request(self, prompt: str, metadata: dict) -> ScannerResult:
        entry = self._add_entry(self.name, "request", {
            "prompt_length": len(prompt),
            "source": metadata.get("source", "unknown"),
        })
        return ScannerResult(
            scanner_name=self.name,
            passed=True,
            severity=Severity.INFO,
            message=f"Ledger entry #{entry.index} recorded (request)",
            details={"entry": asdict(entry), "chain_length": len(self.chain)},
        )

    def scan_response(self, prompt: str, response: str, metadata: dict) -> ScannerResult:
        entry = self._add_entry(self.name, "response", {
            "prompt_length": len(prompt),
            "response_length": len(response),
            "source": metadata.get("source", "unknown"),
        })
        chain_valid = all(
            self.chain[i].verify(self.difficulty) and
            (i == 0 or self.chain[i].previous_hash == self.chain[i - 1].hash)
            for i in range(len(self.chain))
        )
        return ScannerResult(
            scanner_name=self.name,
            passed=chain_valid,
            severity=Severity.INFO if chain_valid else Severity.CRITICAL,
            message=f"Ledger entry #{entry.index} recorded (response). Chain integrity: {'OK' if chain_valid else 'BROKEN'}",
            details={
                "entry": asdict(entry),
                "chain_length": len(self.chain),
                "chain_valid": chain_valid,
            },
            suggestion="Ledger chain integrity check failed! Tampering may have occurred." if not chain_valid else None,
        )

    def verify_chain(self) -> bool:
        for i in range(len(self.chain)):
            if not self.chain[i].verify(self.difficulty):
                return False
            if i > 0 and self.chain[i].previous_hash != self.chain[i - 1].hash:
                return False
        return True
