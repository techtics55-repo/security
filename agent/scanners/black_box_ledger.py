import hashlib
import json
import time
import uuid
from dataclasses import dataclass, asdict
from typing import Optional
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature
from .base import BaseScanner, ScannerResult, Severity


TRISM_CATEGORIES = ["transparency", "risk_assessment", "security_controls", "model_governance", "compliance"]


@dataclass
class ReasoningStep:
    step_index: int = 0
    thought: str = ""
    input_context: str = ""
    output_decision: str = ""
    confidence: float = 0.0
    timestamp: float = 0.0
    step_hash: str = ""

    def seal(self) -> "ReasoningStep":
        raw = f"{self.step_index}{self.thought}{self.input_context}{self.output_decision}{self.confidence}{self.timestamp}"
        self.step_hash = hashlib.sha3_256(raw.encode()).hexdigest()
        return self


@dataclass
class LedgerEntry:
    index: int = 0
    session_id: str = ""
    human_id: str = ""
    agent_id: str = ""
    prompt: str = ""
    prompt_hash: str = ""
    response: str = ""
    response_hash: str = ""
    reasoning_steps: list = None
    reasoning_root_hash: str = ""
    ai_trism_metadata: dict = None
    timestamp: float = 0.0
    encrypted_payload: str = ""
    witness_hash: str = ""
    previous_hash: str = ""
    hash: str = ""
    nonce: int = 0

    def __post_init__(self):
        if self.reasoning_steps is None:
            self.reasoning_steps = []
        if self.ai_trism_metadata is None:
            self.ai_trism_metadata = {}

    def compute_hash(self) -> str:
        raw = f"{self.index}{self.session_id}{self.human_id}{self.agent_id}{self.prompt_hash}{self.response_hash}{self.reasoning_root_hash}{json.dumps(self.ai_trism_metadata, sort_keys=True)}{self.timestamp}{self.encrypted_payload}{self.witness_hash}{self.previous_hash}{self.nonce}"
        return hashlib.sha3_256(raw.encode()).hexdigest()

    def mine(self, difficulty: int = 3) -> "LedgerEntry":
        target = "0" * difficulty
        while not self.hash.startswith(target):
            self.nonce += 1
            self.hash = self.compute_hash()
        return self

    def verify(self, difficulty: int = 3) -> bool:
        target = "0" * difficulty
        return self.hash.startswith(target) and self.hash == self.compute_hash()


class DecisionTrail:
    def __init__(self, session_id: str, human_id: str, agent_id: str):
        self.session_id = session_id
        self.human_id = human_id
        self.agent_id = agent_id
        self.prompt = ""
        self.reasoning_steps: list[ReasoningStep] = []
        self.response = ""
        self.created_at = time.time()

    def record_prompt(self, prompt: str) -> "DecisionTrail":
        self.prompt = prompt
        return self

    def add_reasoning_step(self, thought: str, input_context: str = "",
                           output_decision: str = "", confidence: float = 0.0) -> "DecisionTrail":
        step = ReasoningStep(
            step_index=len(self.reasoning_steps),
            thought=thought,
            input_context=input_context,
            output_decision=output_decision,
            confidence=confidence,
            timestamp=time.time(),
        ).seal()
        self.reasoning_steps.append(step)
        return self

    def record_response(self, response: str) -> "DecisionTrail":
        self.response = response
        return self

    def compute_reasoning_root(self) -> str:
        if not self.reasoning_steps:
            return "0" * 64
        current = self.reasoning_steps[0].step_hash if self.reasoning_steps else "0"
        for step in self.reasoning_steps[1:]:
            current = hashlib.sha3_256(f"{current}{step.step_hash}".encode()).hexdigest()
        return current

    def reconstruct(self) -> dict:
        return {
            "session_id": self.session_id,
            "human_id": self.human_id,
            "agent_id": self.agent_id,
            "prompt": self.prompt,
            "reasoning_chain": [
                {
                    "step": s.step_index,
                    "thought": s.thought,
                    "input_context": s.input_context,
                    "output_decision": s.output_decision,
                    "confidence": s.confidence,
                    "timestamp": s.timestamp,
                    "hash": s.step_hash,
                }
                for s in self.reasoning_steps
            ],
            "response": self.response,
            "reasoning_root_hash": self.compute_reasoning_root(),
            "created_at": self.created_at,
        }


class BlackBoxLedger(BaseScanner):
    name = "black_box_ledger"

    def __init__(self, rules_dir: str):
        super().__init__(rules_dir)
        self.key = Fernet.generate_key()
        self.cipher = Fernet(self.key)
        self.chain: list[LedgerEntry] = []
        self.active_trails: dict[str, DecisionTrail] = {}
        self.difficulty = 3
        self.oracle_private_key = ec.generate_private_key(ec.SECP256R1())
        genesis_payload = self.cipher.encrypt(json.dumps({
            "event": "Oracle Node Black Box Ledger genesis",
            "version": "2.0",
            "ai_trism": {k: "initialized" for k in TRISM_CATEGORIES},
        }).encode()).decode()
        genesis = LedgerEntry(
            index=0, session_id="genesis", human_id="oracle", agent_id="system",
            prompt="", prompt_hash="0" * 64, response="", response_hash="0" * 64,
            reasoning_root_hash="0" * 64,
            ai_trism_metadata={k: "genesis" for k in TRISM_CATEGORIES},
            timestamp=time.time(),
            encrypted_payload=genesis_payload,
            witness_hash=hashlib.sha3_256(b"Oracle Node Genesis Block").hexdigest(),
            previous_hash="0" * 64, nonce=0,
        ).mine(self.difficulty)
        self.chain.append(genesis)

    def start_trail(self, session_id: str, human_id: str, agent_id: str, prompt: str) -> DecisionTrail:
        trail = DecisionTrail(session_id, human_id, agent_id)
        trail.record_prompt(prompt)
        self.active_trails[session_id] = trail
        return trail

    def add_thought(self, session_id: str, thought: str, input_context: str = "",
                    output_decision: str = "", confidence: float = 0.0) -> Optional[DecisionTrail]:
        trail = self.active_trails.get(session_id)
        if trail:
            trail.add_reasoning_step(thought, input_context, output_decision, confidence)
        return trail

    def complete_trail(self, session_id: str, response: str) -> Optional[DecisionTrail]:
        trail = self.active_trails.get(session_id)
        if trail:
            trail.record_response(response)
        return trail

    def seal_entry(self, session_id: str, prompt: str, response: str,
                   human_id: str = "anonymous", agent_id: str = "unknown",
                   ai_trism: dict = None) -> LedgerEntry:
        payload = json.dumps({
            "session_id": session_id,
            "event": "decision_complete",
            "ai_trism_snapshot": ai_trism or {k: "recorded" for k in TRISM_CATEGORIES},
        }, sort_keys=True).encode()
        encrypted = self.cipher.encrypt(payload).decode()
        prev = self.chain[-1]
        prompt_hash = hashlib.sha3_256(prompt.encode()).hexdigest()
        response_hash = hashlib.sha3_256(response.encode()).hexdigest()
        trail = self.active_trails.get(session_id)
        reasoning_root = trail.compute_reasoning_root() if trail else "0" * 64
        witness_raw = f"{session_id}{prompt_hash}{response_hash}{time.time()}{uuid.uuid4()}"
        witness_hash = hashlib.sha3_256(witness_raw.encode()).hexdigest()
        entry = LedgerEntry(
            index=len(self.chain),
            session_id=session_id,
            human_id=human_id,
            agent_id=agent_id,
            prompt=prompt,
            prompt_hash=prompt_hash,
            response=response,
            response_hash=response_hash,
            reasoning_steps=trail.reasoning_steps if trail else [],
            reasoning_root_hash=reasoning_root,
            ai_trism_metadata=ai_trism or {},
            timestamp=time.time(),
            encrypted_payload=encrypted,
            witness_hash=witness_hash,
            previous_hash=prev.hash,
        ).mine(self.difficulty)
        self.chain.append(entry)
        return entry

    def get_trail_reconstruction(self, session_id: str) -> Optional[dict]:
        for entry in reversed(self.chain):
            if entry.session_id == session_id:
                return {
                    "entry_index": entry.index,
                    "session_id": entry.session_id,
                    "human_id": entry.human_id,
                    "agent_id": entry.agent_id,
                    "prompt": entry.prompt,
                    "response": entry.response,
                    "reasoning_steps": [
                        {"step": s.step_index, "thought": s.thought,
                         "input": s.input_context, "decision": s.output_decision,
                         "confidence": s.confidence, "hash": s.step_hash}
                        for s in entry.reasoning_steps
                    ],
                    "reasoning_root_hash": entry.reasoning_root_hash,
                    "ai_trism_metadata": entry.ai_trism_metadata,
                    "witness_hash": entry.witness_hash,
                    "entry_hash": entry.hash,
                    "previous_hash": entry.previous_hash,
                    "timestamp": entry.timestamp,
                    "chain_integrity": self.verify_chain(),
                }
        return None

    def verify_chain(self) -> bool:
        for i in range(len(self.chain)):
            if not self.chain[i].verify(self.difficulty):
                return False
            if i > 0 and self.chain[i].previous_hash != self.chain[i - 1].hash:
                return False
        return True

    def get_chain_of_custody_report(self) -> dict:
        return {
            "node": "Oracle Node Black Box Ledger",
            "version": "2.0",
            "total_entries": len(self.chain),
            "chain_valid": self.verify_chain(),
            "genesis_hash": self.chain[0].hash if self.chain else "",
            "latest_hash": self.chain[-1].hash if self.chain else "",
            "ai_trism_coverage": {
                cat: all(entry.ai_trism_metadata.get(cat) is not None for entry in self.chain)
                for cat in TRISM_CATEGORIES
            },
            "timestamp": time.time(),
        }

    def scan_request(self, prompt: str, metadata: dict) -> ScannerResult:
        session_id = metadata.get("session_id", str(uuid.uuid4()))
        human_id = metadata.get("human_id", "anonymous")
        agent_id = metadata.get("agent_id", "unknown")
        self.start_trail(session_id, human_id, agent_id, prompt)
        return ScannerResult(
            scanner_name=self.name,
            passed=True,
            severity=Severity.INFO,
            message=f"Decision trail started: session {session_id[:12]}...",
            details={"session_id": session_id, "chain_length": len(self.chain)},
        )

    def scan_response(self, prompt: str, response: str, metadata: dict) -> ScannerResult:
        session_id = metadata.get("session_id", "")
        human_id = metadata.get("human_id", "anonymous")
        agent_id = metadata.get("agent_id", "unknown")
        thoughts = metadata.get("reasoning_steps", [])
        ai_trism = metadata.get("ai_trism_metadata", {})
        if session_id and session_id in self.active_trails:
            for t in thoughts:
                self.add_thought(session_id, t.get("thought", ""), t.get("context", ""),
                                 t.get("decision", ""), t.get("confidence", 0.0))
            self.complete_trail(session_id, response)
            entry = self.seal_entry(session_id, prompt, response, human_id, agent_id, ai_trism)
        else:
            entry = self.seal_entry(f"direct-{uuid.uuid4().hex[:8]}", prompt, response,
                                    human_id, agent_id, ai_trism)
        chain_valid = self.verify_chain()
        return ScannerResult(
            scanner_name=self.name,
            passed=chain_valid,
            severity=Severity.INFO if chain_valid else Severity.CRITICAL,
            message=f"Ledger entry #{entry.index} sealed with {len(entry.reasoning_steps)} reasoning step(s). Chain: {'OK' if chain_valid else 'BROKEN'}",
            details={
                "entry_index": entry.index,
                "session_id": entry.session_id,
                "reasoning_steps_count": len(entry.reasoning_steps),
                "reasoning_root_hash": entry.reasoning_root_hash,
                "witness_hash": entry.witness_hash,
                "chain_valid": chain_valid,
                "chain_length": len(self.chain),
                "entry_hash": entry.hash,
            },
            suggestion="Black Box Ledger chain integrity check failed. Tampering detected!" if not chain_valid else None,
        )
