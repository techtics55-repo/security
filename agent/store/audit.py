import hashlib
import json
from datetime import datetime
from typing import Optional


class AuditLogger:
    def __init__(self, store):
        self.store = store
        self._chain = []

    def _hash_entry(self, entry: dict, previous_hash: str) -> str:
        content = json.dumps(entry, sort_keys=True) + previous_hash
        return hashlib.sha256(content.encode()).hexdigest()

    def log(self, action: str, agent_id: str, session_id: str, details: dict,
            verifier: str = "local", policy_violation: bool = False) -> dict:
        previous_hash = self._chain[-1]["hash"] if self._chain else "0" * 64

        entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "action": action,
            "agent_id": agent_id,
            "session_id": session_id,
            "details": details,
            "verifier": verifier,
            "policy_violation": policy_violation,
        }

        entry_hash = self._hash_entry(entry, previous_hash)

        record = {**entry, "hash": entry_hash, "previous_hash": previous_hash}
        self._chain.append(record)

        self.store.log_audit(action, agent_id, session_id, details, verifier)

        return record

    def verify_chain(self) -> bool:
        for i in range(1, len(self._chain)):
            expected_hash = self._hash_entry(
                {k: v for k, v in self._chain[i].items() if k not in ("hash", "previous_hash")},
                self._chain[i - 1]["hash"],
            )
            if self._chain[i]["hash"] != expected_hash:
                return False
        return True

    def get_chain(self, limit: int = 50) -> list:
        return self._chain[-limit:]

    def export_for_compliance(self, start_date: Optional[str] = None) -> dict:
        return {
            "exported_at": datetime.utcnow().isoformat(),
            "chain_integrity": self.verify_chain(),
            "total_entries": len(self._chain),
            "entries": self._chain,
        }
