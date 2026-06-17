import sqlite3
import json
import os
from datetime import datetime
from pathlib import Path
from typing import Optional
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64


class LocalStore:
    def __init__(self, db_path: str, encryption_key: Optional[str] = None):
        self.db_path = db_path
        self.encryption_key = encryption_key
        self._encryptor = None
        if encryption_key:
            self._encryptor = self._setup_encryption(encryption_key)
        self._init_db()

    def _setup_encryption(self, key: str) -> Fernet:
        salt = b"aegis_salt_fixed"
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000)
        derived = base64.urlsafe_b64encode(kdf.derive(key.encode()))
        return Fernet(derived)

    def _encrypt(self, data: str) -> str:
        if self._encryptor:
            return self._encryptor.encrypt(data.encode()).decode()
        return data

    def _decrypt(self, data: str) -> str:
        if self._encryptor:
            return self._encryptor.decrypt(data.encode()).decode()
        return data

    def _init_db(self):
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.executescript("""
            CREATE TABLE IF NOT EXISTS scan_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                session_id TEXT,
                agent_id TEXT,
                scanner_name TEXT NOT NULL,
                passed INTEGER NOT NULL,
                severity TEXT NOT NULL,
                message TEXT,
                details TEXT,
                suggestion TEXT,
                prompt_hash TEXT,
                response_hash TEXT
            );
            CREATE TABLE IF NOT EXISTS agents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                agent_id TEXT UNIQUE NOT NULL,
                registered_at TEXT NOT NULL,
                metadata TEXT,
                policies TEXT,
                is_active INTEGER DEFAULT 1
            );
            CREATE TABLE IF NOT EXISTS audit_trail (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                action TEXT NOT NULL,
                agent_id TEXT,
                session_id TEXT,
                details TEXT,
                verifier TEXT
            );
            CREATE TABLE IF NOT EXISTS policies (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                rules TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON scan_logs(timestamp);
            CREATE INDEX IF NOT EXISTS idx_logs_agent ON scan_logs(agent_id);
            CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_trail(timestamp);
        """)
        conn.commit()
        conn.close()

    def log_scan_result(self, result: dict, session_id: str = "", agent_id: str = ""):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            """INSERT INTO scan_logs 
               (timestamp, session_id, agent_id, scanner_name, passed, severity, message, details, suggestion, prompt_hash, response_hash)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                datetime.utcnow().isoformat(),
                session_id,
                agent_id,
                result.get("scanner", ""),
                1 if result.get("passed") else 0,
                result.get("severity", "info"),
                result.get("message", ""),
                self._encrypt(json.dumps(result.get("details", {}))),
                result.get("suggestion", ""),
                result.get("prompt_hash", ""),
                result.get("response_hash", ""),
            ),
        )
        conn.commit()
        conn.close()

    def log_audit(self, action: str, agent_id: str, session_id: str, details: dict, verifier: str = "local"):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            """INSERT INTO audit_trail (timestamp, action, agent_id, session_id, details, verifier)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (
                datetime.utcnow().isoformat(),
                action,
                agent_id,
                session_id,
                self._encrypt(json.dumps(details)),
                verifier,
            ),
        )
        conn.commit()
        conn.close()

    def get_recent_logs(self, limit: int = 50, severity: Optional[str] = None) -> list:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        if severity:
            cursor.execute(
                "SELECT * FROM scan_logs WHERE severity = ? ORDER BY id DESC LIMIT ?",
                (severity, limit),
            )
        else:
            cursor.execute("SELECT * FROM scan_logs ORDER BY id DESC LIMIT ?", (limit,))
        rows = cursor.fetchall()
        results = []
        for row in rows:
            d = dict(row)
            try:
                d["details"] = json.loads(self._decrypt(d["details"])) if d["details"] else {}
            except Exception:
                d["details"] = {}
            results.append(d)
        conn.close()
        return results

    def get_agents(self) -> list:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM agents WHERE is_active = 1")
        rows = cursor.fetchall()
        conn.close()
        return [dict(r) for r in rows]

    def register_agent(self, agent_id: str, metadata: dict, policies: dict):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            "INSERT OR REPLACE INTO agents (agent_id, registered_at, metadata, policies) VALUES (?, ?, ?, ?)",
            (
                agent_id,
                datetime.utcnow().isoformat(),
                json.dumps(metadata),
                json.dumps(policies),
            ),
        )
        conn.commit()
        conn.close()

    def get_stats(self) -> dict:
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM scan_logs")
        total_scans = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM scan_logs WHERE passed = 0")
        total_issues = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM audit_trail")
        total_audits = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM agents")
        total_agents = cursor.fetchone()[0]
        conn.close()
        return {
            "total_scans": total_scans,
            "total_issues": total_issues,
            "total_audits": total_audits,
            "total_agents": total_agents,
        }
