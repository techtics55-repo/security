import os
import json
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class AgentConfig:
    proxy_host: str = "127.0.0.1"
    proxy_port: int = 8080
    log_dir: str = str(Path.home() / ".aegis" / "logs")
    db_path: str = str(Path.home() / ".aegis" / "aegis.db")
    rules_dir: str = str(Path(__file__).parent.parent / "rules")
    encryption_key: Optional[str] = None
    sync_enabled: bool = False
    sync_url: Optional[str] = None
    api_key: Optional[str] = None
    max_log_size_mb: int = 100
    log_retention_days: int = 30
    alert_webhook_url: Optional[str] = None
    blocked_actions: list = field(default_factory=lambda: ["block"])
    allowed_domains: list = field(default_factory=lambda: [
        "api.openai.com",
        "api.anthropic.com",
        "api.gemini.com",
        "api.deepseek.com",
        "api.mistral.ai",
        "api.cohere.ai",
        "api.together.xyz",
    ])
    dangerous_endpoints: list = field(default_factory=lambda: [
        "api.openai.com",
        "api.anthropic.com",
    ])
    scanner_timeout_seconds: int = 5

    @classmethod
    def from_env(cls) -> "AgentConfig":
        config = cls()
        config.proxy_host = os.getenv("AEGIS_HOST", config.proxy_host)
        config.proxy_port = int(os.getenv("AEGIS_PORT", str(config.proxy_port)))
        config.log_dir = os.getenv("AEGIS_LOG_DIR", config.log_dir)
        config.db_path = os.getenv("AEGIS_DB_PATH", config.db_path)
        config.encryption_key = os.getenv("AEGIS_ENCRYPTION_KEY")
        config.sync_enabled = os.getenv("AEGIS_SYNC_ENABLED", "false").lower() == "true"
        config.sync_url = os.getenv("AEGIS_SYNC_URL")
        config.api_key = os.getenv("AEGIS_API_KEY")
        config.alert_webhook_url = os.getenv("AEGIS_ALERT_WEBHOOK")
        return config

    def ensure_dirs(self):
        Path(self.log_dir).mkdir(parents=True, exist_ok=True)
        Path(self.rules_dir).mkdir(parents=True, exist_ok=True)
        db_parent = Path(self.db_path).parent
        db_parent.mkdir(parents=True, exist_ok=True)
