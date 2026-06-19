import os
import sys
import json
import threading
import uvicorn
from pathlib import Path

AGENT_DIR = Path.home() / ".aegis"
CONFIG_FILE = AGENT_DIR / "config.json"
DB_FILE = AGENT_DIR / "aegis_agent.db"
LOG_FILE = AGENT_DIR / "agent.log"

AGENT_DIR.mkdir(parents=True, exist_ok=True)


class AegisService:
    def __init__(self):
        self._server_thread = None
        self._enabled = True
        self._server = None
        self._config = self._load_config()

    def _load_config(self):
        defaults = {"enabled": True, "port": 8000, "auto_start": True}
        if CONFIG_FILE.exists():
            try:
                data = json.loads(CONFIG_FILE.read_text())
                defaults.update(data)
            except Exception:
                pass
        return defaults

    def _save_config(self):
        CONFIG_FILE.write_text(json.dumps(self._config, indent=2))

    @property
    def enabled(self):
        return self._config.get("enabled", True)

    @enabled.setter
    def enabled(self, value):
        self._config["enabled"] = value
        self._save_config()

    @property
    def port(self):
        return self._config.get("port", 8000)

    def start(self):
        from backend.main import app
        cfg = uvicorn.Config(
            app,
            host="127.0.0.1",
            port=self.port,
            log_level="info",
            log_config=None,
        )
        self._server = uvicorn.Server(cfg)
        self._server_thread = threading.Thread(target=self._server.run, daemon=True)
        self._server_thread.start()

    def stop(self):
        if self._server:
            self._server.should_exit = True
            self._server = None

    def is_running(self):
        return self._server is not None and self._server_thread is not None and self._server_thread.is_alive()

    def enable(self):
        self.enabled = True
        return True

    def disable(self):
        self.enabled = False
        return True

    def status(self):
        return {
            "running": self.is_running(),
            "enabled": self.enabled,
            "port": self.port,
            "db": str(DB_FILE),
        }

    def restart(self):
        self.stop()
        import time
        time.sleep(1)
        self.start()
