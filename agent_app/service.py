import sys
import os
import json
import socket
import threading
import logging
import atexit
from pathlib import Path

AGENT_DIR = Path.home() / ".aegis"
CONFIG_FILE = AGENT_DIR / "config.json"
LOG_FILE = AGENT_DIR / "agent.log"
DB_FILE = AGENT_DIR / "aegis_agent.db"

AGENT_DIR.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(str(LOG_FILE)),
        logging.StreamHandler(sys.stdout),
    ],
)
logger = logging.getLogger("aegis")


def find_free_port(start=8000, max_attempts=100):
    for port in range(start, start + max_attempts):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            if s.connect_ex(("127.0.0.1", port)) != 0:
                return port
    return start


class AegisService:
    def __init__(self):
        self._server_thread = None
        self._server = None
        self._config = self._load_config()
        self._port = None
        self._app = None

    def _load_config(self):
        defaults = {"enabled": True, "auto_start": True, "minimize_to_tray": True}
        if CONFIG_FILE.exists():
            try:
                data = json.loads(CONFIG_FILE.read_text())
                defaults.update(data)
            except Exception as e:
                logger.warning(f"Failed to load config: {e}")
        return defaults

    def _save_config(self):
        try:
            CONFIG_FILE.write_text(json.dumps(self._config, indent=2))
        except Exception as e:
            logger.warning(f"Failed to save config: {e}")

    @property
    def enabled(self):
        return self._config.get("enabled", True)

    @enabled.setter
    def enabled(self, value):
        self._config["enabled"] = value
        self._save_config()

    @property
    def port(self):
        if self._port is None:
            self._port = self._config.get("port", 0)
        return self._port

    def start(self):
        try:
            from backend.main import app
            self._app = app

            import uvicorn

            port = find_free_port()
            self._port = port
            self._config["port"] = port
            self._save_config()

            cfg = uvicorn.Config(
                app,
                host="127.0.0.1",
                port=port,
                log_level="warning",
                log_config=None,
            )
            self._server = uvicorn.Server(cfg)
            self._server_thread = threading.Thread(target=self._server.run, daemon=True)
            self._server_thread.start()

            logger.info(f"Backend started on http://127.0.0.1:{port}")
            return port
        except Exception as e:
            logger.error(f"Failed to start backend: {e}")
            import traceback
            logger.error(traceback.format_exc())
            return None

    def stop(self):
        if self._server:
            self._server.should_exit = True
            self._server = None
            logger.info("Backend stopped")

    def is_running(self):
        if self._server and self._server_thread:
            return self._server_thread.is_alive()
        return False

    def enable(self):
        self.enabled = True
        logger.info("Security enabled")
        return True

    def disable(self):
        self.enabled = False
        logger.info("Security disabled")
        return True

    def status(self):
        return {
            "running": self.is_running(),
            "enabled": self.enabled,
            "port": self.port,
            "db": str(DB_FILE),
            "log": str(LOG_FILE),
            "config": str(CONFIG_FILE),
        }
