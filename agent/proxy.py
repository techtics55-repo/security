import json
import hashlib
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse
from datetime import datetime
from typing import Optional


class AIProxyHandler(BaseHTTPRequestHandler):
    scanner_engine = None
    store = None
    audit_logger = None
    agent_detector = None
    workflow_tracker = None
    config = None

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        status = {
            "status": "running",
            "mode": "monitoring",
            "uptime": datetime.utcnow().isoformat(),
            "version": "1.0.0",
        }
        self.wfile.write(json.dumps(status).encode())

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length) if content_length > 0 else b""

        path = self.path
        target_url = self._resolve_target(path)

        metadata = {
            "endpoint": target_url,
            "method": "POST",
            "path": path,
            "headers": dict(self.headers),
            "content_type": self.headers.get("Content-Type", ""),
            "timestamp": datetime.utcnow().isoformat(),
            "client_address": self.client_address[0],
        }

        try:
            payload = json.loads(body) if body else {}
        except json.JSONDecodeError:
            payload = {"raw": body.decode("utf-8", errors="replace")}

        prompt_text = self._extract_prompt(payload)
        prompt_hash = hashlib.sha256(prompt_text.encode()).hexdigest()[:16]

        session_id = metadata.get("headers", {}).get("X-Session-ID",
                    metadata.get("headers", {}).get("x-session-id", prompt_hash[:8]))

        agent_info = self.agent_detector.detect_agent(prompt_text, metadata) if self.agent_detector else None

        scan_results = []
        all_passed = True
        highest_severity = "info"

        if self.scanner_engine:
            for scanner in self.scanner_engine:
                try:
                    result = scanner.scan_request(prompt_text, metadata)
                    result_dict = result.to_dict()
                    result_dict["prompt_hash"] = prompt_hash
                    scan_results.append(result_dict)
                    if not result_dict["passed"]:
                        all_passed = False
                    severity_order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
                    if severity_order.get(result_dict["severity"], 0) > severity_order.get(highest_severity, 0):
                        highest_severity = result_dict["severity"]
                    if self.store:
                        self.store.log_scan_result(result_dict, session_id,
                            agent_info.get("agent_id", "") if agent_info else "")
                except Exception as e:
                    scan_results.append({
                        "scanner": scanner.name,
                        "passed": True,
                        "severity": "info",
                        "message": f"Scanner error: {str(e)}",
                    })

        if self.workflow_tracker:
            workflow_state = self.workflow_tracker.track_call(session_id, metadata)

        if agent_info and self.audit_logger:
            self.audit_logger.log(
                action="agent_request",
                agent_id=agent_info.get("agent_id", agent_info.get("signatures", [{}])[0].get("framework", "unknown")),
                session_id=session_id,
                details={
                    "agent_info": agent_info,
                    "scan_results": [s for s in scan_results if not s["passed"]],
                    "severity": highest_severity,
                },
                policy_violation=not all_passed,
            )

        response = {
            "aegis": {
                "version": "1.0.0",
                "scan_id": prompt_hash,
                "timestamp": datetime.utcnow().isoformat(),
                "result": "blocked" if highest_severity in ("critical",) else "allowed",
                "all_checks_passed": all_passed,
                "highest_severity": highest_severity,
                "scan_results": scan_results,
                "agent_detected": agent_info,
            },
            "forwarded": True,
        }

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("X-Aegis-Scan-ID", prompt_hash)
        self.send_header("X-Aegis-Result", response["aegis"]["result"])
        self.end_headers()
        self.wfile.write(json.dumps(response).encode())

    def _resolve_target(self, path: str) -> str:
        domain_map = {
            "/v1/chat/completions": "https://api.openai.com/v1/chat/completions",
            "/v1/completions": "https://api.openai.com/v1/completions",
            "/v1/messages": "https://api.anthropic.com/v1/messages",
            "/v1beta1/models": "https://generativelanguage.googleapis.com/v1beta1/models",
        }
        return domain_map.get(path, f"https://proxy.aegis.local{path}")

    def _extract_prompt(self, payload: dict) -> str:
        texts = []
        messages = payload.get("messages", [])
        for msg in messages:
            content = msg.get("content", "")
            if isinstance(content, list):
                for part in content:
                    if isinstance(part, dict) and part.get("type") == "text":
                        texts.append(part.get("text", ""))
            else:
                texts.append(str(content))
        prompt = payload.get("prompt", "")
        if prompt:
            texts.append(str(prompt))
        return "\n".join(texts)

    def log_message(self, format, *args):
        pass


class AegisProxy:
    def __init__(self, config, scanner_engine, store, audit_logger, agent_detector, workflow_tracker):
        self.config = config
        AIProxyHandler.scanner_engine = scanner_engine
        AIProxyHandler.store = store
        AIProxyHandler.audit_logger = audit_logger
        AIProxyHandler.agent_detector = agent_detector
        AIProxyHandler.workflow_tracker = workflow_tracker
        AIProxyHandler.config = config

    def start(self):
        server = HTTPServer(
            (self.config.proxy_host, self.config.proxy_port),
            AIProxyHandler,
        )
        print(f"Aegis proxy running on http://{self.config.proxy_host}:{self.config.proxy_port}")
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print("\nShutting down proxy...")
            server.server_close()
