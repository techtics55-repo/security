import json
import hashlib
import requests
from datetime import datetime
from typing import Optional, Callable


class AegisWrapper:
    def __init__(self, aegis_url: str = "http://127.0.0.1:8080",
                 api_key: Optional[str] = None,
                 on_block: Optional[Callable] = None):
        self.aegis_url = aegis_url.rstrip("/")
        self.api_key = api_key
        self.on_block = on_block or (lambda r: print(f"[AEGIS BLOCKED] {r.get('message', '')}"))

    def wrap_openai(self, client):
        original_create = client.chat.completions.create

        def wrapped_create(*args, **kwargs):
            messages = kwargs.get("messages", [])
            model = kwargs.get("model", "unknown")
            tools = kwargs.get("tools", [])

            prompt_text = json.dumps(messages)
            payload = {
                "model": model,
                "messages": messages,
                "tools": tools,
                "stream": kwargs.get("stream", False),
            }

            scan_result = self._scan_request(prompt_text, payload)
            if scan_result and scan_result.get("aegis", {}).get("result") == "blocked":
                block_msg = f"Request blocked by Aegis: {scan_result['aegis'].get('highest_severity', 'critical')}"
                self.on_block(scan_result["aegis"])
                raise PermissionError(block_msg)

            response = original_create(*args, **kwargs)

            response_text = json.dumps(response.choices[0].message.dict() if hasattr(response, 'choices') else str(response))
            self._scan_response(prompt_text, response_text, {})

            return response

        client.chat.completions.create = wrapped_create
        return client

    def wrap_anthropic(self, client):
        original_create = client.messages.create

        def wrapped_create(*args, **kwargs):
            messages = kwargs.get("messages", [])
            model = kwargs.get("model", "unknown")

            prompt_text = json.dumps(messages)
            payload = {
                "model": model,
                "messages": messages,
                "max_tokens": kwargs.get("max_tokens", 1024),
            }

            scan_result = self._scan_request(prompt_text, payload)
            if scan_result and scan_result.get("aegis", {}).get("result") == "blocked":
                self.on_block(scan_result["aegis"])
                raise PermissionError(f"Request blocked by Aegis")

            response = original_create(*args, **kwargs)

            response_text = str(response.content[0].text) if hasattr(response, 'content') else str(response)
            self._scan_response(prompt_text, response_text, {})

            return response

        client.messages.create = wrapped_create
        return client

    def _scan_request(self, prompt_text: str, payload: dict) -> Optional[dict]:
        try:
            resp = requests.post(
                f"{self.aegis_url}/v1/scan",
                json={"prompt": prompt_text, "payload": payload, "direction": "request"},
                headers={"X-Aegis-Key": self.api_key or ""},
                timeout=5,
            )
            if resp.ok:
                return resp.json()
        except requests.RequestException:
            return None
        return None

    def _scan_response(self, prompt_text: str, response_text: str, metadata: dict):
        try:
            requests.post(
                f"{self.aegis_url}/v1/scan",
                json={
                    "prompt": prompt_text,
                    "response": response_text,
                    "direction": "response",
                    "metadata": metadata,
                },
                headers={"X-Aegis-Key": self.api_key or ""},
                timeout=5,
            )
        except requests.RequestException:
            pass

    def verify_agent_action(self, agent_id: str, action: str, cost: float = 0) -> dict:
        try:
            resp = requests.post(
                f"{self.aegis_url}/v1/verify",
                json={"agent_id": agent_id, "action": action, "cost": cost},
                headers={"X-Aegis-Key": self.api_key or ""},
                timeout=5,
            )
            if resp.ok:
                return resp.json()
        except requests.RequestException:
            pass
        return {"verified": False, "reason": "could not reach Aegis", "action": "block"}
