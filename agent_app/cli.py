#!/usr/bin/env python3
"""
Aegis CLI Agent — Lightweight security layer for AI interactions.
Run: python aegis-cli.pyz [start|stop|status|enable|disable]
"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from agent_app.service import AegisService


def main():
    if len(sys.argv) < 2:
        print("Usage: aegis-cli [start|stop|status|enable|disable]")
        return

    svc = AegisService()
    cmd = sys.argv[1]

    if cmd == "start":
        svc.start()
        print("Aegis Agent started. Dashboard at http://127.0.0.1:8000/app")
    elif cmd == "stop":
        svc.stop()
        print("Aegis Agent stopped.")
    elif cmd == "status":
        s = svc.status()
        print(f"Running: {s['running']}")
        print(f"Enabled: {s['enabled']}")
        print(f"Port: {s['port']}")
    elif cmd == "enable":
        svc.enable()
        print("Security enabled.")
    elif cmd == "disable":
        svc.disable()
        print("Security disabled.")
    else:
        print(f"Unknown command: {cmd}")
        print("Usage: aegis-cli [start|stop|status|enable|disable]")


if __name__ == "__main__":
    main()
