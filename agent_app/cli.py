import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agent_app.service import AegisService


def main():
    if len(sys.argv) < 2:
        print("Usage: aegis-cli [start|stop|status|enable|disable]")
        print("  start   - Launch Aegis Agent in background")
        print("  stop    - Stop the running agent")
        print("  status  - Show agent status")
        print("  enable  - Enable security monitoring")
        print("  disable - Disable security monitoring")
        return

    svc = AegisService()
    cmd = sys.argv[1]

    if cmd == "start":
        port = svc.start()
        if port:
            print(f"Aegis Agent started. Dashboard: http://127.0.0.1:{port}/app")
        else:
            print("Failed to start Aegis Agent.")
    elif cmd == "stop":
        svc.stop()
        print("Aegis Agent stopped.")
    elif cmd == "status":
        s = svc.status()
        print(f"Running:  {s['running']}")
        print(f"Enabled:  {s['enabled']}")
        print(f"Port:     {s['port']}")
        print(f"DB:       {s['db']}")
        print(f"Log:      {s['log']}")
    elif cmd == "enable":
        svc.enable()
        print("Security monitoring enabled.")
    elif cmd == "disable":
        svc.disable()
        print("Security monitoring disabled.")
    else:
        print(f"Unknown command: {cmd}")
        print("Usage: aegis-cli [start|stop|status|enable|disable]")


if __name__ == "__main__":
    main()
