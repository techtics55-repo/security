import sys
import json
import threading
import time
from pathlib import Path
from datetime import datetime

sys.path.insert(0, str(Path(__file__).parent.parent))

from agent.config import AgentConfig
from agent.scanners import (InjectionScanner, PIIScanner, CodeChecker,
                              DataFlowTracker, BehaviorAnalyzer,
                              ResponseSafetyScanner, HallucinationDetector)
from agent.detectors import AgentDetector, WorkflowTracker
from agent.store import LocalStore, AuditLogger
from agent.policies import PolicyEngine
from agent.proxy import AegisProxy


class AegisCLI:
    def __init__(self):
        self.config = AgentConfig.from_env()
        self.config.ensure_dirs()
        self.store = None
        self.audit_logger = None
        self.scanner_engine = []
        self.agent_detector = None
        self.workflow_tracker = None
        self.policy_engine = None
        self.proxy = None
        self.running = False

    def _init_components(self):
        self.store = LocalStore(self.config.db_path, self.config.encryption_key)
        self.audit_logger = AuditLogger(self.store)

        rules_dir = self.config.rules_dir
        self.scanner_engine = [
            InjectionScanner(rules_dir),
            PIIScanner(rules_dir),
            CodeChecker(rules_dir),
            DataFlowTracker(rules_dir),
            BehaviorAnalyzer(rules_dir),
            ResponseSafetyScanner(rules_dir),
            HallucinationDetector(rules_dir),
        ]

        self.agent_detector = AgentDetector(rules_dir)
        self.workflow_tracker = WorkflowTracker()

        self.policy_engine = PolicyEngine()
        self.policy_engine.create_default_policies()

    def cmd_start(self, port: int = 8080, host: str = "127.0.0.1"):
        self.config.proxy_port = port
        self.config.proxy_host = host
        self._init_components()

        self.proxy = AegisProxy(
            self.config, self.scanner_engine, self.store,
            self.audit_logger, self.agent_detector, self.workflow_tracker,
        )

        self.running = True
        print(f"\n{'='*60}")
        print(f"  AEGIS — AI Security & Governance Layer")
        print(f"  Version 1.0.0")
        print(f"  Proxy: http://{host}:{port}")
        print(f"  Logs: {self.config.log_dir}")
        print(f"{'='*60}\n")

        print("  Configure your AI apps to use this proxy:")
        print(f"    export OPENAI_BASE_URL=http://{host}:{port}/v1")
        print(f"    export ANTHROPIC_BASE_URL=http://{host}:{port}\n")

        print("  Press Ctrl+C to stop\n")

        threading.Thread(target=self._health_report_loop, daemon=True).start()
        self.proxy.start()

    def cmd_monitor(self, tail: int = 10, refresh: int = 3):
        self._init_components()
        print(f"\n  Aegis Monitor — real-time view (refresh every {refresh}s)")
        print(f"  {'='*60}\n")
        try:
            while True:
                self._display_monitor()
                time.sleep(refresh)
        except KeyboardInterrupt:
            print("\n  Monitor stopped.")

    def _display_monitor(self):
        stats = self.store.get_stats()
        recent = self.store.get_recent_logs(limit=10)
        issues = [r for r in recent if not r.get("passed", True)]

        print(f"  [{datetime.utcnow().strftime('%H:%M:%S')}] "
              f"Scans: {stats['total_scans']} | "
              f"Issues: {stats['total_issues']} | "
              f"Agents: {stats['total_agents']} | "
              f"Audits: {stats['total_audits']}")

        if issues:
            for issue in issues[:5]:
                sev = issue.get("severity", "?").upper()
                msg = issue.get("message", "?")[:60]
                scanner = issue.get("scanner_name", "?")
                print(f"    [{sev}] [{scanner}] {msg}")
        print()

    def cmd_logs(self, tail: int = 20, severity: str = None):
        self._init_components()
        logs = self.store.get_recent_logs(limit=tail, severity=severity)
        print(f"\n  Recent Audit Logs (last {tail}):\n")
        for log in logs:
            ts = log.get("timestamp", "?")[:19]
            sev = log.get("severity", "?").upper().ljust(8)
            scanner = log.get("scanner_name", "?").ljust(20)
            status = "✅" if log.get("passed") else "❌"
            msg = log.get("message", "")[:60]
            print(f"  {status} [{ts}] {sev} {scanner} {msg}")
        print()

    def cmd_agents(self, register: str = None, action: str = None, agent_id: str = None):
        self._init_components()
        if register and agent_id:
            result = self.agent_detector.register_agent(agent_id, {"allowed_actions": [action] if action else []})
            self.store.register_agent(agent_id, {}, {"allowed_actions": [action] if action else []})
            print(f"\n  ✅ Agent '{agent_id}' registered.")
            print(f"  Allowed action: {action or 'none'}")
            return

        if agent_id and action:
            result = self.agent_detector.verify_agent_action(agent_id, action)
            status = "✅ ALLOWED" if result.get("verified") else "❌ BLOCKED"
            print(f"\n  {status}")
            print(f"  Agent: {agent_id} | Action: {action}")
            print(f"  Reason: {result.get('reason', '')}")
            return

        agents = self.store.get_agents()
        print(f"\n  Registered Agents ({len(agents)}):\n")
        for a in agents:
            print(f"  • {a.get('agent_id', '?')} — registered {a.get('registered_at', '?')[:19]}")
        if not agents:
            print("  (no agents registered)")
        print()

    def cmd_policies(self, list_only: bool = True, add: str = None):
        self._init_components()
        if list_only:
            print(f"\n  Active Policies ({len(self.policy_engine.policies)}):\n")
            for p in self.policy_engine.policies:
                print(f"  • {p.name} (priority: {p.priority})")
                print(f"    {p.description}")
                for r in p.rules:
                    print(f"    - If {r.field} {r.operator} {r.value} → {r.action}")
                print()
            if not self.policy_engine.policies:
                print("  (no policies loaded)\n")

    def cmd_status(self):
        self._init_components()
        stats = self.store.get_stats()
        print(f"\n  Aegis Status")
        print(f"  {'='*40}")
        print(f"  Proxy: {'Running' if self.running else 'Stopped'}")
        print(f"  Database: {self.config.db_path}")
        print(f"  Rules: {self.config.rules_dir}")
        print(f"  Encryption: {'Enabled' if self.config.encryption_key else 'Disabled (not recommended)'}")
        print(f"  Sync: {'Enabled' if self.config.sync_enabled else 'Disabled'}")
        print(f"\n  Statistics:")
        print(f"    Total scans:     {stats['total_scans']}")
        print(f"    Issues found:    {stats['total_issues']}")
        print(f"    Audit entries:   {stats['total_audits']}")
        print(f"    Registered agents: {stats['total_agents']}")
        print()

    def _health_report_loop(self):
        while self.running:
            time.sleep(300)
            if self.store:
                stats = self.store.get_stats()
                self.audit_logger.log(
                    action="health_report",
                    agent_id="system",
                    session_id="system",
                    details=stats,
                    verifier="system",
                )


def main():
    import argparse
    cli = AegisCLI()

    parser = argparse.ArgumentParser(
        description="Aegis — AI Security & Governance Layer",
        prog="aegis",
    )
    sub = parser.add_subparsers(dest="command", help="Command")

    p_start = sub.add_parser("start", help="Start the monitoring proxy")
    p_start.add_argument("--port", type=int, default=8080, help="Proxy port (default: 8080)")
    p_start.add_argument("--host", type=str, default="127.0.0.1", help="Proxy host (default: 127.0.0.1)")

    p_monitor = sub.add_parser("monitor", help="View real-time monitoring dashboard")
    p_monitor.add_argument("--tail", type=int, default=10, help="Recent entries to show")
    p_monitor.add_argument("--refresh", type=int, default=3, help="Refresh interval in seconds")

    p_logs = sub.add_parser("logs", help="View audit logs")
    p_logs.add_argument("--tail", type=int, default=20, help="Number of log entries")
    p_logs.add_argument("--severity", choices=["info", "low", "medium", "high", "critical"])

    p_agents = sub.add_parser("agents", help="Manage registered AI agents")
    p_agents.add_argument("--register", type=str, help="Register a new agent")
    p_agents.add_argument("--agent-id", type=str, help="Agent ID")
    p_agents.add_argument("--action", type=str, help="Action to verify or allow")

    p_policies = sub.add_parser("policies", help="View active policies")
    p_policies.set_defaults(list_only=True)

    p_status = sub.add_parser("status", help="Show system status")

    args = parser.parse_args()

    if args.command == "start":
        cli.cmd_start(port=args.port, host=args.host)
    elif args.command == "monitor":
        cli.cmd_monitor(tail=args.tail, refresh=args.refresh)
    elif args.command == "logs":
        cli.cmd_logs(tail=args.tail, severity=args.severity)
    elif args.command == "agents":
        cli.cmd_agents(register=args.register, action=args.action, agent_id=args.agent_id)
    elif args.command == "policies":
        cli.cmd_policies()
    elif args.command == "status":
        cli.cmd_status()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
