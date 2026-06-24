#!/usr/bin/env python3
"""
Local Security Agent — powered by Ollama (fully offline)
Run: python agent.py
"""

import sys
import json
import os
import datetime
import requests
from typing import Any

sys.path.insert(0, os.path.dirname(__file__))

from config import OLLAMA_MODEL, OLLAMA_BASE_URL, ALERT_LOG
from tools.log_analyzer import analyze_logs
from tools.network_monitor import scan_network
from tools.file_integrity import check_integrity, create_baseline
from tools.process_monitor import scan_processes

BANNER = r"""
╔══════════════════════════════════════════════════════╗
║        LOCAL SECURITY AGENT  •  Offline LLM          ║
║        Model: {model:<38}║
╚══════════════════════════════════════════════════════╝
Type 'help' for commands. All processing is local.
"""

SYSTEM_PROMPT = """You are a local security analyst AI agent running completely offline on the user's machine.
Your job is to analyze security data from the local system — logs, processes, network connections,
and file integrity — and provide clear, actionable threat assessments.

Rules:
- Be concise but thorough. Lead with the most critical finding.
- Classify severity: CRITICAL / HIGH / MEDIUM / LOW / INFO
- Always explain WHY something is suspicious, not just that it is.
- Recommend concrete next steps the user can take.
- Never make up data — only assess what is provided.
- If data is clean, say so clearly and briefly.
"""

TOOL_DEFINITIONS = [
    {
        "name": "analyze_logs",
        "description": "Scan system log files for threat patterns (brute force, privilege escalation, intrusion attempts, suspicious downloads).",
        "parameters": {"type": "object", "properties": {}, "required": []},
    },
    {
        "name": "scan_network",
        "description": "List active network connections and flag suspicious ports or unexpected external connections.",
        "parameters": {"type": "object", "properties": {}, "required": []},
    },
    {
        "name": "check_integrity",
        "description": "Compare current hashes of watched sensitive files against the stored baseline to detect unauthorized modifications.",
        "parameters": {"type": "object", "properties": {}, "required": []},
    },
    {
        "name": "create_baseline",
        "description": "Capture SHA-256 hashes of all watched files as a trusted baseline for future integrity checks.",
        "parameters": {"type": "object", "properties": {}, "required": []},
    },
    {
        "name": "scan_processes",
        "description": "List all running processes and flag suspicious ones by name, high connection count, or unexpected root execution.",
        "parameters": {"type": "object", "properties": {}, "required": []},
    },
    {
        "name": "full_scan",
        "description": "Run all security checks at once: logs, network, file integrity, and processes.",
        "parameters": {"type": "object", "properties": {}, "required": []},
    },
]

TOOL_MAP = {
    "analyze_logs": analyze_logs,
    "scan_network": scan_network,
    "check_integrity": check_integrity,
    "create_baseline": create_baseline,
    "scan_processes": scan_processes,
    "full_scan": lambda: {
        "logs": analyze_logs(),
        "network": scan_network(),
        "integrity": check_integrity(),
        "processes": scan_processes(),
    },
}


def call_ollama(messages: list[dict], tools: list[dict] | None = None) -> dict:
    payload = {
        "model": OLLAMA_MODEL,
        "messages": messages,
        "stream": False,
    }
    if tools:
        payload["tools"] = tools

    try:
        resp = requests.post(
            f"{OLLAMA_BASE_URL}/api/chat",
            json=payload,
            timeout=120,
        )
        resp.raise_for_status()
        return resp.json()
    except requests.ConnectionError:
        print("\n[ERROR] Cannot reach Ollama. Is it running? Run: ollama serve")
        sys.exit(1)
    except requests.HTTPError as e:
        print(f"\n[ERROR] Ollama returned an error: {e}")
        sys.exit(1)


def log_alert(findings: dict) -> None:
    os.makedirs(os.path.dirname(ALERT_LOG), exist_ok=True)
    with open(ALERT_LOG, "a") as f:
        f.write(json.dumps({
            "timestamp": datetime.datetime.now().isoformat(),
            "findings": findings,
        }) + "\n")


def run_tool(name: str, args: dict) -> Any:
    fn = TOOL_MAP.get(name)
    if not fn:
        return {"error": f"Unknown tool: {name}"}
    print(f"  [Tool] Running {name}...", end=" ", flush=True)
    result = fn(**args) if args else fn()
    print("done.")
    return result


def agent_loop(user_message: str, conversation: list[dict]) -> str:
    conversation.append({"role": "user", "content": user_message})

    # Agentic loop — allow up to 5 tool call rounds
    for _ in range(5):
        response = call_ollama(conversation, tools=TOOL_DEFINITIONS)
        message = response.get("message", {})
        tool_calls = message.get("tool_calls", [])

        if not tool_calls:
            assistant_text = message.get("content", "")
            conversation.append({"role": "assistant", "content": assistant_text})
            return assistant_text

        # Execute all tool calls and feed results back
        conversation.append({"role": "assistant", "content": message.get("content", ""), "tool_calls": tool_calls})
        for tc in tool_calls:
            fn_name = tc["function"]["name"]
            fn_args = tc.get("function", {}).get("arguments", {})
            if isinstance(fn_args, str):
                try:
                    fn_args = json.loads(fn_args)
                except json.JSONDecodeError:
                    fn_args = {}
            result = run_tool(fn_name, fn_args)
            log_alert(result)
            conversation.append({
                "role": "tool",
                "content": json.dumps(result, default=str),
            })

    return "[Agent] Max tool call rounds reached."


def print_help() -> None:
    print("""
Commands:
  scan logs       — Analyze system logs for threats
  scan network    — Check active connections and ports
  scan files      — File integrity check (needs baseline first)
  baseline        — Create file hash baseline
  scan processes  — Inspect running processes
  scan all        — Run every check at once
  alerts          — Show past alert log
  clear           — Clear conversation history
  exit / quit     — Exit the agent

Or type any question in natural language.
""")


def show_alerts() -> None:
    if not os.path.exists(ALERT_LOG):
        print("No alerts logged yet.")
        return
    with open(ALERT_LOG) as f:
        lines = f.readlines()[-10:]
    print(f"\nLast {len(lines)} alert entries:\n")
    for line in lines:
        try:
            entry = json.loads(line)
            print(f"  [{entry['timestamp']}]")
        except Exception:
            print(f"  {line.strip()}")


COMMAND_MAP = {
    "scan logs": "Analyze my system logs and identify any security threats.",
    "scan network": "Scan the network connections on this machine and flag anything suspicious.",
    "scan files": "Check file integrity and tell me if any critical files have been modified.",
    "baseline": "Create a file hash baseline for all watched files.",
    "scan processes": "Scan all running processes and identify any suspicious activity.",
    "scan all": "Run a full security scan: logs, network, files, and processes. Give me a complete threat assessment.",
}


def main() -> None:
    print(BANNER.format(model=OLLAMA_MODEL))

    # Verify Ollama is reachable
    try:
        requests.get(f"{OLLAMA_BASE_URL}/api/tags", timeout=5)
    except requests.ConnectionError:
        print("[WARN] Ollama not detected. Start it with: ollama serve")
        print("       Then pull a model: ollama pull llama3\n")

    conversation = [{"role": "system", "content": SYSTEM_PROMPT}]

    while True:
        try:
            user_input = input("\nAgent> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nGoodbye.")
            break

        if not user_input:
            continue

        cmd = user_input.lower()

        if cmd in ("exit", "quit"):
            print("Goodbye.")
            break
        elif cmd == "help":
            print_help()
            continue
        elif cmd == "clear":
            conversation = [{"role": "system", "content": SYSTEM_PROMPT}]
            print("Conversation cleared.")
            continue
        elif cmd == "alerts":
            show_alerts()
            continue
        elif cmd in COMMAND_MAP:
            user_input = COMMAND_MAP[cmd]

        print()
        reply = agent_loop(user_input, conversation)
        print(f"\n{reply}\n")


if __name__ == "__main__":
    main()
