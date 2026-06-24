import socket
import subprocess
import platform
from config import SUSPICIOUS_PORTS


def _get_connections_macos() -> list[dict]:
    """Use lsof on macOS to list network connections."""
    try:
        result = subprocess.run(
            ["lsof", "-nP", "-iTCP", "-iUDP", "-sTCP:LISTEN,ESTABLISHED"],
            capture_output=True, text=True, timeout=15
        )
        connections = []
        for line in result.stdout.splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 9:
                connections.append({
                    "process": parts[0],
                    "pid": parts[1],
                    "type": parts[4],
                    "address": parts[8],
                    "state": parts[9] if len(parts) > 9 else "LISTEN",
                })
        return connections
    except Exception as e:
        return [{"error": str(e)}]


def _get_connections_linux() -> list[dict]:
    """Use ss on Linux to list network connections."""
    try:
        result = subprocess.run(
            ["ss", "-tulpn"],
            capture_output=True, text=True, timeout=15
        )
        connections = []
        for line in result.stdout.splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 5:
                connections.append({
                    "protocol": parts[0],
                    "state": parts[1],
                    "local_address": parts[4],
                    "process": parts[-1] if "pid" in parts[-1] else "unknown",
                })
        return connections
    except Exception as e:
        return [{"error": str(e)}]


def scan_network() -> dict:
    system = platform.system()
    if system == "Darwin":
        connections = _get_connections_macos()
    elif system == "Linux":
        connections = _get_connections_linux()
    else:
        return {"error": f"Unsupported platform: {system}"}

    suspicious = []
    for conn in connections:
        addr = conn.get("address", "") or conn.get("local_address", "")
        for port in SUSPICIOUS_PORTS:
            if f":{port}" in addr or f"*.{port}" in addr:
                suspicious.append({**conn, "flagged_port": port})

    # Hostname resolution check (detect unusual external connections)
    external = []
    for conn in connections:
        addr = conn.get("address", "")
        if "->" in addr:
            remote = addr.split("->")[-1].split(":")[0]
            if not remote.startswith(("127.", "::1", "0.", "192.168.", "10.", "172.")):
                external.append({"remote": remote, "connection": conn})

    return {
        "total_connections": len(connections),
        "suspicious_port_matches": suspicious,
        "external_connections": external[:10],
        "all_connections": connections[:30],
    }
