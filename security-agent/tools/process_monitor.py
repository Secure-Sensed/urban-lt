import subprocess
import platform
import psutil
from datetime import datetime
from config import SUSPICIOUS_PROCESS_NAMES


def _get_processes() -> list[dict]:
    procs = []
    for proc in psutil.process_iter(["pid", "name", "username", "cmdline", "connections", "create_time"]):
        try:
            info = proc.info
            procs.append({
                "pid": info["pid"],
                "name": info["name"],
                "user": info["username"],
                "cmdline": " ".join(info["cmdline"] or [])[:200],
                "connections": len(info["connections"] or []),
                "started": datetime.fromtimestamp(info["create_time"]).isoformat(),
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return procs


def scan_processes() -> dict:
    processes = _get_processes()

    flagged = []
    for proc in processes:
        name_lower = proc["name"].lower()
        cmd_lower = proc["cmdline"].lower()
        for sus in SUSPICIOUS_PROCESS_NAMES:
            if sus in name_lower or sus in cmd_lower:
                flagged.append({**proc, "matched_keyword": sus})
                break

    # Flag processes with many open connections
    high_conn = [p for p in processes if p["connections"] > 20]

    # Flag processes running as root/admin unexpectedly
    root_procs = [
        p for p in processes
        if p["user"] in ("root", "SYSTEM") and p["name"] not in (
            "launchd", "kernel_task", "systemd", "kthreadd", "sshd", "cron"
        )
    ]

    return {
        "total_processes": len(processes),
        "flagged_by_name": flagged,
        "high_connection_count": high_conn[:10],
        "unexpected_root_processes": root_procs[:10],
        "all_processes": processes[:50],
    }
