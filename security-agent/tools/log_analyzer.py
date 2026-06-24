import os
import re
import glob
from datetime import datetime
from config import LOG_PATHS

# Patterns that indicate potential threats
THREAT_PATTERNS = [
    (r"Failed password|authentication failure|Invalid user", "BRUTE_FORCE"),
    (r"sudo:.+FAILED|su:.+FAILED", "PRIVILEGE_ESCALATION_ATTEMPT"),
    (r"Accepted password|Accepted publickey", "SUCCESSFUL_LOGIN"),
    (r"segfault|kernel panic|oom-killer", "SYSTEM_INSTABILITY"),
    (r"POSSIBLE BREAK-IN ATTEMPT|reverse mapping checking", "INTRUSION_ATTEMPT"),
    (r"chmod 777|chmod \+s|setuid", "PERMISSION_CHANGE"),
    (r"wget|curl.*http|base64 -d|eval\(", "SUSPICIOUS_DOWNLOAD"),
    (r"/etc/shadow|/etc/passwd.*root", "SENSITIVE_FILE_ACCESS"),
]


def _read_recent_lines(path: str, max_lines: int = 200) -> list[str]:
    try:
        with open(path, "r", errors="replace") as f:
            return f.readlines()[-max_lines:]
    except (PermissionError, FileNotFoundError):
        return []


def analyze_logs() -> dict:
    findings = []
    sources_checked = []

    paths_to_check = []
    for p in LOG_PATHS:
        if os.path.isdir(p):
            paths_to_check.extend(glob.glob(os.path.join(p, "*.log")))
        elif os.path.isfile(p):
            paths_to_check.append(p)

    for log_path in paths_to_check:
        lines = _read_recent_lines(log_path)
        if not lines:
            continue
        sources_checked.append(log_path)
        for line in lines:
            for pattern, threat_type in THREAT_PATTERNS:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append({
                        "source": log_path,
                        "threat_type": threat_type,
                        "line": line.strip(),
                        "timestamp": datetime.now().isoformat(),
                    })
                    break  # one classification per line

    # Deduplicate by threat_type + source
    seen = set()
    unique = []
    for f in findings:
        key = (f["threat_type"], f["source"])
        if key not in seen:
            seen.add(key)
            unique.append(f)

    return {
        "sources_checked": sources_checked,
        "total_matches": len(findings),
        "unique_threat_types": list({f["threat_type"] for f in unique}),
        "findings": unique[:20],  # cap to avoid flooding the LLM context
    }
