import hashlib
import json
import os
from datetime import datetime
from config import WATCH_PATHS, BASELINE_FILE


def _hash_file(path: str) -> str | None:
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except (PermissionError, FileNotFoundError):
        return None


def create_baseline() -> dict:
    """Snapshot current hashes for all watched paths."""
    baseline = {}
    for path in WATCH_PATHS:
        if os.path.isfile(path):
            h = _hash_file(path)
            if h:
                baseline[path] = {
                    "hash": h,
                    "size": os.path.getsize(path),
                    "mtime": os.path.getmtime(path),
                    "captured_at": datetime.now().isoformat(),
                }

    os.makedirs(os.path.dirname(BASELINE_FILE), exist_ok=True)
    with open(BASELINE_FILE, "w") as f:
        json.dump(baseline, f, indent=2)

    return {"status": "baseline_created", "files_captured": list(baseline.keys())}


def check_integrity() -> dict:
    if not os.path.exists(BASELINE_FILE):
        return {
            "status": "no_baseline",
            "message": "Run 'baseline' command first to capture a snapshot.",
        }

    with open(BASELINE_FILE) as f:
        baseline = json.load(f)

    changes = []
    missing = []
    new_files = []

    for path in WATCH_PATHS:
        if path not in baseline:
            if os.path.isfile(path):
                new_files.append(path)
            continue
        if not os.path.isfile(path):
            missing.append(path)
            continue

        current_hash = _hash_file(path)
        stored = baseline[path]
        if current_hash and current_hash != stored["hash"]:
            changes.append({
                "path": path,
                "original_hash": stored["hash"],
                "current_hash": current_hash,
                "original_mtime": stored["mtime"],
                "current_mtime": os.path.getmtime(path),
                "baseline_captured": stored["captured_at"],
            })

    return {
        "status": "checked",
        "modified_files": changes,
        "missing_files": missing,
        "new_files_not_in_baseline": new_files,
        "total_watched": len(WATCH_PATHS),
        "clean": len(changes) == 0 and len(missing) == 0,
    }
