import os

# Ollama model to use — change to any locally pulled model
OLLAMA_MODEL = "llama3"
OLLAMA_BASE_URL = "http://localhost:11434"

# Paths to monitor for file integrity
WATCH_PATHS = [
    "/etc/hosts",
    "/etc/passwd",
    "/etc/sudoers",
    os.path.expanduser("~/.ssh/authorized_keys"),
    os.path.expanduser("~/.bashrc"),
    os.path.expanduser("~/.zshrc"),
]

# Log files to analyze
LOG_PATHS = [
    "/var/log/system.log",        # macOS system log
    "/var/log/auth.log",          # auth events (Linux)
    "/var/log/syslog",            # syslog (Linux)
    os.path.expanduser("~/Library/Logs"),  # macOS app logs
]

# Ports considered suspicious if listening externally
SUSPICIOUS_PORTS = [23, 445, 3389, 4444, 5900, 6666, 6667, 31337]

# Processes to flag as suspicious by name
SUSPICIOUS_PROCESS_NAMES = [
    "nc", "ncat", "netcat", "nmap", "msfconsole",
    "meterpreter", "mimikatz", "hydra", "john"
]

# Baseline storage
BASELINE_FILE = os.path.join(os.path.dirname(__file__), "data/baselines/file_hashes.json")

# Alert log
ALERT_LOG = os.path.join(os.path.dirname(__file__), "data/logs/alerts.jsonl")
