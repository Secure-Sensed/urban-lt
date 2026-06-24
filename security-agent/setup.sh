#!/usr/bin/env bash
set -e

echo "=== Local Security Agent Setup ==="
echo ""

# 1. Check Python
if ! command -v python3 &>/dev/null; then
  echo "[ERROR] Python 3 not found. Install from https://python.org"
  exit 1
fi
echo "[OK] Python: $(python3 --version)"

# 2. Install Python dependencies
echo ""
echo "[1/3] Installing Python dependencies..."
pip3 install -r requirements.txt --quiet
echo "[OK] Dependencies installed."

# 3. Install Ollama
echo ""
echo "[2/3] Checking Ollama..."
if command -v ollama &>/dev/null; then
  echo "[OK] Ollama already installed: $(ollama --version)"
else
  echo "Installing Ollama..."
  if [[ "$OSTYPE" == "darwin"* ]]; then
    # macOS
    if command -v brew &>/dev/null; then
      brew install ollama
    else
      curl -fsSL https://ollama.com/install.sh | sh
    fi
  else
    # Linux
    curl -fsSL https://ollama.com/install.sh | sh
  fi
  echo "[OK] Ollama installed."
fi

# 4. Pull the LLM model
echo ""
echo "[3/3] Pulling llama3 model (this downloads ~4GB the first time)..."
ollama pull llama3
echo "[OK] Model ready."

echo ""
echo "=== Setup complete! ==="
echo ""
echo "To start the security agent:"
echo "  1. Start Ollama:   ollama serve"
echo "  2. Run the agent:  python3 agent.py"
echo ""
echo "First run: type 'baseline' to capture your file hashes, then 'scan all'."
