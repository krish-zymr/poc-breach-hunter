#!/usr/bin/env sh
set -e

# Simple helper script to run the demo agent WITH Breach Hunter integration.
# - Ensures Python dependencies are installed
# - Sets a default BREACH_HUNTER_URL if not already configured
# - Executes the sample CrewAI agent

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
cd "$SCRIPT_DIR"

echo "[Runner] Ensuring Python dependencies are installed..."
if command -v pip >/dev/null 2>&1; then
  pip install --no-cache-dir -r requirements.txt
else
  echo "[Runner] ERROR: 'pip' not found on PATH." >&2
  exit 1
fi

export BREACH_HUNTER_URL="${BREACH_HUNTER_URL:-http://breach-hunter-api:8000/notify}"
export DEMO_AGENT_ID="${DEMO_AGENT_ID:-demo-agent-001}"

echo "[Runner] Using BREACH_HUNTER_URL=${BREACH_HUNTER_URL}"
echo "[Runner] Using DEMO_AGENT_ID=${DEMO_AGENT_ID}"

echo "[Runner] Running sample agent with Breach Hunter integration..."
python sample_agent_with_breach_hunter.py


