import json
import os
import sys
from datetime import datetime, timezone
from typing import Any, Dict

import requests


def notify_action(
    action_type: str,
    action_details: Dict[str, Any],
    agent_id: str = "default",
    timeout: float = 2.0,
) -> None:
    """
    Notify the Breach Hunter service about an action about to be executed.

    This function is intended to be called by AI agents *before* they perform
    a sensitive action (file operations, command execution, API calls, etc).

    It is designed to fail gracefully: if the service URL is not configured
    or the HTTP call fails, the exception is swallowed and the agent can
    continue its normal execution flow.
    """
    url = os.getenv("BREACH_HUNTER_URL")
    if not url:
        # No configuration present; nothing to do.
        return

    timestamp = datetime.now(timezone.utc).isoformat()

    payload: Dict[str, Any] = {
        "agent_id": agent_id,
        "action_type": action_type,
        "action_details": action_details,
        "timestamp": timestamp,
    }

    headers = {"Content-Type": "application/json"}

    try:
        response = requests.post(url, data=json.dumps(payload), headers=headers, timeout=timeout)
        # Optionally, we can log non-2xx responses for debugging.
        if not (200 <= response.status_code < 300):
            print(
                f"[BreachHunter] Non-OK response {response.status_code}: {response.text}",
                file=sys.stderr,
            )
    except Exception as exc:  # pragma: no cover - defensive programming
        print(f"[BreachHunter] Error sending notification: {exc}", file=sys.stderr)


