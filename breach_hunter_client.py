import json
import os
import socket
import sys
from datetime import datetime, timezone
from typing import Any, Dict, Optional

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

    # Capture process ID and host address
    process_id: Optional[int] = None
    host_address: Optional[str] = None

    try:
        process_id = os.getpid()
    except Exception:
        pass  # Ignore if process ID cannot be obtained

    try:
        # Try to get hostname first, fallback to IP address
        hostname = socket.gethostname()
        host_address = socket.gethostbyname(hostname)
    except Exception:
        try:
            # Fallback: try to get local IP address
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            host_address = s.getsockname()[0]
            s.close()
        except Exception:
            pass  # Ignore if host address cannot be obtained

    payload: Dict[str, Any] = {
        "agent_id": agent_id,
        "action_type": action_type,
        "action_details": action_details,
        "timestamp": timestamp,
    }

    # Add process_id and host_address if available
    if process_id is not None:
        payload["process_id"] = process_id
    if host_address is not None:
        payload["host_address"] = host_address

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


