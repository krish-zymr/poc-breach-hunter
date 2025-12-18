from fastapi import FastAPI
from pydantic import BaseModel, Field
from typing import Any, Dict, Optional
from datetime import datetime
import json
import sys


app = FastAPI(title="Breach Hunter", version="0.1.0")


class ActionDetails(BaseModel):
    command: Optional[str] = None
    file_path: Optional[str] = None
    method: Optional[str] = Field(
        default=None, description="HTTP method for API calls, e.g. GET/POST"
    )
    url: Optional[str] = None
    headers: Optional[Dict[str, Any]] = None
    body: Optional[Dict[str, Any]] = None


class ActionNotification(BaseModel):
    agent_id: str
    action_type: str
    action_details: ActionDetails
    timestamp: datetime


@app.post("/notify")
async def notify(action: ActionNotification):
    """
    Receive an agent action notification before it executes.
    Simply logs the payload and returns a basic acknowledgement.
    """
    # Pretty-print the incoming JSON to console/stdout
    try:
        payload_dict = action.model_dump(mode="json")
        pretty = json.dumps(payload_dict, indent=2, sort_keys=True)
        print("=== Breach Hunter - Incoming Action ===", file=sys.stdout)
        print(pretty, file=sys.stdout, flush=True)
    except Exception as exc:  # pragma: no cover - logging safety net
        print(f"Error while logging action: {exc}", file=sys.stderr, flush=True)

    return {"status": "received"}


@app.get("/health")
async def health():
    """Simple health check endpoint."""
    return {"status": "ok"}


