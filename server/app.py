from fastapi import FastAPI, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Any, Dict, List, Optional
from datetime import datetime, timezone
import json
import sys


app = FastAPI(title="Breach Hunter", version="0.2.0")

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, specify exact origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


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
    process_id: Optional[int] = Field(default=None, description="Process ID of the agent")
    host_address: Optional[str] = Field(default=None, description="Host address (hostname or IP) of the agent")


class StoredAction(BaseModel):
    id: int
    agent_id: str
    action_type: str
    action_details: ActionDetails
    timestamp: datetime
    status: str = Field(default="NEW", description="Lifecycle status of the action")
    process_id: Optional[int] = Field(default=None, description="Process ID of the agent")
    host_address: Optional[str] = Field(default=None, description="Host address (hostname or IP) of the agent")


class StoredAgent(BaseModel):
    agent_id: str
    created_time: datetime
    updated_time: datetime
    last_action_type: Optional[str] = None
    last_action_timestamp: Optional[datetime] = None


class PaginatedResponse(BaseModel):
    items: List[Any]
    total: int
    page: int
    page_size: int


# In-memory stores (reset on container restart)
ACTION_ID_SEQ = 0
ACTIONS: List[StoredAction] = []
AGENTS: Dict[str, StoredAgent] = {}


def _next_action_id() -> int:
    global ACTION_ID_SEQ
    ACTION_ID_SEQ += 1
    return ACTION_ID_SEQ


@app.post("/notify")
async def notify(action: ActionNotification):
    """
    Receive an agent action notification before it executes.
    - Logs the payload to stdout
    - Upserts the agent record
    - Stores the action with status NEW in an in-memory store
    """
    # Pretty-print the incoming JSON to console/stdout
    try:
        payload_dict = action.model_dump(mode="json")
        pretty = json.dumps(payload_dict, indent=2, sort_keys=True)
        print("=== Breach Hunter - Incoming Action ===", file=sys.stdout)
        print(pretty, file=sys.stdout, flush=True)
    except Exception as exc:  # pragma: no cover - logging safety net
        print(f"Error while logging action: {exc}", file=sys.stderr, flush=True)

    # Upsert agent record
    now = datetime.now(timezone.utc)
    existing = AGENTS.get(action.agent_id)
    if existing is None:
        AGENTS[action.agent_id] = StoredAgent(
            agent_id=action.agent_id,
            created_time=now,
            updated_time=now,
            last_action_type=action.action_type,
            last_action_timestamp=action.timestamp,
        )
    else:
        existing.updated_time = now
        existing.last_action_type = action.action_type
        existing.last_action_timestamp = action.timestamp
        AGENTS[action.agent_id] = existing

    # Store action with default status NEW
    stored = StoredAction(
        id=_next_action_id(),
        agent_id=action.agent_id,
        action_type=action.action_type,
        action_details=action.action_details,
        timestamp=action.timestamp,
        status="NEW",
        process_id=action.process_id,
        host_address=action.host_address,
    )
    ACTIONS.append(stored)

    return {"status": "received", "action_id": stored.id}


@app.get("/health")
async def health():
    """Simple health check endpoint."""
    return {"status": "ok"}


@app.get("/agents", response_model=PaginatedResponse)
async def list_agents(
    q: Optional[str] = Query(default=None, description="Search by agent_id substring"),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
):
    """
    Return a paginated list of agents.
    Supports simple search over agent_id via the `q` query parameter.
    """
    agents = list(AGENTS.values())

    if q:
        q_lower = q.lower()
        agents = [a for a in agents if q_lower in a.agent_id.lower()]

    total = len(agents)
    start = (page - 1) * page_size
    end = start + page_size
    items = agents[start:end]

    return PaginatedResponse(
        items=[a.model_dump(mode="json") for a in items],
        total=total,
        page=page,
        page_size=page_size,
    )


@app.get("/actions", response_model=PaginatedResponse)
async def list_actions(
    q: Optional[str] = Query(
        default=None,
        description="Search over agent_id, action_type, command or URL",
    ),
    agent_id: Optional[str] = Query(default=None, description="Filter by agent_id"),
    status: Optional[str] = Query(
        default=None, description='Filter by status (e.g. "NEW")'
    ),
    action_type: Optional[str] = Query(
        default=None, description="Filter by action_type (e.g. 'command_execution')"
    ),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
):
    """
    Return a paginated list of actions.
    Supports filters on agent_id, status, action_type, and a simple text search.
    """
    actions = ACTIONS

    if agent_id:
        actions = [a for a in actions if a.agent_id == agent_id]

    if status:
        actions = [a for a in actions if a.status.lower() == status.lower()]

    if action_type:
        actions = [a for a in actions if a.action_type.lower() == action_type.lower()]

    if q:
        q_lower = q.lower()
        filtered: List[StoredAction] = []
        for a in actions:
            details = a.action_details
            command = (details.command or "").lower()
            url = (details.url or "").lower()
            if (
                q_lower in a.agent_id.lower()
                or q_lower in a.action_type.lower()
                or q_lower in command
                or q_lower in url
            ):
                filtered.append(a)
        actions = filtered

    total = len(actions)
    start = (page - 1) * page_size
    end = start + page_size
    items = actions[start:end]

    return PaginatedResponse(
        items=[a.model_dump(mode="json") for a in items],
        total=total,
        page=page,
        page_size=page_size,
    )

