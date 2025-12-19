from fastapi import FastAPI, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Any, Dict, List, Optional
from datetime import datetime, timezone
import json
import sys
import os
import asyncio
import time
import traceback
from openai import OpenAI, AsyncOpenAI

# Module-level log to confirm file is loaded
print(
    f"[Module Load] app.py module loaded at {datetime.now(timezone.utc).isoformat()}",
    file=sys.stdout,
    flush=True,
)

app = FastAPI(title="Breach Hunter", version="0.2.0")
print(
    f"[Module Load] FastAPI app instance created",
    file=sys.stdout,
    flush=True,
)

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
    # Evaluation fields
    evaluation_by: Optional[str] = Field(default=None, description="Who evaluated this action (e.g., 'OpenAI GPT-4')")
    intent: Optional[str] = Field(default=None, description="Detected intent of the action")
    risk: Optional[str] = Field(default=None, description="Risk classification (e.g., 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL')")
    evaluation_time_taken: Optional[float] = Field(default=None, description="Time taken for evaluation in seconds")
    evaluation_description: Optional[str] = Field(default=None, description="Detailed description of the evaluation")
    evaluation_timestamp: Optional[datetime] = Field(default=None, description="When the evaluation was completed")


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

# Background task reference (to prevent garbage collection)
BACKGROUND_TASK: Optional[asyncio.Task] = None

# OpenAI clients (initialized lazily if API key is available)
OPENAI_CLIENT: Optional[OpenAI] = None
OPENAI_ASYNC_CLIENT: Optional[AsyncOpenAI] = None
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
OPENAI_BASE_URL = os.getenv("OPENAI_BASE_URL")  # Custom on-prem URL (optional)
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "openai/gpt-5.2")  # Model name, defaults to openai/gpt-5.2


def get_openai_client() -> Optional[OpenAI]:
    """Get or initialize synchronous OpenAI client. Returns None if API key is not configured."""
    global OPENAI_CLIENT
    if OPENAI_CLIENT is not None:
        return OPENAI_CLIENT
    
    if not OPENAI_API_KEY:
        print(
            "[OpenAI] API key not configured, skipping client initialization",
            file=sys.stdout,
            flush=True,
        )
        return None
    
    try:
        # Explicitly create client with only api_key to avoid any proxy/environment issues
        # Check OpenAI library version compatibility
        import openai
        print(
            f"[OpenAI] Initializing sync client with OpenAI library version: {openai.__version__}",
            file=sys.stdout,
            flush=True,
        )
        
        # Initialize with explicit api_key and optional base_url
        # Note: If you see 'proxies' parameter errors, it's likely a version compatibility
        # issue between openai and httpx. Upgrade openai to >=1.55.3 or downgrade httpx to 0.27.2
        client_kwargs = {"api_key": OPENAI_API_KEY}
        if OPENAI_BASE_URL:
            client_kwargs["base_url"] = OPENAI_BASE_URL
            print(
                f"[OpenAI] Using custom base URL: {OPENAI_BASE_URL}",
                file=sys.stdout,
                flush=True,
            )
        OPENAI_CLIENT = OpenAI(**client_kwargs)
        print(
            f"[OpenAI] Sync client initialized successfully (model: {OPENAI_MODEL})",
            file=sys.stdout,
            flush=True,
        )
        return OPENAI_CLIENT
    except Exception as e:
        error_type = type(e).__name__
        error_msg = str(e)
        print(
            f"[OpenAI] Failed to initialize sync client: {error_type}: {error_msg}",
            file=sys.stderr,
            flush=True,
        )
        # Print full traceback for debugging
        import traceback
        print(
            f"[OpenAI] Traceback:\n{traceback.format_exc()}",
            file=sys.stderr,
            flush=True,
        )
        OPENAI_CLIENT = None  # Ensure it's set to None on failure
        return None


def get_openai_async_client() -> Optional[AsyncOpenAI]:
    """Get or initialize async OpenAI client. Returns None if API key is not configured."""
    global OPENAI_ASYNC_CLIENT
    if OPENAI_ASYNC_CLIENT is not None:
        return OPENAI_ASYNC_CLIENT
    
    if not OPENAI_API_KEY:
        return None
    
    try:
        import openai
        print(
            f"[OpenAI] Initializing async client with OpenAI library version: {openai.__version__}",
            file=sys.stdout,
            flush=True,
        )
        
        # Initialize async client with explicit api_key and optional base_url
        client_kwargs = {"api_key": OPENAI_API_KEY}
        if OPENAI_BASE_URL:
            client_kwargs["base_url"] = OPENAI_BASE_URL
            print(
                f"[OpenAI] Using custom base URL: {OPENAI_BASE_URL}",
                file=sys.stdout,
                flush=True,
            )
        OPENAI_ASYNC_CLIENT = AsyncOpenAI(**client_kwargs)
        print(
            f"[OpenAI] Async client initialized successfully (model: {OPENAI_MODEL})",
            file=sys.stdout,
            flush=True,
        )
        return OPENAI_ASYNC_CLIENT
    except Exception as e:
        error_type = type(e).__name__
        error_msg = str(e)
        print(
            f"[OpenAI] Failed to initialize async client: {error_type}: {error_msg}",
            file=sys.stderr,
            flush=True,
        )
        print(
            f"[OpenAI] Traceback:\n{traceback.format_exc()}",
            file=sys.stderr,
            flush=True,
        )
        OPENAI_ASYNC_CLIENT = None
        return None


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
    
    print(
        f"[Notify] Stored new action: id={stored.id}, agent_id={stored.agent_id}, "
        f"action_type={stored.action_type}, status={stored.status}, "
        f"total_actions_in_store={len(ACTIONS)}",
        file=sys.stdout,
        flush=True,
    )

    return {"status": "received", "action_id": stored.id}


@app.get("/health")
async def health():
    """Simple health check endpoint."""
    return {"status": "ok"}


@app.get("/worker-status")
async def worker_status():
    """Diagnostic endpoint to check background worker status."""
    global BACKGROUND_TASK
    
    status_info = {
        "worker_task_exists": BACKGROUND_TASK is not None,
        "openai_configured": OPENAI_API_KEY is not None,
        "openai_sync_client_available": get_openai_client() is not None,
        "openai_async_client_available": get_openai_async_client() is not None,
        "total_actions": len(ACTIONS),
        "new_actions_count": len([a for a in ACTIONS if a.status == "NEW"]),
        "status_breakdown": {},
    }
    
    if BACKGROUND_TASK:
        status_info["task_done"] = BACKGROUND_TASK.done()
        status_info["task_cancelled"] = BACKGROUND_TASK.cancelled()
        if BACKGROUND_TASK.done():
            try:
                status_info["task_exception"] = str(BACKGROUND_TASK.exception())
            except Exception as e:
                status_info["task_exception"] = f"Error getting exception: {e}"
    
    # Status breakdown
    for action in ACTIONS:
        status = action.status
        status_info["status_breakdown"][status] = status_info["status_breakdown"].get(status, 0) + 1
    
    return status_info


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


async def evaluate_action_with_openai(action: StoredAction) -> Dict[str, Any]:
    """
    Evaluate an action using OpenAI to determine intent and risk classification.
    Returns a dictionary with evaluation results.
    Uses async OpenAI client to avoid blocking the event loop.
    """
    print(
        f"[Evaluate OpenAI] Starting evaluation for action {action.id} (agent_id={action.agent_id}, type={action.action_type})",
        file=sys.stdout,
        flush=True,
    )
    
    # Use async client to avoid blocking the event loop
    client = get_openai_async_client()
    if not client:
        print(
            f"[Evaluate OpenAI] WARNING: OpenAI async client not available for action {action.id}",
            file=sys.stderr,
            flush=True,
        )
        return {
            "evaluation_by": None,
            "intent": "Evaluation unavailable",
            "risk": "UNKNOWN",
            "evaluation_time_taken": 0.0,
            "evaluation_description": "OpenAI API key not configured or client initialization failed",
        }

    start_time = time.time()
    print(
        f"[Evaluate OpenAI] OpenAI async client available, building prompt for action {action.id}...",
        file=sys.stdout,
        flush=True,
    )

    # Build context for OpenAI
    action_context = {
        "agent_id": action.agent_id,
        "action_type": action.action_type,
        "process_id": action.process_id,
        "host_address": action.host_address,
        "timestamp": action.timestamp.isoformat(),
    }

    # Add action-specific details
    details = action.action_details
    if details.command:
        action_context["command"] = details.command
    if details.file_path:
        action_context["file_path"] = details.file_path
    if details.url:
        action_context["url"] = details.url
    if details.method:
        action_context["method"] = details.method

    prompt = f"""You are a security analyst evaluating AI agent actions for potential security risks.

Action Details:
- Agent ID: {action_context.get('agent_id', 'N/A')}
- Action Type: {action_context.get('action_type', 'N/A')}
- Process ID: {action_context.get('process_id', 'N/A')}
- Host Address: {action_context.get('host_address', 'N/A')}
- Timestamp: {action_context.get('timestamp', 'N/A')}
"""

    if details.command:
        prompt += f"- Command: {details.command}\n"
    if details.file_path:
        prompt += f"- File Path: {details.file_path}\n"
    if details.url:
        prompt += f"- URL: {details.url}\n"
    if details.method:
        prompt += f"- HTTP Method: {details.method}\n"

    prompt += """
Analyze this action and provide:
1. INTENT: What is the likely intent/purpose of this action? (e.g., "File read operation", "Network request", "System command execution")
2. RISK: Classify the risk level as one of: LOW, MEDIUM, HIGH, CRITICAL
3. DESCRIPTION: A brief explanation of why this risk level was assigned and what security concerns exist.

Respond in JSON format with these exact keys:
{
  "intent": "...",
  "risk": "LOW|MEDIUM|HIGH|CRITICAL",
  "description": "..."
}
"""

    try:
        # Use async API call to avoid blocking the event loop
        response = await client.chat.completions.create(
            model="openai/gpt-5.2",
            messages=[
                {
                    "role": "system",
                    "content": "You are a security analyst specializing in AI agent behavior analysis. Always respond with valid JSON.",
                },
                {"role": "user", "content": prompt},
            ],
            temperature=0.3,
            max_tokens=500,
        )

        content = response.choices[0].message.content.strip()
        # Try to extract JSON from the response
        if "```json" in content:
            content = content.split("```json")[1].split("```")[0].strip()
        elif "```" in content:
            content = content.split("```")[1].split("```")[0].strip()

        eval_result = json.loads(content)
        time_taken = time.time() - start_time

        return {
            "evaluation_by": "OpenAI GPT-4",
            "intent": eval_result.get("intent", "Unknown"),
            "risk": eval_result.get("risk", "UNKNOWN").upper(),
            "evaluation_time_taken": round(time_taken, 2),
            "evaluation_description": eval_result.get("description", "No description provided"),
        }
    except Exception as e:
        time_taken = time.time() - start_time
        return {
            "evaluation_by": "OpenAI GPT-4",
            "intent": "Evaluation failed",
            "risk": "UNKNOWN",
            "evaluation_time_taken": round(time_taken, 2),
            "evaluation_description": f"Error during evaluation: {str(e)}",
        }


async def background_evaluation_worker():
    """
    Background worker that continuously polls for NEW actions and evaluates them.
    """
    poll_count = 0
    print(
        f"[Evaluation Worker] Background evaluation worker STARTED at {datetime.now(timezone.utc).isoformat()}",
        file=sys.stdout,
        flush=True,
    )
    print(
        f"[Evaluation Worker] OpenAI API key configured: {OPENAI_API_KEY is not None}",
        file=sys.stdout,
        flush=True,
    )
    print(
        f"[Evaluation Worker] OpenAI async client available: {get_openai_async_client() is not None}",
        file=sys.stdout,
        flush=True,
    )
    
    # Initial heartbeat to confirm worker is running
    print(
        f"[Evaluation Worker] Worker heartbeat: Initial poll starting in 1 second...",
        file=sys.stdout,
        flush=True,
    )
    await asyncio.sleep(1)
    
    while True:
        try:
            poll_count += 1
            total_actions = len(ACTIONS)
            
            # Find actions with status NEW
            new_actions = [a for a in ACTIONS if a.status == "NEW"]
            new_count = len(new_actions)
            
            print(
                f"[Evaluation Worker] Poll #{poll_count}: Total actions={total_actions}, "
                f"NEW actions found={new_count}",
                file=sys.stdout,
                flush=True,
            )
            
            if new_count == 0:
                print(
                    f"[Evaluation Worker] No new actions to evaluate, sleeping for 2 seconds...",
                    file=sys.stdout,
                    flush=True,
                )
            else:
                # Log status breakdown for debugging
                status_breakdown = {}
                for a in ACTIONS:
                    status_breakdown[a.status] = status_breakdown.get(a.status, 0) + 1
                print(
                    f"[Evaluation Worker] Action status breakdown: {status_breakdown}",
                    file=sys.stdout,
                    flush=True,
                )
                
                for idx, action in enumerate(new_actions, 1):
                    print(
                        f"[Evaluation Worker] Processing action {idx}/{new_count}: "
                        f"id={action.id}, agent_id={action.agent_id}, "
                        f"action_type={action.action_type}, current_status={action.status}",
                        file=sys.stdout,
                        flush=True,
                    )
                    
                    # Update status to UNDER_EVALUATION
                    old_status = action.status
                    action.status = "UNDER_EVALUATION"
                    print(
                        f"[Evaluation Worker] Action {action.id} status changed: "
                        f"{old_status} -> {action.status}",
                        file=sys.stdout,
                        flush=True,
                    )

                    # Perform evaluation
                    print(
                        f"[Evaluation Worker] Starting OpenAI evaluation for action {action.id}...",
                        file=sys.stdout,
                        flush=True,
                    )
                    eval_result = await evaluate_action_with_openai(action)
                    print(
                        f"[Evaluation Worker] OpenAI evaluation completed for action {action.id}: "
                        f"risk={eval_result.get('risk')}, intent={eval_result.get('intent')}, "
                        f"time_taken={eval_result.get('evaluation_time_taken')}s",
                        file=sys.stdout,
                        flush=True,
                    )

                    # Update action with evaluation results
                    action.status = "EVALUATED"
                    action.evaluation_by = eval_result.get("evaluation_by")
                    action.intent = eval_result.get("intent")
                    action.risk = eval_result.get("risk")
                    action.evaluation_time_taken = eval_result.get("evaluation_time_taken")
                    action.evaluation_description = eval_result.get("evaluation_description")
                    action.evaluation_timestamp = datetime.now(timezone.utc)

                    print(
                        f"[Evaluation Worker] Action {action.id} evaluation complete: "
                        f"status={action.status}, risk={action.risk}, intent={action.intent}",
                        file=sys.stdout,
                        flush=True,
                    )

            # Sleep for 2 seconds before next poll
            print(
                f"[Evaluation Worker] Poll #{poll_count} complete, sleeping for 2 seconds...",
                file=sys.stdout,
                flush=True,
            )
            await asyncio.sleep(2)
        except Exception as e:
            error_trace = traceback.format_exc()
            print(
                f"[Evaluation Worker] ERROR in poll #{poll_count}: {type(e).__name__}: {e}",
                file=sys.stderr,
                flush=True,
            )
            print(
                f"[Evaluation Worker] Error traceback:\n{error_trace}",
                file=sys.stderr,
                flush=True,
            )
            await asyncio.sleep(5)  # Wait longer on error


@app.on_event("startup")
async def startup_event():
    """Start the background evaluation worker on server startup."""
    global BACKGROUND_TASK
    
    print(
        f"[Startup] FastAPI startup event triggered at {datetime.now(timezone.utc).isoformat()}",
        file=sys.stdout,
        flush=True,
    )
    
    # Check OpenAI configuration
    print(
        f"[Startup] Checking OpenAI configuration...",
        file=sys.stdout,
        flush=True,
    )
    print(
        f"[Startup] OPENAI_API_KEY environment variable set: {OPENAI_API_KEY is not None}",
        file=sys.stdout,
        flush=True,
    )
    if OPENAI_BASE_URL:
        print(
            f"[Startup] OPENAI_BASE_URL configured: {OPENAI_BASE_URL}",
            file=sys.stdout,
            flush=True,
        )
    print(
        f"[Startup] OpenAI model: {OPENAI_MODEL}",
        file=sys.stdout,
        flush=True,
    )
    
    # Initialize both sync and async clients
    sync_client = get_openai_client()
    async_client = get_openai_async_client()
    
    if sync_client and async_client:
        print(
            f"[Startup] OpenAI clients (sync and async) initialized successfully",
            file=sys.stdout,
            flush=True,
        )
    elif async_client:
        print(
            f"[Startup] OpenAI async client initialized successfully (sync client failed)",
            file=sys.stdout,
            flush=True,
        )
    else:
        print(
            "[Startup] WARNING: OpenAI API key not configured or client initialization failed.",
            file=sys.stderr,
            flush=True,
        )
        print(
            "[Startup] Worker will still run but evaluations will use default 'UNKNOWN' risk level.",
            file=sys.stdout,
            flush=True,
        )
    
    # Always start the worker, even if OpenAI is not configured
    # The worker will handle missing OpenAI gracefully
    print(
        f"[Startup] Creating background evaluation worker task...",
        file=sys.stdout,
        flush=True,
    )
    # Create and store the task to prevent garbage collection
    BACKGROUND_TASK = asyncio.create_task(background_evaluation_worker())
    print(
        f"[Startup] Background evaluation worker task created: {BACKGROUND_TASK}",
        file=sys.stdout,
        flush=True,
    )
    print(
        f"[Startup] Task done status: {BACKGROUND_TASK.done()}, cancelled: {BACKGROUND_TASK.cancelled()}",
        file=sys.stdout,
        flush=True,
    )
    print(
        "[Startup] Background evaluation worker started successfully",
        file=sys.stdout,
        flush=True,
    )
