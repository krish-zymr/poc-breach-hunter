"""Type definitions for intent classification system."""
from __future__ import annotations

from enum import Enum
from typing import Dict, Optional, TypedDict


class ActionType(str, Enum):
    """Types of actions that can be intercepted."""

    FILE_READ = "file_read"
    FILE_WRITE = "file_write"
    SUBPROCESS_EXEC = "subprocess_execution"
    NETWORK_CONNECT = "network_connect"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    UNKNOWN = "unknown"


class IntentType(str, Enum):
    """Probable intent behind an action."""

    BENIGN = "benign"
    EXPLORATION = "exploration"
    DATA_EXFILTRATION = "data_exfiltration"
    REMOTE_COMMAND_EXECUTION = "remote_command_execution"
    ENUMERATION = "enumeration"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    ATTACK_PREP = "attack_prep"
    UNKNOWN = "unknown"


class RiskLevel(str, Enum):
    """Risk level associated with an action."""

    SAFE = "safe"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class IntentResult(TypedDict, total=False):
    """Structured result from intent classification.

    Attributes:
        action_type: Type of action detected.
        intent: Probable intent behind the action.
        risk: Risk level (low, medium, high, critical).
        confidence: Confidence score between 0.0 and 1.0.
        explanation: Human-readable explanation of the classification.
        rule_matched: Name of the rule that matched (if rule-based).
        ml_confidence: ML model confidence (if ML-based).
        classification_backend: Backend used for classification (ollama, transformers, ml, rule, fallback).
        classification_duration_ms: Time taken to classify, in milliseconds.
    """

    action_type: ActionType
    intent: IntentType
    risk: RiskLevel
    confidence: float
    explanation: str
    rule_matched: Optional[str]
    ml_confidence: Optional[float]
    classification_backend: Optional[str]
    classification_duration_ms: Optional[int]


class EventDict(TypedDict, total=False):
    """Normalized event structure for classification.

    Attributes:
        event_type: Type of event (e.g., "file_open", "subprocess_popen").
        file: File path (for file operations).
        mode: File open mode (for file operations).
        argv: Command and arguments (for subprocess operations).
        cmd: Command string (for os.system).
        host: Hostname or IP address (for network operations).
        port: Port number (for network operations).
        family: Socket family (for network operations).
        type: Socket type (for network operations).
    """

    event_type: str
    file: Optional[str]
    mode: Optional[str]
    argv: Optional[list[str]]
    cmd: Optional[str]
    host: Optional[str]
    port: Optional[int]
    family: Optional[int]
    type: Optional[int]


def normalize_event(event_type: str, arguments: Dict[str, object]) -> EventDict:
    """Normalize an intercepted event into a unified structure.

    Args:
        event_type: Type of event (e.g., "file_open", "subprocess_popen").
        arguments: Event arguments dictionary.

    Returns:
        Normalized EventDict structure.
    """
    normalized: EventDict = {
        "event_type": event_type.lower(),
    }

    # File operations
    # Handle both "file" and "file_path" keys
    if "file" in arguments:
        normalized["file"] = str(arguments["file"])
    elif "file_path" in arguments:
        normalized["file"] = str(arguments["file_path"])
    
    # Handle both "mode" and "command" keys (command="write" -> mode="w")
    if "mode" in arguments:
        normalized["mode"] = str(arguments["mode"])
    elif "command" in arguments:
        cmd = str(arguments["command"]).lower()
        if cmd == "write" or cmd == "w":
            normalized["mode"] = "w"
        elif cmd == "read" or cmd == "r":
            normalized["mode"] = "r"
        elif cmd == "append" or cmd == "a":
            normalized["mode"] = "a"
        else:
            normalized["mode"] = cmd

    # Subprocess operations
    if "argv" in arguments:
        argv = arguments["argv"]
        if isinstance(argv, (list, tuple)):
            normalized["argv"] = [str(arg) for arg in argv]
        else:
            normalized["argv"] = [str(argv)]
    if "cmd" in arguments:
        normalized["cmd"] = str(arguments["cmd"])

    # Network operations
    if "host" in arguments:
        normalized["host"] = str(arguments["host"])
    if "port" in arguments:
        try:
            normalized["port"] = int(arguments["port"])
        except (ValueError, TypeError):
            pass
    if "family" in arguments:
        try:
            normalized["family"] = int(arguments["family"])
        except (ValueError, TypeError):
            pass
    if "type" in arguments:
        try:
            normalized["type"] = int(arguments["type"])
        except (ValueError, TypeError):
            pass

    return normalized

