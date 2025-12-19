"""Unified risk scoring logic for intent classification."""
from __future__ import annotations

from typing import Dict

from intent_types import ActionType, EventDict, IntentType, RiskLevel


class RiskScorer:
    """Computes risk scores based on action type, intent, and context."""

    # Risk scores by action type (0.0 to 1.0)
    ACTION_RISK_SCORES: Dict[ActionType, float] = {
        ActionType.FILE_READ: 0.1,
        ActionType.FILE_WRITE: 0.5,
        ActionType.SUBPROCESS_EXEC: 0.7,
        ActionType.NETWORK_CONNECT: 0.6,
        ActionType.PRIVILEGE_ESCALATION: 0.95,
        ActionType.UNKNOWN: 0.3,
    }

    # Risk scores by intent type
    INTENT_RISK_SCORES: Dict[IntentType, float] = {
        IntentType.BENIGN: 0.1,
        IntentType.EXPLORATION: 0.3,
        IntentType.ENUMERATION: 0.6,
        IntentType.ATTACK_PREP: 0.8,
        IntentType.DATA_EXFILTRATION: 0.85,
        IntentType.REMOTE_COMMAND_EXECUTION: 0.9,
        IntentType.UNKNOWN: 0.4,
    }

    # High-risk file paths (both exact paths and directory prefixes)
    HIGH_RISK_PATHS = [
        "/etc/shadow",
        "/etc/passwd",
        "/etc/password",  # Common typo/variant
        "/etc/sudoers",
        "/etc/",  # All /etc/ files are high risk
        "/root/",
        "/proc/",
        "/sys/",
        "/dev/",
        "/boot/",
        "/usr/bin/",
        "/usr/sbin/",
        "/bin/",
        "/sbin/",
    ]

    # High-risk subprocess commands
    HIGH_RISK_COMMANDS = [
        "wget",
        "curl",
        "nc",
        "netcat",
        "ssh",
        "scp",
        "rsync",
        "sudo",
        "su",
        "chmod",
        "chown",
        "setuid",
        "setgid",
        "bash",
        "sh",
        "python",
        "perl",
        "ruby",
    ]

    # External/external network indicators
    EXTERNAL_INDICATORS = [
        "http://",
        "https://",
        "ftp://",
        "tcp://",
    ]

    @classmethod
    def score_action(cls, action_type: ActionType, event: EventDict) -> float:
        """Compute risk score for an action type with context.

        Args:
            action_type: Type of action.
            event: Normalized event dictionary.

        Returns:
            Risk score between 0.0 and 1.0.
        """
        base_score = cls.ACTION_RISK_SCORES.get(action_type, 0.3)

        # Apply context-based modifiers
        if action_type == ActionType.FILE_READ:
            file_path = event.get("file", "")
            if file_path:
                # Check for high-risk paths (both exact matches and prefix matches)
                if any(file_path.startswith(risk_path) for risk_path in cls.HIGH_RISK_PATHS):
                    base_score = max(base_score, 0.8)
                elif file_path.startswith("/tmp/") or file_path.startswith("/var/tmp/"):
                    base_score = min(base_score, 0.2)

        elif action_type == ActionType.FILE_WRITE:
            file_path = event.get("file", "")
            if file_path:
                # Check for high-risk paths (both exact matches and prefix matches)
                if any(file_path.startswith(risk_path) for risk_path in cls.HIGH_RISK_PATHS):
                    base_score = max(base_score, 0.95)
                # Special handling for critical system files
                if file_path in ["/etc/passwd", "/etc/shadow", "/etc/sudoers", "/etc/password"]:
                    base_score = 1.0  # Maximum risk for critical system files
            mode = event.get("mode", "")
            if "a" in mode or "+" in mode:  # Append or read-write
                base_score = min(base_score + 0.1, 1.0)

        elif action_type == ActionType.SUBPROCESS_EXEC:
            argv = event.get("argv", [])
            cmd = event.get("cmd", "")
            command_str = " ".join(argv) if argv else str(cmd)

            # Check for high-risk commands
            if any(risk_cmd in command_str.lower() for risk_cmd in cls.HIGH_RISK_COMMANDS):
                base_score = max(base_score, 0.9)

            # Check for external network indicators
            if any(indicator in command_str.lower() for indicator in cls.EXTERNAL_INDICATORS):
                base_score = max(base_score, 0.85)

        elif action_type == ActionType.NETWORK_CONNECT:
            host = event.get("host", "")
            # External IPs (not localhost/private)
            if host and host not in ("127.0.0.1", "localhost", "::1", "0.0.0.0"):
                if not host.startswith(("10.", "172.16.", "192.168.", "169.254.")):
                    base_score = max(base_score, 0.8)

        return min(max(base_score, 0.0), 1.0)

    @classmethod
    def score_intent(cls, intent: IntentType) -> float:
        """Compute risk score for an intent type.

        Args:
            intent: Intent type.

        Returns:
            Risk score between 0.0 and 1.0.
        """
        return cls.INTENT_RISK_SCORES.get(intent, 0.4)

    @classmethod
    def compute_combined_risk(
        cls, action_type: ActionType, intent: IntentType, event: EventDict, ml_confidence: float = 0.5
    ) -> float:
        """Compute combined risk score from action, intent, and ML confidence.

        Args:
            action_type: Type of action.
            intent: Intent type.
            event: Normalized event dictionary.
            ml_confidence: ML model confidence (0.0 to 1.0).

        Returns:
            Combined risk score between 0.0 and 1.0.
        """
        action_score = cls.score_action(action_type, event)
        intent_score = cls.score_intent(intent)

        # Weighted combination: 40% action, 40% intent, 20% ML confidence
        combined = (0.4 * action_score) + (0.4 * intent_score) + (0.2 * ml_confidence)

        return min(max(combined, 0.0), 1.0)

    @classmethod
    def risk_level_from_score(cls, score: float) -> RiskLevel:
        """Convert numeric risk score to RiskLevel enum.

        Args:
            score: Risk score between 0.0 and 1.0.

        Returns:
            RiskLevel enum value.
        """
        if score >= 0.8:
            return RiskLevel.CRITICAL
        elif score >= 0.6:
            return RiskLevel.HIGH
        elif score >= 0.4:
            return RiskLevel.MEDIUM
        elif score >= 0.2:
            return RiskLevel.LOW
        else:
            return RiskLevel.SAFE

    @classmethod
    def is_critical_file_write(cls, action_type: ActionType, event: EventDict) -> bool:
        """Check if this is a write operation to a critical system file path.
        
        Args:
            action_type: Type of action.
            event: Normalized event dictionary.
            
        Returns:
            True if this is a FILE_WRITE to a critical path, False otherwise.
        """
        if action_type != ActionType.FILE_WRITE:
            return False
        
        file_path = event.get("file", "")
        if not file_path:
            return False
        
        # Check if file path matches any high-risk path
        return any(file_path.startswith(risk_path) for risk_path in cls.HIGH_RISK_PATHS)

