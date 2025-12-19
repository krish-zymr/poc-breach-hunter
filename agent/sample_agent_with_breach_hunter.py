"""
Sample CrewAI-based agent WITH Breach Hunter integration.

This script demonstrates various actions that trigger different analysis modes:
- Rule-based analysis (BLOCK): CRITICAL operations like password file writes
- Full LLM analysis: Normal operations that need AI evaluation
"""

import os
import subprocess
import time
from pathlib import Path

import requests
from crewai import Agent

from breach_hunter_client import notify_action


security_agent = Agent(
    role="Breach Hunter Demo Agent",
    goal="Demonstrate various actions with security monitoring via Breach Hunter.",
    backstory=(
        "This agent is used in a hackathon demo to show how actions are reported "
        "to the Breach Hunter monitoring service before they execute. It performs "
        "both safe and potentially dangerous operations to demonstrate the rule engine."
    ),
    verbose=True,
)


AGENT_ID = os.getenv("DEMO_AGENT_ID", "demo-agent-001")


def safe_notify_action(action_type, action_details, description):
    """Helper function to safely notify action with error handling and delay"""
    try:
        notify_action(
            action_type=action_type,
            action_details=action_details,
            agent_id=AGENT_ID,
        )
        print(f"[Agent] {description}")
        time.sleep(0.3)  # Small delay to ensure notification is processed
        return True
    except Exception as e:
        print(f"[Agent] Error in {description}: {e}")
        import traceback
        traceback.print_exc()
        return False


# ============================================================================
# RULE-BASED ANALYSIS ACTIONS (Should be BLOCKED - CRITICAL)
# ============================================================================

def attempt_password_file_write():
    """CRITICAL: Attempt to write to /etc/passwd - Should be BLOCKED by rule engine"""
    return safe_notify_action(
        "file_operation",
        {"file_path": "/etc/passwd", "command": "write"},
        "Attempting to write to /etc/passwd (CRITICAL - should be BLOCKED)"
    )


def attempt_shadow_file_write():
    """CRITICAL: Attempt to write to /etc/shadow - Should be BLOCKED by rule engine"""
    return safe_notify_action(
        "file_operation",
        {"file_path": "/etc/shadow", "command": "append"},
        "Attempting to append to /etc/shadow (CRITICAL - should be BLOCKED)"
    )


def attempt_ssh_key_access():
    """CRITICAL: Attempt to access SSH private key - Should be BLOCKED by rule engine"""
    return safe_notify_action(
        "file_operation",
        {"file_path": "~/.ssh/id_rsa", "command": "read"},
        "Attempting to read SSH private key (CRITICAL - should be BLOCKED)"
    )


def attempt_pem_file_access():
    """CRITICAL: Attempt to access .pem certificate - Should be BLOCKED by rule engine"""
    return safe_notify_action(
        "file_operation",
        {"file_path": "/tmp/secret.pem", "command": "read"},
        "Attempting to read .pem certificate file (CRITICAL - should be BLOCKED)"
    )


def attempt_authorized_keys_write():
    """CRITICAL: Attempt to write to authorized_keys - Should be BLOCKED by rule engine"""
    return safe_notify_action(
        "file_operation",
        {"file_path": "/root/.ssh/authorized_keys", "command": "write"},
        "Attempting to write to authorized_keys (CRITICAL - should be BLOCKED)"
    )


def attempt_aws_credentials_access():
    """CRITICAL: Attempt to access AWS credentials - Should be BLOCKED by rule engine"""
    return safe_notify_action(
        "file_operation",
        {"file_path": "~/.aws/credentials", "command": "read"},
        "Attempting to read AWS credentials (CRITICAL - should be BLOCKED)"
    )


# ============================================================================
# RULE-BASED ANALYSIS ACTIONS (Should be BLOCKED - HIGH risk score)
# ============================================================================

def attempt_permission_change():
    """HIGH: Attempt to change permissions on sensitive file - Should be BLOCKED if risk >= 80"""
    return safe_notify_action(
        "command_execution",
        {"command": "chmod 777 /etc/passwd"},
        "Attempting to change permissions on /etc/passwd (HIGH - should be BLOCKED)"
    )


def attempt_path_traversal():
    """HIGH: Attempt path traversal - Should be BLOCKED if risk >= 80"""
    return safe_notify_action(
        "file_operation",
        {"file_path": "../../etc/passwd", "command": "read"},
        "Attempting path traversal attack (HIGH - should be BLOCKED)"
    )


# ============================================================================
# FULL LLM ANALYSIS ACTIONS (Should go to OpenAI)
# ============================================================================

def safe_file_read():
    """ALLOW: Safe file read operation - Should go to LLM for analysis"""
    return safe_notify_action(
        "file_operation",
        {"file_path": "/tmp/demo.txt", "command": "read"},
        "Reading safe file (ALLOW - should go to LLM)"
    )


def safe_file_write():
    """ALLOW: Safe file write operation - Should go to LLM for analysis"""
    demo_file = Path("demo_output.txt")
    result = safe_notify_action(
        "file_operation",
        {"file_path": str(demo_file), "command": "write"},
        f"Writing to safe file: {demo_file} (ALLOW - should go to LLM)"
    )
    try:
        demo_file.write_text(
            "This is a safe demo file created by the agent.\n",
            encoding="utf-8",
        )
    except Exception as e:
        print(f"[Agent] File write failed (notification was sent): {e}")
    return result


def safe_file_delete():
    """ALLOW: Safe file delete operation - Should go to LLM for analysis"""
    return safe_notify_action(
        "file_operation",
        {"file_path": "/tmp/temp_file.txt", "command": "delete"},
        "Deleting temporary file (ALLOW - should go to LLM)"
    )


def make_api_call():
    """ALLOW: API call to external service - Should go to LLM for analysis"""
    url = "https://httpbin.org/get"
    result = safe_notify_action(
        "api_call",
        {
            "method": "GET",
            "url": url,
            "headers": {"User-Agent": "BreachHunter-Demo"},
            "body": {},
        },
        f"Making API call to: {url} (ALLOW - should go to LLM)"
    )
    try:
        resp = requests.get(url, timeout=5)
        print(f"[Agent] API response status: {resp.status_code}")
    except Exception as e:
        print(f"[Agent] API call failed: {e}")
    return result


def make_post_api_call():
    """ALLOW: POST API call - Should go to LLM for analysis"""
    url = "https://httpbin.org/post"
    return safe_notify_action(
        "api_call",
        {
            "method": "POST",
            "url": url,
            "headers": {"Content-Type": "application/json"},
            "body": {"action": "demo", "data": "test"},
        },
        f"Making POST API call to: {url} (ALLOW - should go to LLM)"
    )


def run_safe_shell_command():
    """ALLOW: Safe shell command - Should go to LLM for analysis"""
    command = ["ls", "-la"]
    return safe_notify_action(
        "command_execution",
        {"command": " ".join(command)},
        f"Running safe shell command: {' '.join(command)} (ALLOW - should go to LLM)"
    )


# ============================================================================
# UNCERTAIN ACTIONS (Should go to LLM - Missing fields or unknown operations)
# ============================================================================

def unknown_file_operation():
    """UNCERTAIN: Unknown file operation command - Should go to LLM"""
    return safe_notify_action(
        "file_operation",
        {"file_path": "/tmp/test.txt", "command": "encrypt"},
        "Unknown file operation command (UNCERTAIN - should go to LLM)"
    )


def file_operation_missing_fields():
    """UNCERTAIN: File operation with missing fields - Should go to LLM"""
    return safe_notify_action(
        "file_operation",
        {"command": "write"},  # Missing file_path
        "File operation with missing file_path (UNCERTAIN - should go to LLM)"
    )


def main():
    print("=" * 80)
    print("[Agent] Starting comprehensive Breach Hunter demo agent")
    print(f"[Agent] Agent configuration: {security_agent}")
    print(f"[Agent] Using agent_id: {AGENT_ID}")
    print("=" * 80)
    print()

    actions_executed = 0
    actions_failed = 0
    
    try:
        # Rule-based BLOCK actions (CRITICAL)
        print("\n[Category 1] CRITICAL Operations (Rule-based BLOCK - No LLM):")
        print("-" * 80)
        if attempt_password_file_write():
            actions_executed += 1
        else:
            actions_failed += 1
        if attempt_shadow_file_write():
            actions_executed += 1
        else:
            actions_failed += 1
        if attempt_ssh_key_access():
            actions_executed += 1
        else:
            actions_failed += 1
        if attempt_pem_file_access():
            actions_executed += 1
        else:
            actions_failed += 1
        if attempt_authorized_keys_write():
            actions_executed += 1
        else:
            actions_failed += 1
        if attempt_aws_credentials_access():
            actions_executed += 1
        else:
            actions_failed += 1

        print("\n[Category 2] HIGH Risk Operations (Rule-based BLOCK if risk >= 80):")
        print("-" * 80)
        if attempt_permission_change():
            actions_executed += 1
        else:
            actions_failed += 1
        if attempt_path_traversal():
            actions_executed += 1
        else:
            actions_failed += 1

        print("\n[Category 3] Safe Operations (Full LLM Analysis):")
        print("-" * 80)
        if safe_file_read():
            actions_executed += 1
        else:
            actions_failed += 1
        if safe_file_write():
            actions_executed += 1
        else:
            actions_failed += 1
        if safe_file_delete():
            actions_executed += 1
        else:
            actions_failed += 1
        if make_api_call():
            actions_executed += 1
        else:
            actions_failed += 1
        if make_post_api_call():
            actions_executed += 1
        else:
            actions_failed += 1
        if run_safe_shell_command():
            actions_executed += 1
        else:
            actions_failed += 1

        print("\n[Category 4] UNCERTAIN Operations (Full LLM Analysis):")
        print("-" * 80)
        if unknown_file_operation():
            actions_executed += 1
        else:
            actions_failed += 1
        if file_operation_missing_fields():
            actions_executed += 1
        else:
            actions_failed += 1

        print("\n" + "=" * 80)
        print(f"[Agent] Demo complete!")
        print(f"[Agent] Successfully sent {actions_executed} action notifications")
        if actions_failed > 0:
            print(f"[Agent] Failed to send {actions_failed} action notifications")
        print(f"[Agent] Total actions attempted: {actions_executed + actions_failed}")
        print("[Agent] Check the Breach Hunter dashboard to see:")
        print("  - Rule-based analysis for CRITICAL operations")
        print("  - Full LLM analysis for safe/uncertain operations")
        print("=" * 80)
        
        # Keep container running
        print("\n[Agent] Keeping container alive. Press Ctrl+C to exit.")
        while True:
            time.sleep(60)
    except KeyboardInterrupt:
        print("\n[Agent] Shutting down...")
    except Exception as e:
        print(f"\n[Agent] Error in main: {e}")
        import traceback
        traceback.print_exc()
        print(f"[Agent] Executed {actions_executed} actions before error.")


if __name__ == "__main__":
    main()


