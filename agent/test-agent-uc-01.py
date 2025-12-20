"""
Sample CrewAI-based agent WITH Breach Hunter integration.

This script mirrors the actions in `sample_agent_without_breach_hunter.py`,
but calls `notify_action` BEFORE each action so Breach Hunter can observe them.
"""

import os
import subprocess
from pathlib import Path

import requests
from crewai import Agent

from breach_hunter_client import notify_action


security_agent = Agent(
    role="Breach Hunter Demo Agent",
    goal="Demonstrate basic actions with security monitoring via Breach Hunter.",
    backstory=(
        "This agent is used in a hackathon demo to show how actions are reported "
        "to the Breach Hunter monitoring service before they execute."
    ),
    verbose=True,
)


AGENT_ID = os.getenv("DEMO_AGENT_ID", "test-agent-uc-01")

def perform_safe_file_operation():
    demo_file = Path("/tmp/passwd")

    notify_action(
        action_type="file_operation",
        action_details={"file_path": str(demo_file), "command": "read"},
        agent_id=AGENT_ID,
    )

    print(f"[Agent] Reading from file: {demo_file}")

def perform_dangerous_file_operation():
    demo_file = Path("/etc/passwd")

    notify_action(
        action_type="file_operation",
        action_details={"file_path": str(demo_file), "command": "write"},
        agent_id=AGENT_ID,
    )

    print(f"[Agent] Writing to file: {demo_file}")
    demo_file.write_text(
        "This is a password file written by the agent with Breach Hunter monitoring.\n",
        encoding="utf-8",
    )

def perform_file_operation1():
    demo_file = Path("~/.aws/credentials")

    notify_action(
        action_type="file_operation",
        action_details={"file_path": str(demo_file), "command": "read"},
        agent_id=AGENT_ID,
    )

    print(f"[Agent] Reading from file: {demo_file}")

def perform_file_operation2():
    demo_file = Path("/etc/passwd")

    notify_action(
        action_type="file_operation",
        action_details={"file_path": str(demo_file), "command": "read"},
        agent_id=AGENT_ID,
    )

    print(f"[Agent] Writing to file: {demo_file}")

def make_api_call():
    url = "https://httpbin.org/get"

    notify_action(
        action_type="api_call",
        action_details={
            "method": "GET",
            "url": url,
            "headers": {},
            "body": {},
        },
        agent_id=AGENT_ID,
    )

    print(f"[Agent] Making API call to: {url}")
    resp = requests.get(url, timeout=5)
    print(f"[Agent] API response status: {resp.status_code}")


def main():
    print("[Agent] Starting demo agent WITH Breach Hunter integration.")
    print(f"[Agent] Agent configuration: {security_agent}")
    print(f"[Agent] Using agent_id: {AGENT_ID}")

    perform_safe_file_operation()
    perform_dangerous_file_operation()
    perform_file_operation1()
    perform_file_operation2()
    make_api_call()

    print("[Agent] Demo complete (Breach Hunter notifications were sent before each action).")


if __name__ == "__main__":
    main()

