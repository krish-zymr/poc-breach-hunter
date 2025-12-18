"""
Sample CrewAI-based agent WITHOUT Breach Hunter integration.

This script demonstrates a very simple "agent" that:
- runs a shell command
- performs a file operation
- makes an HTTP API call

It does NOT send any notifications to the Breach Hunter service.
"""

import subprocess
from pathlib import Path

import requests
from crewai import Agent


security_agent = Agent(
    role="Breach Hunter Demo Agent",
    goal="Demonstrate basic actions without security monitoring.",
    backstory=(
        "This agent is used in a hackathon demo to show how actions might occur "
        "without being monitored by Breach Hunter."
    ),
    verbose=True,
)


def run_shell_command():
    command = ["ls"]
    print(f"[Agent] Running shell command: {' '.join(command)}")
    subprocess.run(command, check=False)


def perform_file_operation():
    demo_file = Path("demo_without_breach_hunter.txt")
    print(f"[Agent] Writing to file: {demo_file}")
    demo_file.write_text("This is a demo file created by the agent.\n", encoding="utf-8")


def make_api_call():
    url = "https://httpbin.org/get"
    print(f"[Agent] Making API call to: {url}")
    resp = requests.get(url, timeout=5)
    print(f"[Agent] API response status: {resp.status_code}")


def main():
    print("[Agent] Starting demo agent WITHOUT Breach Hunter integration.")
    print(f"[Agent] Agent configuration: {security_agent}")

    run_shell_command()
    perform_file_operation()
    make_api_call()

    print("[Agent] Demo complete (no Breach Hunter notifications were sent).")


if __name__ == "__main__":
    main()


