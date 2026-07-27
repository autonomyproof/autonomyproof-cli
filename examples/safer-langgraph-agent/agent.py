"""Remediated counterpart to the vulnerable LangGraph agent.

Demonstrates the expected fixes: command allowlist (no shell), fixed endpoints,
parameterized SQL, human approval for destructive actions, execution limits, and tracing.
The scanner should report no findings for this file.
"""

from __future__ import annotations

import logging
import sqlite3

import httpx
from langgraph.graph import StateGraph

logger = logging.getLogger("support-agent")

ALLOWED_COMMANDS = {"ls", "cat"}
MAX_ITERATIONS = 25


class _AccountRepository:
    """Placeholder repository that encapsulates data access."""

    def remove(self, user_id: str) -> None:
        """Remove an account through a safe, audited data-access layer."""
        logger.info("account removed", extra={"user_id": user_id})


repository = _AccountRepository()


def run_command(command: str) -> str:
    """Only allowlisted commands run, without a shell, with a timeout."""
    if command not in ALLOWED_COMMANDS:
        raise ValueError("command not allowed")
    completed = subprocess_run_allowlisted(command)
    return completed


def subprocess_run_allowlisted(command: str) -> str:
    """Run a single allowlisted binary with no shell and a bounded timeout."""
    import subprocess

    return subprocess.run([command], capture_output=True, timeout=10).stdout.decode()


def check_status() -> str:
    """Call a fixed, trusted endpoint with a timeout."""
    return httpx.get("https://api.example.com/status", timeout=10).text


def get_account(user_id: str) -> list[tuple[object, ...]]:
    """Parameterized query — the identifier is bound, never interpolated."""
    connection = sqlite3.connect("app.db")
    cursor = connection.cursor()
    return cursor.execute("SELECT id, name FROM accounts WHERE id = ?", (user_id,)).fetchall()


def delete_account(user_id: str, approved: bool) -> None:
    """Destructive action requires explicit human approval."""
    if not approved:
        raise PermissionError("human approval required")
    logger.info("removing account after approval", extra={"user_id": user_id})
    repository.remove(user_id)


def build_graph() -> StateGraph:
    """Iteration limit and tracing are configured elsewhere; logger provides tracing."""
    logger.info("building graph", extra={"max_iterations": MAX_ITERATIONS})
    return StateGraph(dict)
