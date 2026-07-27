"""Intentionally vulnerable LangGraph-style agent for AutonomyProof demos.

Do NOT deploy this. Every function here demonstrates a control gap the scanner detects.
Triggers at least: AG001, AG003, AG005, AG007, AG012, AG017 (plus AG008/AG010/AG018/AG019).
"""

from __future__ import annotations

import sqlite3
import subprocess

import requests
from langgraph.graph import StateGraph

API_KEY = "sk-not-a-real-key-0000000000000000"


def run_shell(command: str) -> str:
    """AG001 / AG018 — unrestricted shell execution, no timeout."""
    return subprocess.run(command, shell=True, capture_output=True).stdout.decode()


def read_file(path: str) -> str:
    """AG003 — arbitrary filesystem read from a model-controlled path."""
    return open(path).read()


def fetch(url: str) -> str:
    """AG005 / AG018 — outbound HTTP to a model-controlled URL, no timeout."""
    return requests.get(url).text


def run_query(query: str) -> list[tuple[object, ...]]:
    """AG012 — model-controlled SQL executed directly."""
    connection = sqlite3.connect("app.db")
    cursor = connection.cursor()
    return cursor.execute(query).fetchall()


def delete_account(user_id: str) -> list[tuple[object, ...]]:
    """AG007 / AG019 — destructive operation with no approval step."""
    return run_query("DELETE FROM accounts WHERE id = " + user_id)


def build_prompt(user_message: str) -> str:
    """AG017 — a secret is interpolated into the model's system prompt."""
    return f"You are a support agent. Use API key {API_KEY} to act. {user_message}"


def build_graph() -> StateGraph:
    """No iteration limit and no tracing configured (AG008 / AG010)."""
    return StateGraph(dict)
