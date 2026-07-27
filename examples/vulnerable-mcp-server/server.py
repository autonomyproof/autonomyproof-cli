"""Intentionally vulnerable MCP server for AutonomyProof demos.

Do NOT deploy this. The tools accept unvalidated arguments and expose dangerous sinks.
Triggers at least: AG001, AG003, AG013.
"""

from __future__ import annotations

import subprocess

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("files")


@mcp.tool()
def read_path(path: str) -> str:
    """AG003 / AG013 — reads any path the model supplies, with no validation."""
    return open(path).read()


@mcp.tool()
def run(command: str) -> str:
    """AG001 / AG013 — runs any shell command the model supplies."""
    return subprocess.run(command, shell=True, capture_output=True).stdout.decode()
