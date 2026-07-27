"""Agent-framework detection from imports and dependency manifests (PRD §8.2)."""

from __future__ import annotations

import ast
from collections.abc import Iterable

from autonomyproof.astutils import FileAnalysis

# Map an import/package prefix to the canonical framework name.
_FRAMEWORK_PREFIXES: dict[str, str] = {
    "langgraph": "LangGraph",
    "langchain": "LangChain",
    "crewai": "CrewAI",
    "autogen": "AutoGen",
    "autogen_agentchat": "AutoGen",
    "pydantic_ai": "PydanticAI",
    "semantic_kernel": "Semantic Kernel",
    "mcp": "MCP",
    "agents": "OpenAI Agents SDK",
    "openai_agents": "OpenAI Agents SDK",
}


def _prefix_to_framework(name: str) -> str | None:
    head = name.split(".")[0].replace("-", "_")
    return _FRAMEWORK_PREFIXES.get(head)


def detect_frameworks(
    analyses: Iterable[FileAnalysis],
    dependency_names: Iterable[str],
) -> list[str]:
    """Return the sorted set of frameworks referenced by imports or dependencies."""
    found: set[str] = set()

    for analysis in analyses:
        for node in ast.walk(analysis.tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    framework = _prefix_to_framework(alias.name)
                    if framework:
                        found.add(framework)
            elif isinstance(node, ast.ImportFrom) and node.module:
                framework = _prefix_to_framework(node.module)
                if framework:
                    found.add(framework)

    for dependency in dependency_names:
        framework = _prefix_to_framework(dependency)
        if framework:
            found.add(framework)

    return sorted(found)


def primary_framework(frameworks: list[str]) -> str | None:
    """Pick the most specific framework to attribute findings to."""
    priority = [
        "LangGraph",
        "CrewAI",
        "AutoGen",
        "PydanticAI",
        "Semantic Kernel",
        "OpenAI Agents SDK",
        "MCP",
        "LangChain",
    ]
    for name in priority:
        if name in frameworks:
            return name
    return None
