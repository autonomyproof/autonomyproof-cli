"""Agent-tool detection: which functions are exposed to the model as callable tools."""

from __future__ import annotations

import ast

from autonomyproof.astutils import FileAnalysis

# Decorator base names that mark a function as an agent/model-callable tool.
_TOOL_DECORATOR_NAMES = {"tool", "function_tool", "kernel_function"}


def _decorator_marks_tool(decorator: ast.expr) -> bool:
    """Return ``True`` if ``decorator`` denotes an agent-tool registration."""
    target = decorator.func if isinstance(decorator, ast.Call) else decorator
    if isinstance(target, ast.Name):
        return target.id in _TOOL_DECORATOR_NAMES
    if isinstance(target, ast.Attribute):
        return target.attr in _TOOL_DECORATOR_NAMES
    return False


def detect_tools(analysis: FileAnalysis) -> dict[str, str]:
    """Map enclosing-function name -> exposed tool name for every tool in ``analysis``.

    The tool name defaults to the function name (the identifier the model calls).
    """
    tools: dict[str, str] = {}
    for node in ast.walk(analysis.tree):
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef) and any(
            _decorator_marks_tool(dec) for dec in node.decorator_list
        ):
            tools[node.name] = node.name
    return tools
