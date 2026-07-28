"""Agent-tool detection: which functions are exposed to the model as callable tools."""

from __future__ import annotations

import ast

from autonomyproof.astutils import FileAnalysis, keyword

# Decorator base names that mark a function as an agent/model-callable tool.
_TOOL_DECORATOR_NAMES = {"tool", "function_tool", "kernel_function"}
# Constructor/factory callees that wrap a plain function as a tool.
_TOOL_FACTORY_NAMES = {"Tool", "StructuredTool", "FunctionTool", "from_function"}
# Keyword arguments that carry the wrapped function on those factories.
_TOOL_FUNC_KWARGS = ("func", "function", "coroutine")


def _decorator_marks_tool(decorator: ast.expr) -> bool:
    """Return ``True`` if ``decorator`` denotes an agent-tool registration."""
    target = decorator.func if isinstance(decorator, ast.Call) else decorator
    if isinstance(target, ast.Name):
        return target.id in _TOOL_DECORATOR_NAMES
    if isinstance(target, ast.Attribute):
        return target.attr in _TOOL_DECORATOR_NAMES
    return False


def _registered_tool_names(analysis: FileAnalysis, call: ast.Call) -> set[str]:
    """Function names exposed as tools via list/object registration in ``call``.

    Covers ``tools=[fn, ...]`` on any constructor, ``Tool(func=fn)`` /
    ``FunctionTool(function=fn)``, and ``StructuredTool.from_function(fn)``.
    """
    names: set[str] = set()
    tools_kw = keyword(call, "tools")
    if isinstance(tools_kw, ast.List):
        names.update(el.id for el in tools_kw.elts if isinstance(el, ast.Name))

    callee = analysis.resolve_call(call) or ""
    base = callee.rsplit(".", 1)[-1]
    if base in _TOOL_FACTORY_NAMES:
        for kwarg in _TOOL_FUNC_KWARGS:
            value = keyword(call, kwarg)
            if isinstance(value, ast.Name):
                names.add(value.id)
        if base == "from_function" and call.args and isinstance(call.args[0], ast.Name):
            names.add(call.args[0].id)
    return names


def detect_tools(analysis: FileAnalysis) -> dict[str, str]:
    """Map enclosing-function name -> exposed tool name for every tool in ``analysis``.

    Detects both decorator-style tools (``@tool``) and functions registered as tools
    via lists or wrapper objects. The tool name defaults to the function name (the
    identifier the model calls).
    """
    tools: dict[str, str] = {}
    for node in ast.walk(analysis.tree):
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef) and any(
            _decorator_marks_tool(dec) for dec in node.decorator_list
        ):
            tools[node.name] = node.name
    for call in analysis.calls:
        for name in _registered_tool_names(analysis, call):
            tools.setdefault(name, name)
    return tools
