"""Shared intra-function source resolution used across rules.

Deliberately shallow: single function, plain ``name = value`` assignments, no
control-flow reasoning. It answers two questions a rule needs about an argument:
where a value ultimately comes from, and the string literals it may carry.
"""

from __future__ import annotations

import ast

from autonomyproof.astutils import string_literals
from autonomyproof.rules.base import RuleContext

# Root identifiers that denote trusted, non-model-controlled configuration.
_CONFIG_ROOTS = {"settings", "config", "cfg", "conf", "constants", "secrets", "env"}


def root_expr(ctx: RuleContext, node: ast.expr, origin: ast.AST, depth: int = 0) -> ast.expr:
    """Follow simple ``name = value`` chains to the expression a value comes from."""
    if isinstance(node, ast.Name) and depth < 6:
        value = ctx.analysis.resolve_local_value(node.id, origin)
        if value is not None and value is not node:
            return root_expr(ctx, value, origin, depth + 1)
    return node


def _config_rooted(node: ast.expr) -> bool:
    """Whether ``node`` reads from trusted config (settings.X, os.environ, a CONSTANT)."""
    attrs: list[str] = []
    current: ast.expr = node
    while True:
        if isinstance(current, ast.Attribute):
            attrs.append(current.attr.lower())
            current = current.value
        elif isinstance(current, ast.Subscript):
            current = current.value
        elif isinstance(current, ast.Call):
            current = current.func
        else:
            break
    root_name = current.id if isinstance(current, ast.Name) else ""
    if any(attr in {"environ", "getenv"} for attr in attrs):
        return True
    if root_name.lower() in _CONFIG_ROOTS:
        return True
    return root_name.isupper() and len(root_name) > 1


def classify_source(ctx: RuleContext, origin: ast.AST, expr: ast.expr) -> str:
    """Classify a model-controlled value as ``safe``, ``tainted``, or ``unknown``.

    ``safe`` = provably a hardcoded constant or trusted config; ``tainted`` = a
    function/tool parameter (model/attacker influenced); ``unknown`` otherwise.
    """
    root = root_expr(ctx, expr, origin)
    if isinstance(root, ast.Constant) or _config_rooted(root):
        return "safe"
    if isinstance(root, ast.Name) and ctx.analysis.is_parameter(root.id, origin):
        return "tainted"
    return "unknown"


def resolved_strings(ctx: RuleContext, call: ast.Call) -> list[str]:
    """String literals in ``call`` plus those from any name it uses, resolved locally."""
    strings = list(string_literals(call))
    for node in ast.walk(call):
        if isinstance(node, ast.Name):
            value = ctx.analysis.resolve_local_value(node.id, call)
            if value is not None:
                strings.extend(string_literals(value))
    return strings
