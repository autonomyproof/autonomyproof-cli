"""AST helpers shared by the rule implementations.

The scanner parses each Python file once and hands every rule a :class:`FileAnalysis`,
which pre-computes import resolution, parent links, and the list of call nodes. Rules stay
small and declarative on top of these helpers.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field


class _ImportResolver(ast.NodeVisitor):
    """Map local names to fully-qualified dotted paths from imports."""

    def __init__(self) -> None:
        self.aliases: dict[str, str] = {}

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            local = alias.asname or alias.name.split(".")[0]
            target = alias.name if alias.asname else alias.name.split(".")[0]
            self.aliases[local] = target

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        module = node.module or ""
        for alias in node.names:
            local = alias.asname or alias.name
            self.aliases[local] = f"{module}.{alias.name}" if module else alias.name


@dataclass
class FileAnalysis:
    """Everything a rule needs about one parsed source file."""

    path: str
    source: str
    tree: ast.Module
    lines: list[str] = field(default_factory=list)
    aliases: dict[str, str] = field(default_factory=dict)
    parents: dict[ast.AST, ast.AST] = field(default_factory=dict)
    calls: list[ast.Call] = field(default_factory=list)

    @classmethod
    def build(cls, path: str, source: str) -> FileAnalysis:
        """Parse ``source`` and pre-compute all derived structures."""
        tree = ast.parse(source)
        resolver = _ImportResolver()
        resolver.visit(tree)

        parents: dict[ast.AST, ast.AST] = {}
        calls: list[ast.Call] = []
        for parent in ast.walk(tree):
            for child in ast.iter_child_nodes(parent):
                parents[child] = parent
            if isinstance(parent, ast.Call):
                calls.append(parent)

        return cls(
            path=path,
            source=source,
            tree=tree,
            lines=source.splitlines(),
            aliases=resolver.aliases,
            parents=parents,
            calls=calls,
        )

    def dotted_name(self, node: ast.AST) -> str | None:
        """Return the dotted attribute/name for ``node`` (e.g. ``os.path.join``)."""
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            base = self.dotted_name(node.value)
            return f"{base}.{node.attr}" if base else None
        return None

    def resolve_call(self, call: ast.Call) -> str | None:
        """Return the import-resolved dotted callee name for ``call``.

        ``import subprocess as sp; sp.run(...)`` resolves to ``subprocess.run`` and
        ``from os import system; system(...)`` resolves to ``os.system``.
        """
        raw = self.dotted_name(call.func)
        if raw is None:
            return None
        head, _, rest = raw.partition(".")
        resolved_head = self.aliases.get(head, head)
        return f"{resolved_head}.{rest}" if rest else resolved_head

    def enclosing_function(self, node: ast.AST) -> str:
        """Return the name of the nearest enclosing function, or ``<module>``."""
        current: ast.AST | None = node
        while current is not None:
            if isinstance(current, ast.FunctionDef | ast.AsyncFunctionDef):
                return current.name
            current = self.parents.get(current)
        return "<module>"

    def enclosing_scope(self, node: ast.AST) -> ast.AST:
        """Return the nearest enclosing function or the module for ``node``."""
        current: ast.AST | None = node
        while current is not None:
            if isinstance(current, ast.FunctionDef | ast.AsyncFunctionDef | ast.Module):
                return current
            current = self.parents.get(current)
        return self.tree  # pragma: no cover - every node lives under the module

    def _assignments_to(self, scope: ast.AST, name: str) -> list[ast.expr]:
        values = [
            value
            for stmt in _walk_scope(scope)
            if (value := _assigned_value(stmt, name)) is not None
        ]
        return sorted(values, key=lambda v: getattr(v, "lineno", 0))

    def resolve_local_value(self, name: str, origin: ast.AST) -> ast.expr | None:
        """Return the value last assigned to ``name`` before ``origin`` in its scope.

        Looks in the enclosing function first, then the module. Only plain
        ``name = value`` assignments are followed — intentionally shallow, single
        function, no control-flow reasoning.
        """
        origin_line = getattr(origin, "lineno", None)
        scope = self.enclosing_scope(origin)
        matches = self._assignments_to(scope, name)
        if origin_line is not None:
            before = [v for v in matches if getattr(v, "lineno", 0) <= origin_line]
            matches = before or matches
        if not matches and not isinstance(scope, ast.Module):
            matches = self._assignments_to(self.tree, name)
        return matches[-1] if matches else None

    def is_parameter(self, name: str, origin: ast.AST) -> bool:
        """Whether ``name`` is a parameter of the function enclosing ``origin``."""
        current: ast.AST | None = origin
        while current is not None:
            if isinstance(current, ast.FunctionDef | ast.AsyncFunctionDef):
                args = current.args
                names = {a.arg for a in (*args.posonlyargs, *args.args, *args.kwonlyargs)}
                if args.vararg:
                    names.add(args.vararg.arg)
                if args.kwarg:
                    names.add(args.kwarg.arg)
                return name in names
            current = self.parents.get(current)
        return False

    def snippet(self, node: ast.AST) -> str:
        """Return the source text of ``node`` (single line via ast.get_source_segment)."""
        segment = ast.get_source_segment(self.source, node)
        if segment is not None:
            return segment.replace("\n", " ").strip()
        lineno = getattr(node, "lineno", 0)
        if 1 <= lineno <= len(self.lines):
            return self.lines[lineno - 1].strip()
        return ""  # pragma: no cover - defensive


def _walk_scope(scope: ast.AST) -> list[ast.AST]:
    """Yield nodes within ``scope``, descending into control flow but not nested scopes.

    Crucially this does NOT descend into nested function/class/lambda bodies, so a
    variable in one function never resolves to an identically-named local in another.
    """
    found: list[ast.AST] = []
    stack = list(ast.iter_child_nodes(scope))
    while stack:
        node = stack.pop()
        found.append(node)
        if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef | ast.Lambda):
            stack.extend(ast.iter_child_nodes(node))
    return found


def _assigned_value(stmt: ast.AST, name: str) -> ast.expr | None:
    """Return the value ``stmt`` assigns to ``name``, or ``None`` if it does not."""
    if isinstance(stmt, ast.Assign) and any(
        isinstance(t, ast.Name) and t.id == name for t in stmt.targets
    ):
        return stmt.value
    if isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
        return stmt.value if stmt.target.id == name else None
    return None


def keyword(call: ast.Call, name: str) -> ast.expr | None:
    """Return the value expression of keyword ``name`` on ``call``, if present."""
    for kw in call.keywords:
        if kw.arg == name:
            return kw.value
    return None


def is_true_literal(node: ast.expr | None) -> bool:
    """Return ``True`` if ``node`` is the literal ``True``."""
    return isinstance(node, ast.Constant) and node.value is True


def is_constant_str(node: ast.expr | None) -> bool:
    """Return ``True`` if ``node`` is a plain string literal."""
    return isinstance(node, ast.Constant) and isinstance(node.value, str)


def is_model_controlled(node: ast.expr | None) -> bool:
    """Heuristic: an argument is model-controlled if it is not a constant literal.

    Variables, f-strings, concatenations, calls, subscripts, and attribute reads are all
    treated as potentially agent/model-influenced. Plain literals are treated as safe.
    This is intentionally conservative — the security-relevant default.
    """
    if node is None:
        return False
    return not isinstance(node, ast.Constant)


def string_literals(node: ast.AST) -> list[str]:
    """Collect every string constant contained within ``node``."""
    return [
        child.value
        for child in ast.walk(node)
        if isinstance(child, ast.Constant) and isinstance(child.value, str)
    ]


def function_defs(tree: ast.AST) -> dict[str, ast.FunctionDef | ast.AsyncFunctionDef]:
    """Map each same-file function name to its definition (first definition wins).

    This is the minimal call graph for cross-function taint: it lets a rule resolve a
    plain ``helper(x)`` call to the ``def helper`` in the same file and reason about what
    that helper returns.
    """
    defs: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            defs.setdefault(node.name, node)
    return defs


def return_values(func: ast.FunctionDef | ast.AsyncFunctionDef) -> list[ast.expr]:
    """Return the value expressions of ``func``'s own ``return`` statements.

    Scope-respecting: it does not descend into nested functions, so a return inside a
    closure defined within ``func`` is not attributed to ``func``.
    """
    return [
        node.value
        for node in _walk_scope(func)
        if isinstance(node, ast.Return) and node.value is not None
    ]
