"""Tests for the AST helpers."""

from __future__ import annotations

import ast

from autonomyproof.astutils import (
    FileAnalysis,
    is_constant_str,
    is_model_controlled,
    is_true_literal,
    keyword,
    string_literals,
)


def _analysis(code: str) -> FileAnalysis:
    return FileAnalysis.build("m.py", code)


def test_resolve_call_with_import_alias() -> None:
    a = _analysis("import subprocess as sp\nsp.run(x)\n")
    assert a.resolve_call(a.calls[0]) == "subprocess.run"


def test_resolve_call_with_from_import() -> None:
    a = _analysis("from os import system\nsystem(x)\n")
    assert a.resolve_call(a.calls[0]) == "os.system"


def test_resolve_call_with_dotted_import() -> None:
    a = _analysis("import os\nos.path.join(x)\n")
    assert a.resolve_call(a.calls[0]) == "os.path.join"


def test_resolve_call_builtin() -> None:
    a = _analysis("eval(x)\n")
    assert a.resolve_call(a.calls[0]) == "eval"


def test_resolve_call_unresolvable_returns_none() -> None:
    a = _analysis("data[0](x)\n")
    assert a.resolve_call(a.calls[0]) is None


def test_dotted_name_variants() -> None:
    a = _analysis("a.b.c\n")
    expr = a.tree.body[0].value  # type: ignore[attr-defined]
    assert a.dotted_name(expr) == "a.b.c"
    assert a.dotted_name(ast.Constant(value=1)) is None


def test_enclosing_function_levels() -> None:
    code = (
        "def outer():\n    def inner():\n        y = 1\n        return y\n    return inner\nz = 2\n"
    )
    a = _analysis(code)
    inner_assign = next(
        n
        for n in ast.walk(a.tree)
        if isinstance(n, ast.Assign) and isinstance(n.value, ast.Constant) and n.value.value == 1
    )
    assert a.enclosing_function(inner_assign) == "inner"
    module_assign = next(
        n
        for n in ast.walk(a.tree)
        if isinstance(n, ast.Assign) and isinstance(n.value, ast.Constant) and n.value.value == 2
    )
    assert a.enclosing_function(module_assign) == "<module>"


def test_snippet_from_source() -> None:
    a = _analysis("value = compute(1, 2)\n")
    call = a.calls[0]
    assert a.snippet(call) == "compute(1, 2)"


def test_snippet_fallback_to_line() -> None:
    a = _analysis("alpha = 1\nbeta = 2\n")
    node = ast.Constant(value=99)
    node.lineno = 2  # not present in source -> get_source_segment returns None
    assert a.snippet(node) == "beta = 2"


def test_keyword_and_literals() -> None:
    a = _analysis("f(a, mode='w', shell=True)\n")
    call = a.calls[0]
    assert is_true_literal(keyword(call, "shell"))
    assert is_constant_str(keyword(call, "mode"))
    assert keyword(call, "missing") is None


def test_model_controlled() -> None:
    a = _analysis("f(var, 'literal')\n")
    call = a.calls[0]
    assert is_model_controlled(call.args[0]) is True
    assert is_model_controlled(call.args[1]) is False
    assert is_model_controlled(None) is False


def test_string_literals_collects_all() -> None:
    a = _analysis("f('x', ['y', 'z'], 1)\n")
    assert set(string_literals(a.calls[0])) == {"x", "y", "z"}
