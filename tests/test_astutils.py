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


def test_resolve_local_value_module_scope_without_lineno_origin() -> None:
    a = _analysis("x = 'http://10.0.0.1'\n")
    # The module node has no lineno, exercising the un-ordered lookup path.
    value = a.resolve_local_value("x", a.tree)
    assert is_constant_str(value)


def test_resolve_local_value_prefers_last_before_use() -> None:
    a = _analysis("x = 'a'\nx = 'b'\nf(x)\n")
    call = a.calls[0]
    value = a.resolve_local_value("x", call)
    assert is_constant_str(value) and value.value == "b"  # type: ignore[attr-defined]


def test_resolve_local_value_falls_back_to_module() -> None:
    a = _analysis("URL = 'http://10.0.0.1'\ndef f():\n    return get(URL)\n")
    call = a.calls[0]
    assert is_constant_str(a.resolve_local_value("URL", call))


def test_resolve_local_value_ignores_annotation_of_other_name() -> None:
    a = _analysis("def f():\n    y: int = 5\n    return get(x)\n")
    call = a.calls[0]
    assert a.resolve_local_value("x", call) is None


def test_is_parameter_covers_vararg_and_kwarg() -> None:
    a = _analysis("def f(a, *args, **kw):\n    return g()\n")
    call = a.calls[0]
    assert a.is_parameter("a", call)
    assert a.is_parameter("args", call)
    assert a.is_parameter("kw", call)
    assert not a.is_parameter("missing", call)


def test_is_parameter_false_at_module_level() -> None:
    a = _analysis("g(x)\n")
    assert not a.is_parameter("x", a.calls[0])


def test_resolve_local_value_does_not_leak_across_functions() -> None:
    # A local in one function must never resolve to an identically-named local in another.
    a = _analysis("def other():\n    u = 'secret'\ndef here():\n    return get(u)\n")
    call = a.calls[0]  # get(u) inside here()
    assert a.resolve_local_value("u", call) is None


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
