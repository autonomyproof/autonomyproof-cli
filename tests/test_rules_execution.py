"""Tests for execution rules (AG001, AG002, AG019)."""

from __future__ import annotations

from autonomyproof.models import Severity
from autonomyproof.rules.execution import (
    DestructiveCommandRule,
    DynamicCodeExecutionRule,
    ShellExecutionRule,
)
from helpers import run_rule


def test_ag001_os_system() -> None:
    findings = run_rule(ShellExecutionRule(), "import os\nos.system(cmd)\n")
    assert findings[0].ruleId == "AG001"
    assert findings[0].severity is Severity.CRITICAL


def test_ag001_os_popen() -> None:
    assert run_rule(ShellExecutionRule(), "import os\nos.popen(cmd)\n")


def test_ag001_subprocess_shell_true() -> None:
    code = "import subprocess\nsubprocess.run(cmd, shell=True)\n"
    assert run_rule(ShellExecutionRule(), code)


def test_ag001_subprocess_without_shell_is_clean() -> None:
    code = "import subprocess\nsubprocess.run([cmd], shell=False)\n"
    assert run_rule(ShellExecutionRule(), code) == []


def test_ag001_unrelated_call_is_clean() -> None:
    assert run_rule(ShellExecutionRule(), "print(x)\n") == []


def test_ag002_eval_exec_compile() -> None:
    for builtin in ("eval", "exec", "compile"):
        assert run_rule(DynamicCodeExecutionRule(), f"{builtin}(src)\n")


def test_ag002_clean() -> None:
    assert run_rule(DynamicCodeExecutionRule(), "json.loads(src)\n") == []


def test_ag019_detects_destructive_string() -> None:
    findings = run_rule(DestructiveCommandRule(), "cmd = 'rm -rf /data'\n")
    assert findings[0].ruleId == "AG019"


def test_ag019_only_one_finding_per_string() -> None:
    findings = run_rule(DestructiveCommandRule(), "cmd = 'sudo rm -rf /'\n")
    assert len(findings) == 1


def test_ag019_ignores_non_string_and_clean_string() -> None:
    assert run_rule(DestructiveCommandRule(), "x = 5\ny = 'hello world'\n") == []
