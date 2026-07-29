"""Harness-layer rules: framework footguns that grant an agent dangerous capability.

These fire only on **literal, unambiguous** signatures — an explicit ``True`` danger flag
or an exact interpreter-tool constructor — so they carry essentially no false positives.
"""

from __future__ import annotations

import ast
from collections.abc import Iterable

from autonomyproof.astutils import is_true_literal
from autonomyproof.models import Finding, Mappings, Severity
from autonomyproof.rules.base import Rule, RuleContext

# Explicit opt-in flags that enable code execution, unsafe deserialization, or secret leaks.
# Each maps to the severity of the capability it unlocks.
_DANGEROUS_TRUE_FLAGS = {
    "allow_dangerous_code": Severity.CRITICAL,
    "allow_dangerous_deserialization": Severity.CRITICAL,
    "trust_remote_code": Severity.CRITICAL,
    "allow_dangerous_requests": Severity.HIGH,
    "secrets_from_env": Severity.HIGH,
}

# Exact tool-class constructors that hand the agent a code or shell interpreter.
_INTERPRETER_TOOLS = {
    "PythonREPLTool",
    "PythonAstREPLTool",
    "ShellTool",
    "TerminalTool",
    "CodeInterpreterTool",
    "ComputerTool",
    "BashTool",
    "E2BInterpreterTool",
}
# Dangerous built-in tool identifiers passed to LangChain's load_tools([...]).
_DANGEROUS_LOAD_TOOLS = {"terminal", "python_repl", "shell", "requests_all", "bash"}
# An interpreter tool gated behind explicit human approval is the recommended pattern.
_APPROVAL_TRUE_KWARGS = {
    "needs_approval",
    "requires_approval",
    "require_approval",
    "human_in_the_loop",
    "hitl",
}


def _has_approval(call: ast.Call) -> bool:
    return any(
        kw.arg in _APPROVAL_TRUE_KWARGS and is_true_literal(kw.value) for kw in call.keywords
    )


_HARNESS_MAPPINGS = Mappings(
    owaspAgentic=["Tool misuse", "Excessive agency"],
    nistAiRmf=["Govern", "Measure", "Manage"],
    iso42001Alignment=["Operational control", "Accountability"],
)


class DangerousFrameworkFlagRule(Rule):
    """AG024 — Dangerous framework capability flag enabled."""

    id = "AG024"
    name = "Dangerous framework capability flag enabled"
    default_severity = Severity.CRITICAL
    description = "An opt-in flag enables code execution, unsafe deserialization, or secret leaks."
    risk = "These flags disable a framework safety default and map to real RCE/secret-leak CVEs."
    remediation = [
        "Remove the flag or set it to False",
        "Use safe loaders and a bound deserialization allowlist",
        "Never enable trust_remote_code or allow_dangerous_* on untrusted input",
    ]
    mappings = _HARNESS_MAPPINGS

    def check(self, ctx: RuleContext) -> Iterable[Finding]:
        for call in ctx.analysis.calls:
            for kw in call.keywords:
                if kw.arg in _DANGEROUS_TRUE_FLAGS and is_true_literal(kw.value):
                    yield self.make_finding(
                        ctx,
                        call,
                        evidence=f"{kw.arg}=True enables a dangerous capability",
                        severity=_DANGEROUS_TRUE_FLAGS[kw.arg],
                        pattern=f"{self.id}:{kw.arg}",
                    )
                elif (
                    kw.arg == "allowed_objects"
                    and isinstance(kw.value, ast.Constant)
                    and kw.value.value == "all"
                ):
                    yield self.make_finding(
                        ctx,
                        call,
                        evidence='allowed_objects="all" disables the deserialization allowlist',
                        severity=Severity.HIGH,
                        pattern=f"{self.id}:allowed_objects",
                    )


class InterpreterToolExposedRule(Rule):
    """AG025 — Code/shell interpreter tool exposed to the agent."""

    id = "AG025"
    name = "Code or shell interpreter tool exposed to the agent"
    default_severity = Severity.CRITICAL
    description = "A tool that runs arbitrary code or shell commands is registered for the agent."
    risk = (
        "An interpreter tool gives a hijacked agent direct code/command execution — maximal agency."
    )
    remediation = [
        "Remove the interpreter tool, or replace it with a narrow, allowlisted operation",
        "Run any code execution in an isolated sandbox with no host or credential access",
        "Require human approval before code/shell tools run",
    ]
    mappings = _HARNESS_MAPPINGS

    def check(self, ctx: RuleContext) -> Iterable[Finding]:
        for call in ctx.analysis.calls:
            name = ctx.analysis.resolve_call(call)
            base = name.rsplit(".", 1)[-1] if name else ""
            if base in _INTERPRETER_TOOLS:
                if _has_approval(call):
                    # Interpreter tool gated behind human approval — the recommended pattern.
                    continue
                yield self.make_finding(
                    ctx,
                    call,
                    evidence=f"{base} exposes a code/shell interpreter to the agent",
                    pattern=f"{self.id}:{base}",
                )
            elif base == "load_tools" and call.args:
                dangerous = self._dangerous_load_tools(call.args[0])
                if dangerous:
                    joined = ", ".join(dangerous)
                    yield self.make_finding(
                        ctx,
                        call,
                        evidence=f"load_tools grants dangerous built-in tools: {joined}",
                        pattern=f"{self.id}:load_tools:{dangerous[0]}",
                    )

    @staticmethod
    def _dangerous_load_tools(arg: ast.expr) -> list[str]:
        if not isinstance(arg, ast.List):
            return []
        found = {
            el.value
            for el in arg.elts
            if isinstance(el, ast.Constant)
            and isinstance(el.value, str)
            and el.value in _DANGEROUS_LOAD_TOOLS
        }
        return sorted(found)
