"""Execution-related rules: shell, dynamic code, and destructive commands."""

from __future__ import annotations

import ast
from collections.abc import Iterable

from autonomyproof.astutils import is_true_literal, keyword
from autonomyproof.models import Finding, Mappings, Severity
from autonomyproof.rules.base import Rule, RuleContext

_SUBPROCESS_SHELL = {
    "subprocess.run",
    "subprocess.Popen",
    "subprocess.call",
    "subprocess.check_call",
    "subprocess.check_output",
}
_OS_SHELL = {"os.system", "os.popen"}

_DESTRUCTIVE_MARKERS = [
    "rm -rf",
    "git push --force",
    "git push -f",
    "git reset --hard",
    "drop database",
    "delete from",
    "kubectl delete",
    "terraform destroy",
    "npm publish",
    "docker --privileged",
    "--privileged",
    "sudo ",
]


class ShellExecutionRule(Rule):
    """AG001 — Unrestricted shell execution exposed to agent."""

    id = "AG001"
    name = "Unrestricted shell execution exposed to agent"
    default_severity = Severity.CRITICAL
    description = "A model-controlled tool can execute arbitrary shell commands."
    risk = "A manipulated agent could execute arbitrary operating-system commands."
    remediation = [
        "Remove shell=True",
        "Use a command allowlist",
        "Restrict the working directory",
        "Apply a timeout",
        "Require approval for privileged operations",
    ]
    mappings = Mappings(
        owaspAgentic=["Tool misuse", "Identity and privilege abuse"],
        nistAiRmf=["Govern", "Measure", "Manage"],
        iso42001Alignment=["Operational control", "Monitoring", "Accountability"],
    )

    def check(self, ctx: RuleContext) -> Iterable[Finding]:
        for call in ctx.analysis.calls:
            name = ctx.analysis.resolve_call(call)
            if name in _OS_SHELL:
                yield self.make_finding(ctx, call, evidence=f"{name} invoked with a command string")
            elif name in _SUBPROCESS_SHELL and is_true_literal(keyword(call, "shell")):
                yield self.make_finding(ctx, call, evidence=f"{name} invoked with shell=True")


class DynamicCodeExecutionRule(Rule):
    """AG002 — Dynamic code execution."""

    id = "AG002"
    name = "Dynamic code execution exposed to agent"
    default_severity = Severity.CRITICAL
    description = "Model-controlled input reaches eval/exec/compile."
    risk = "A manipulated agent could execute arbitrary Python code in-process."
    remediation = [
        "Remove eval/exec/compile from tool paths",
        "Replace with an explicit, whitelisted dispatch table",
        "Validate and constrain any dynamic input",
    ]
    mappings = Mappings(
        owaspAgentic=["Tool misuse", "Code execution"],
        nistAiRmf=["Measure", "Manage"],
        iso42001Alignment=["Operational control"],
    )

    def check(self, ctx: RuleContext) -> Iterable[Finding]:
        for call in ctx.analysis.calls:
            name = ctx.analysis.resolve_call(call)
            if name in {"eval", "exec", "compile"}:
                yield self.make_finding(ctx, call, evidence=f"{name}(...) called")


class DestructiveCommandRule(Rule):
    """AG019 — Destructive command exposure."""

    id = "AG019"
    name = "Destructive command exposure"
    default_severity = Severity.CRITICAL
    description = "A destructive command string is present in agent-reachable code."
    risk = "If reachable by the agent, this command could destroy data or infrastructure."
    remediation = [
        "Remove destructive commands from agent tool paths",
        "Gate destructive operations behind human approval",
        "Scope credentials so destructive actions are impossible",
    ]
    mappings = Mappings(
        owaspAgentic=["Tool misuse", "Excessive agency"],
        nistAiRmf=["Manage"],
        iso42001Alignment=["Operational control", "Accountability"],
    )

    def check(self, ctx: RuleContext) -> Iterable[Finding]:
        for node in ast.walk(ctx.analysis.tree):
            if not isinstance(node, ast.Constant) or not isinstance(node.value, str):
                continue
            lowered = node.value.lower()
            for marker in _DESTRUCTIVE_MARKERS:
                if marker in lowered:
                    yield self.make_finding(
                        ctx,
                        node,
                        evidence=f"Destructive command detected: {marker!r}",
                        pattern=f"{self.id}:{marker}",
                    )
                    break
