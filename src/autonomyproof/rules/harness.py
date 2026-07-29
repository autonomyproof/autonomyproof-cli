"""Harness-layer rules: framework footguns that grant an agent dangerous capability.

These fire only on **literal, unambiguous** signatures — an explicit ``True`` danger flag
or an exact interpreter-tool constructor — so they carry essentially no false positives.
"""

from __future__ import annotations

import ast
from collections.abc import Iterable
from dataclasses import replace

from autonomyproof.astutils import is_true_literal
from autonomyproof.cve import known_vulnerabilities
from autonomyproof.models import Finding, Mappings, Severity
from autonomyproof.rules.base import ProjectContext, Rule, RuleContext

# LangChain constructors that build an agent/chain which executes model-generated code or SQL.
_CODE_EXEC_AGENTS = {
    "create_pandas_dataframe_agent",
    "create_csv_agent",
    "create_python_agent",
    "create_spark_dataframe_agent",
    "create_xorbits_agent",
    "create_sql_agent",
    "PALChain",
    "LLMMathChain",
    "LLMBashChain",
    "SQLDatabaseChain",
}
# Prebuilt tools that make unrestricted outbound HTTP requests (SSRF surface).
_HTTP_REQUEST_TOOLS = {
    "RequestsGetTool",
    "RequestsPostTool",
    "RequestsPutTool",
    "RequestsDeleteTool",
    "RequestsPatchTool",
    "TextRequestsWrapper",
}

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


def _is_false_literal(node: ast.expr | None) -> bool:
    return isinstance(node, ast.Constant) and node.value is False


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
    # ATLAS supply-chain / user-execution. No CVE here: this rule detects the *pattern*,
    # not a version-specific vulnerability. Version-validated CVEs are AG026's job.
    mappings = replace(_HARNESS_MAPPINGS, mitre=["AML.T0010", "AML.T0011"])

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
    mappings = replace(_HARNESS_MAPPINGS, mitre=["T1059"])  # Command and Scripting Interpreter

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


class KnownVulnerableDependencyRule(Rule):
    """AG026 — Known-vulnerable agent-framework dependency (version-validated)."""

    id = "AG026"
    name = "Known-vulnerable agent-framework dependency"
    default_severity = Severity.CRITICAL
    description = "A pinned dependency version falls in the vulnerable range of a known CVE."
    risk = "Running a version with a published CVE exposes the agent to a known exploit."
    remediation = [
        "Upgrade the dependency to a fixed version",
        "Pin only patched releases in requirements/lockfiles",
        "Track security advisories for your agent frameworks",
    ]
    mappings = _HARNESS_MAPPINGS
    project_level = True

    def check_project(self, pctx: ProjectContext) -> Iterable[Finding]:
        for match in known_vulnerabilities(pctx.dependency_versions):
            evidence = f"{match.package}=={match.version} — {match.cve}: {match.summary}"
            finding = self.make_project_finding(
                pctx,
                evidence=evidence,
                pattern=f"{self.id}:{match.cve}",
            )
            finding.mappings = replace(_HARNESS_MAPPINGS, mitre=match.mitre, cve=[match.cve])
            yield finding


class SandboxDisabledRule(Rule):
    """AG027 — Code-execution sandbox disabled (use_docker=False)."""

    id = "AG027"
    name = "Code-execution sandbox disabled"
    default_severity = Severity.CRITICAL
    description = "An agent code executor is configured to run on the host (use_docker=False)."
    risk = "Without container isolation, model-generated code runs against your host and secrets."
    remediation = [
        "Set use_docker=True (or omit it) so code runs in a container",
        "Use a sandboxed executor with no host or credential access",
        "Never execute LLM-generated code directly on the host",
    ]
    mappings = replace(_HARNESS_MAPPINGS, mitre=["T1059"])

    def check(self, ctx: RuleContext) -> Iterable[Finding]:
        for call in ctx.analysis.calls:
            for kw in call.keywords:
                if kw.arg == "use_docker" and _is_false_literal(kw.value):
                    yield self.make_finding(
                        ctx, call, evidence="use_docker=False runs agent code on the host"
                    )
        for node in ast.walk(ctx.analysis.tree):
            if isinstance(node, ast.Dict) and self._dict_disables_docker(node):
                yield self.make_finding(
                    ctx, node, evidence="use_docker: False runs agent code on the host"
                )

    @staticmethod
    def _dict_disables_docker(node: ast.Dict) -> bool:
        for key, value in zip(node.keys, node.values, strict=False):
            if (
                isinstance(key, ast.Constant)
                and key.value == "use_docker"
                and _is_false_literal(value)
            ):
                return True
        return False


def _matched_segment(ctx: RuleContext, call: ast.Call, names: set[str]) -> str | None:
    """Return the first dotted segment of the callee that is in ``names``.

    Matches both direct constructors (``PALChain(...)``) and factory methods
    (``PALChain.from_math_prompt(...)``), where the class name is a middle segment.
    """
    resolved = ctx.analysis.resolve_call(call) or ""
    return next((seg for seg in resolved.split(".") if seg in names), None)


class CodeExecutingAgentRule(Rule):
    """AG028 — Agent or chain that executes model-generated code or SQL."""

    id = "AG028"
    name = "Code-executing agent or chain"
    default_severity = Severity.CRITICAL
    description = "A framework constructor builds an agent/chain that runs model-generated code."
    risk = "These agents execute code/SQL the model writes — a hijacked agent gains execution."
    remediation = [
        "Avoid dataframe/python/SQL agents on untrusted input",
        "If required, run them in a sandbox with least-privilege data access",
        "Require human approval before generated code or SQL runs",
    ]
    mappings = replace(_HARNESS_MAPPINGS, mitre=["T1059"])

    def check(self, ctx: RuleContext) -> Iterable[Finding]:
        for call in ctx.analysis.calls:
            match = _matched_segment(ctx, call, _CODE_EXEC_AGENTS)
            if match:
                yield self.make_finding(
                    ctx,
                    call,
                    evidence=f"{match} builds an agent/chain that executes model-generated code",
                    pattern=f"{self.id}:{match}",
                )


class UnrestrictedRequestToolRule(Rule):
    """AG029 — Unrestricted HTTP request tool exposed to the agent."""

    id = "AG029"
    name = "Unrestricted HTTP request tool"
    default_severity = Severity.HIGH
    description = "A prebuilt tool lets the agent make arbitrary outbound HTTP requests."
    risk = "An unrestricted request tool is an SSRF and data-exfiltration surface for the agent."
    remediation = [
        "Remove the raw requests tool or restrict it to an allowlist of hosts",
        "Block private, loopback, and metadata addresses",
        "Prefer a purpose-built tool over a generic HTTP client",
    ]
    mappings = replace(_HARNESS_MAPPINGS, mitre=["T1552.005"])

    def check(self, ctx: RuleContext) -> Iterable[Finding]:
        for call in ctx.analysis.calls:
            match = _matched_segment(ctx, call, _HTTP_REQUEST_TOOLS)
            if match:
                yield self.make_finding(
                    ctx,
                    call,
                    evidence=f"{match} exposes unrestricted outbound HTTP to the agent",
                    pattern=f"{self.id}:{match}",
                )
