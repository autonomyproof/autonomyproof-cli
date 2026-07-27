"""Agent-control rules: approval, limits, MCP validation, self-modification, sub-agents."""

from __future__ import annotations

import ast
from collections.abc import Iterable

from autonomyproof.astutils import string_literals
from autonomyproof.models import Finding, Mappings, Severity
from autonomyproof.rules.base import Rule, RuleContext

_DANGEROUS_OPS = [
    "delete",
    "deploy",
    "refund",
    "transfer",
    "send_email",
    "execute",
    "publish",
    "push",
    "modify_iam",
    "run_sql",
    "disable",
    "terminate",
    "create_user",
]
_APPROVAL_MARKERS = (
    "approve",
    "approval",
    "confirm",
    "human_in_the_loop",
    "requires_approval",
    "interrupt",
    "authorize",
)
_RISKY_PARAMS = {
    "path",
    "file",
    "filepath",
    "url",
    "uri",
    "command",
    "cmd",
    "query",
    "sql",
    "email",
    "amount",
    "resource",
    "host",
}
_SENSITIVE_ATTRS = {
    "system_prompt",
    "instructions",
    "approval",
    "approval_required",
    "policy",
    "guardrails",
    "guardrail",
    "audit",
}
_SELFMOD_MARKERS = [
    ".github/workflows",
    "autonomyproof",
    "system_prompt",
    "policy",
    "approval",
    "audit",
]
_AGENT_CTORS = {
    "Agent",
    "create_agent",
    "AssistantAgent",
    "ConversableAgent",
    "spawn_agent",
    "create_react_agent",
    "Crew",
    "Swarm",
}
_LIMIT_KWARGS = ("max", "limit", "budget")

_CTRL_MAPPINGS = Mappings(
    owaspAgentic=["Excessive agency", "Insufficient oversight"],
    nistAiRmf=["Govern", "Manage"],
    iso42001Alignment=["Operational control", "Accountability", "Monitoring"],
)


def _identifiers_in(node: ast.AST) -> set[str]:
    tokens: set[str] = set()
    for child in ast.walk(node):
        if isinstance(child, ast.Name):
            tokens.add(child.id.lower())
        elif isinstance(child, ast.Attribute):
            tokens.add(child.attr.lower())
        elif isinstance(child, ast.keyword) and child.arg:
            tokens.add(child.arg.lower())
    return tokens


class DangerousOperationRule(Rule):
    """AG007 — Dangerous operation without approval."""

    id = "AG007"
    name = "Dangerous operation without human approval"
    default_severity = Severity.CRITICAL
    description = "A high-impact operation is exposed with no detectable approval step."
    risk = "A manipulated agent could take an irreversible action without oversight."
    remediation = [
        "Require human approval before executing the operation",
        "Add an interrupt or confirmation gate",
        "Constrain the operation's blast radius",
    ]
    mappings = _CTRL_MAPPINGS

    def check(self, ctx: RuleContext) -> Iterable[Finding]:
        for node in ast.walk(ctx.analysis.tree):
            if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                continue
            lowered = node.name.lower()
            op = next((o for o in _DANGEROUS_OPS if o in lowered), None)
            if op is None:
                continue
            body_text = " ".join(_identifiers_in(node))
            if any(marker in body_text for marker in _APPROVAL_MARKERS):
                continue
            yield self.make_finding(
                ctx,
                node,
                evidence=f"Function '{node.name}' performs a dangerous operation without approval",
                tool_name=ctx.tool_functions.get(node.name, node.name),
                pattern=f"{self.id}:{node.name}",
            )


class ExcessiveLimitRule(Rule):
    """AG009 — Excessive execution limit."""

    id = "AG009"
    name = "Excessive or unbounded execution limit"
    default_severity = Severity.HIGH
    description = "A retry/recursion limit is set very high, or a loop is unbounded."
    risk = "Excessive limits let a misbehaving agent loop, retry, or recurse without bound."
    remediation = [
        "Cap retries at a small number",
        "Set conservative recursion and iteration limits",
        "Ensure every loop has a bounded exit condition",
    ]
    mappings = _CTRL_MAPPINGS

    def check(self, ctx: RuleContext) -> Iterable[Finding]:
        for call in ctx.analysis.calls:
            yield from self._check_kwargs(ctx, call)
            if ctx.analysis.resolve_call(call) == "sys.setrecursionlimit":
                arg = call.args[0] if call.args else None
                if (
                    isinstance(arg, ast.Constant)
                    and isinstance(arg.value, int)
                    and arg.value > 1000
                ):
                    yield self.make_finding(
                        ctx, call, evidence=f"sys.setrecursionlimit({arg.value})"
                    )
        for node in ast.walk(ctx.analysis.tree):
            if (
                isinstance(node, ast.While)
                and isinstance(node.test, ast.Constant)
                and node.test.value is True
                and not any(isinstance(n, ast.Break) for n in ast.walk(node))
            ):
                yield self.make_finding(
                    ctx,
                    node,
                    evidence="Unbounded 'while True' loop with no break",
                    pattern=f"{self.id}:while-true",
                )

    def _check_kwargs(self, ctx: RuleContext, call: ast.Call) -> Iterable[Finding]:
        for kw in call.keywords:
            if not (
                kw.arg and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, int)
            ):
                continue
            name = kw.arg.lower()
            value = kw.value.value
            if name in {"max_retries", "retries", "retry"} and value > 20:
                yield self.make_finding(
                    ctx,
                    call,
                    evidence=f"{kw.arg}={value} exceeds the retry threshold",
                    pattern=f"{self.id}:{name}",
                )
            elif name in {"recursion_limit", "max_iterations"} and value > 1000:
                yield self.make_finding(
                    ctx,
                    call,
                    evidence=f"{kw.arg}={value} is excessively high",
                    pattern=f"{self.id}:{name}",
                )


class McpArgumentValidationRule(Rule):
    """AG013 — MCP argument validation missing."""

    id = "AG013"
    name = "MCP tool accepts unvalidated arguments"
    default_severity = Severity.HIGH
    description = "An MCP tool takes a sensitive argument with no validation in its body."
    risk = "Unvalidated tool arguments let an agent supply dangerous paths, URLs, or SQL."
    remediation = [
        "Validate and constrain every tool argument",
        "Allowlist acceptable values for paths, URLs, and resources",
        "Reject inputs that fail validation before acting",
    ]
    mappings = _CTRL_MAPPINGS

    def check(self, ctx: RuleContext) -> Iterable[Finding]:
        if "MCP" not in ctx.frameworks:
            return
        for node in ast.walk(ctx.analysis.tree):
            if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                continue
            if node.name not in ctx.tool_functions:
                continue
            risky = [a.arg for a in node.args.args if a.arg.lower() in _RISKY_PARAMS]
            if risky and not self._has_validation(node):
                yield self.make_finding(
                    ctx,
                    node,
                    evidence=f"Tool '{node.name}' accepts unvalidated arg(s): {', '.join(risky)}",
                    tool_name=node.name,
                    pattern=f"{self.id}:{node.name}",
                )

    @staticmethod
    def _has_validation(node: ast.AST) -> bool:
        for child in ast.walk(node):
            if isinstance(child, ast.If | ast.Raise):
                return True
            if isinstance(child, ast.Call):
                name = (
                    child.func.attr
                    if isinstance(child.func, ast.Attribute)
                    else (child.func.id if isinstance(child.func, ast.Name) else "")
                )
                if any(v in name.lower() for v in ("valid", "allow", "check", "sanitiz")):
                    return True
        return False


class GuardrailSelfModificationRule(Rule):
    """AG015 — Guardrail self-modification."""

    id = "AG015"
    name = "Agent can modify its own guardrails"
    default_severity = Severity.CRITICAL
    description = "Code can rewrite prompts, policy, CI, approval, or audit configuration."
    risk = "An agent that can edit its own controls can disable every other safeguard."
    remediation = [
        "Make guardrail configuration read-only to the agent",
        "Store policy and approval logic outside agent-writable paths",
        "Require human approval to change controls",
    ]
    mappings = _CTRL_MAPPINGS

    def check(self, ctx: RuleContext) -> Iterable[Finding]:
        for node in ast.walk(ctx.analysis.tree):
            if isinstance(node, ast.Assign | ast.AugAssign):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                for target in targets:
                    if isinstance(target, ast.Attribute) and target.attr in _SENSITIVE_ATTRS:
                        yield self.make_finding(
                            ctx,
                            node,
                            evidence=f"Assignment to guardrail attribute '{target.attr}'",
                        )
                        break
            elif isinstance(node, ast.Call) and self._is_config_write(ctx, node):
                yield self.make_finding(
                    ctx,
                    node,
                    evidence="Write to a guardrail/config file path",
                )

    @staticmethod
    def _is_config_write(ctx: RuleContext, call: ast.Call) -> bool:
        func = call.func
        write_sink = False
        if ctx.analysis.resolve_call(call) == "open":
            mode = call.args[1] if len(call.args) > 1 else None
            write_sink = (
                isinstance(mode, ast.Constant)
                and isinstance(mode.value, str)
                and any(flag in mode.value for flag in ("w", "a", "x", "+"))
            )
        elif isinstance(func, ast.Attribute) and func.attr in {"write_text", "write_bytes"}:
            write_sink = True
        if not write_sink:
            return False
        haystack = " ".join(string_literals(call)).lower()
        if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Call):
            haystack += " " + " ".join(string_literals(func.value)).lower()
        return any(marker in haystack for marker in _SELFMOD_MARKERS)


class SubAgentCreationRule(Rule):
    """AG016 — Unrestricted sub-agent creation."""

    id = "AG016"
    name = "Unrestricted sub-agent creation"
    default_severity = Severity.HIGH
    description = "Agents are created dynamically without a child limit or budget."
    risk = "Unbounded sub-agent spawning can fan out cost, access, and blast radius."
    remediation = [
        "Cap the number and type of child agents",
        "Propagate a budget to every child",
        "Reduce permissions for sub-agents and keep a parent-child trace",
    ]
    mappings = _CTRL_MAPPINGS

    def check(self, ctx: RuleContext) -> Iterable[Finding]:
        for call in ctx.analysis.calls:
            name = ctx.analysis.resolve_call(call)
            if name is None or name.split(".")[-1] not in _AGENT_CTORS:
                continue
            in_tool = ctx.tool_name_for(call) is not None
            if not (in_tool or self._within_loop(ctx, call)):
                continue
            has_limit = any(
                kw.arg and kw.arg.lower().startswith(_LIMIT_KWARGS) for kw in call.keywords
            )
            if not has_limit:
                yield self.make_finding(
                    ctx,
                    call,
                    evidence=f"{name.split('.')[-1]}(...) created without a child limit",
                )

    @staticmethod
    def _within_loop(ctx: RuleContext, node: ast.AST) -> bool:
        current: ast.AST | None = node
        while current is not None:
            if isinstance(current, ast.For | ast.While | ast.AsyncFor):
                return True
            current = ctx.analysis.parents.get(current)
        return False
