"""Execution-related rules: shell, dynamic code, and destructive commands."""

from __future__ import annotations

import ast
from collections.abc import Iterable

from autonomyproof.astutils import function_defs, is_true_literal, keyword, return_values
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

# AG040 — sinks that execute their argument as code or a shell command.
_CODE_EXEC_SINKS = {"eval", "exec", "compile", "os.system", "os.popen"}
_SHELL_EXEC_SINKS = {
    "subprocess.run",
    "subprocess.Popen",
    "subprocess.call",
    "subprocess.check_call",
    "subprocess.check_output",
}
# High-precision method names for an LLM/model call. Deliberately excludes overloaded verbs
# like run/call/create-in-general; `create` only counts on a completions/messages receiver.
_MODEL_METHODS = {
    "invoke",
    "ainvoke",
    "predict",
    "apredict",
    "predict_messages",
    "generate",
    "agenerate",
    "complete",
    "acomplete",
}

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
        mitre=["T1059"],  # Command and Scripting Interpreter
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
        mitre=["T1059.006"],  # Command and Scripting Interpreter: Python
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


def _terminal(node: ast.expr) -> ast.expr:
    """Peel attribute/subscript/await accessors to the underlying expression.

    ``llm.invoke(x).content`` -> the ``llm.invoke(x)`` call;
    ``resp.choices[0].message.content`` -> the ``resp`` name.
    """
    while isinstance(node, ast.Attribute | ast.Subscript | ast.Await):
        node = node.value
    return node


def _is_model_call(node: ast.expr) -> bool:
    """True if ``node`` is a call that returns LLM/model output."""
    if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
        return False
    if node.func.attr in _MODEL_METHODS:
        return True
    if node.func.attr in {"create", "acreate"}:
        recv = node.func.value
        return isinstance(recv, ast.Attribute) and recv.attr in {"completions", "messages"}
    return False


def _param_index(func: ast.FunctionDef | ast.AsyncFunctionDef, name: str) -> int | None:
    """Positional index of parameter ``name`` in ``func``, or None (keyword-only excluded)."""
    positional = func.args.posonlyargs + func.args.args
    for index, arg in enumerate(positional):
        if arg.arg == name:
            return index
    return None


class InsecureModelOutputRule(Rule):
    """AG040 — Model output executed as code or a shell command."""

    id = "AG040"
    name = "Model output executed as code or command"
    default_severity = Severity.CRITICAL
    description = "The output of an LLM call flows into a code or shell execution sink."
    risk = (
        "If an attacker steers the model (e.g. via prompt injection), model-generated text "
        "becomes executed code or shell commands — remote code execution."
    )
    remediation = [
        "Never pass model output to eval/exec/compile or a shell",
        "Validate model output against a strict schema or allowlist before use",
        "Prefer structured tool-calling over executing generated code",
        "If code execution is required, run it in an isolated, no-network sandbox",
    ]
    mappings = Mappings(
        owaspAgentic=["Tool misuse", "Excessive agency"],
        nistAiRmf=["Measure", "Manage"],
        iso42001Alignment=["Operational control", "Accountability"],
        mitre=["T1059"],  # Command and Scripting Interpreter
    )

    def check(self, ctx: RuleContext) -> Iterable[Finding]:
        fmap = function_defs(ctx.analysis.tree)
        for call in ctx.analysis.calls:
            name = ctx.analysis.resolve_call(call)
            if name not in _CODE_EXEC_SINKS and name not in _SHELL_EXEC_SINKS:
                continue
            if not call.args:
                continue
            if self._from_model(ctx, call.args[0], call, fmap):
                yield self.make_finding(
                    ctx, call, evidence=f"Model output flows into {name}() and is executed"
                )

    def _from_model(
        self,
        ctx: RuleContext,
        node: ast.expr,
        origin: ast.AST,
        fmap: dict[str, ast.FunctionDef | ast.AsyncFunctionDef],
        depth: int = 0,
    ) -> bool:
        base = _terminal(node)
        if _is_model_call(base):
            return True
        # Cross-function (single file): a call to a local helper whose body returns model
        # output taints the result too — following the taint across the function boundary.
        if isinstance(base, ast.Call) and isinstance(base.func, ast.Name) and depth < 4:
            helper = fmap.get(base.func.id)
            if helper is not None and any(
                self._from_model(ctx, ret, ret, fmap, depth + 1) for ret in return_values(helper)
            ):
                return True
        if isinstance(base, ast.Name) and depth < 4:
            assigned = ctx.analysis.resolve_local_value(base.id, origin)
            if assigned is not None:
                return self._from_model(ctx, assigned, origin, fmap, depth + 1)
            # Phase 2: parameter propagation — an unassigned name that is a parameter of the
            # enclosing function is tainted if any caller passes model output for it.
            if self._param_fed_by_model(ctx, base.id, origin, fmap, depth):
                return True
        return False

    def _param_fed_by_model(
        self,
        ctx: RuleContext,
        name: str,
        origin: ast.AST,
        fmap: dict[str, ast.FunctionDef | ast.AsyncFunctionDef],
        depth: int,
    ) -> bool:
        scope = ctx.analysis.enclosing_scope(origin)
        if not isinstance(scope, ast.FunctionDef | ast.AsyncFunctionDef):
            return False
        index = _param_index(scope, name)
        if index is None:
            return False
        for call in ctx.analysis.calls:
            if not (isinstance(call.func, ast.Name) and call.func.id == scope.name):
                continue
            arg = call.args[index] if index < len(call.args) else keyword(call, name)
            if arg is not None and self._from_model(ctx, arg, call, fmap, depth + 1):
                return True
        return False
