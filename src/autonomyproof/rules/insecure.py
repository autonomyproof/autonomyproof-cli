"""Insecure-primitive rules: deserialization, disabled TLS verification, template injection."""

from __future__ import annotations

import ast
from collections.abc import Iterable
from dataclasses import replace

from autonomyproof.astutils import is_model_controlled, is_true_literal, keyword
from autonomyproof.models import Finding, Mappings, Severity
from autonomyproof.rules.base import Rule, RuleContext

_DESERIALIZE_SINKS = {
    "pickle.load",
    "pickle.loads",
    "cPickle.load",
    "cPickle.loads",
    "dill.load",
    "dill.loads",
    "marshal.load",
    "marshal.loads",
    "jsonpickle.decode",
    "torch.load",
    "joblib.load",
    "pandas.read_pickle",
}
_SAFE_YAML_LOADERS = {"SafeLoader", "CSafeLoader"}
_UNVERIFIED_SSL = {"ssl._create_unverified_context"}
_SSTI_RENDER_STRING = {"flask.render_template_string", "render_template_string"}
_SSTI_TEMPLATE_CTORS = {"jinja2.Template", "Template"}
_SSTI_ENVIRONMENTS = {
    "Environment",
    "SandboxedEnvironment",
    "ImmutableSandboxedEnvironment",
    "NativeEnvironment",
}

_INSECURE_MAPPINGS = Mappings(
    owaspAgentic=["Tool misuse", "Code execution"],
    nistAiRmf=["Measure", "Manage"],
    iso42001Alignment=["Operational control"],
)


def _is_false(node: ast.expr | None) -> bool:
    return isinstance(node, ast.Constant) and node.value is False


class InsecureDeserializationRule(Rule):
    """AG021 — Insecure deserialization."""

    id = "AG021"
    name = "Insecure deserialization exposed to agent"
    default_severity = Severity.CRITICAL
    description = "Untrusted data is deserialized with a primitive that can execute code."
    risk = "A manipulated agent could achieve code execution by feeding a crafted payload."
    remediation = [
        "Never unpickle or yaml.load untrusted input",
        "Use yaml.safe_load / json for data interchange",
        "Deserialize only formats that cannot execute code",
    ]
    # ATLAS: User Execution (Unsafe ML Artifacts) + AI Supply Chain Compromise.
    mappings = replace(_INSECURE_MAPPINGS, mitre=["AML.T0011", "AML.T0010"])

    def check(self, ctx: RuleContext) -> Iterable[Finding]:
        for call in ctx.analysis.calls:
            name = ctx.analysis.resolve_call(call)
            if name in _DESERIALIZE_SINKS:
                yield self.make_finding(
                    ctx, call, evidence=f"{name}(...) deserializes untrusted data"
                )
            elif name == "numpy.load" and is_true_literal(keyword(call, "allow_pickle")):
                yield self.make_finding(
                    ctx, call, evidence="numpy.load(allow_pickle=True) can execute pickled code"
                )
            elif name == "yaml.load" and not self._has_safe_loader(call):
                yield self.make_finding(
                    ctx, call, evidence="yaml.load without SafeLoader executes arbitrary tags"
                )

    @staticmethod
    def _has_safe_loader(call: ast.Call) -> bool:
        loader = keyword(call, "Loader") or (call.args[1] if len(call.args) > 1 else None)
        if isinstance(loader, ast.Attribute):
            return loader.attr in _SAFE_YAML_LOADERS
        if isinstance(loader, ast.Name):
            return loader.id in _SAFE_YAML_LOADERS
        return False


class DisabledCertVerificationRule(Rule):
    """AG022 — Disabled TLS certificate verification."""

    id = "AG022"
    name = "Disabled TLS certificate verification"
    default_severity = Severity.HIGH
    description = "An outbound call disables certificate or hostname verification."
    risk = "Disabling verification exposes agent traffic to interception and spoofing."
    remediation = [
        "Never set verify=False or check_hostname=False in production",
        "Trust the system CA bundle or pin a known certificate",
        "Do not build unverified SSL contexts",
    ]
    mappings = _INSECURE_MAPPINGS

    def check(self, ctx: RuleContext) -> Iterable[Finding]:
        for call in ctx.analysis.calls:
            if ctx.analysis.resolve_call(call) in _UNVERIFIED_SSL:
                yield self.make_finding(ctx, call, evidence="Unverified SSL context created")
                continue
            if _is_false(keyword(call, "verify")):
                yield self.make_finding(
                    ctx, call, evidence="TLS verification disabled (verify=False)"
                )
            elif _is_false(keyword(call, "check_hostname")):
                yield self.make_finding(
                    ctx, call, evidence="Hostname verification disabled (check_hostname=False)"
                )


class TemplateInjectionRule(Rule):
    """AG023 — Server-side template injection."""

    id = "AG023"
    name = "Server-side template injection"
    default_severity = Severity.HIGH
    description = "Model-controlled input is compiled as a template that can execute code."
    risk = "A manipulated agent could execute code or read data through template evaluation."
    remediation = [
        "Never build templates from model or user input",
        "Render fixed templates and pass untrusted data only as bound variables",
        "Use a sandboxed template environment if dynamic templates are unavoidable",
    ]
    mappings = _INSECURE_MAPPINGS

    def check(self, ctx: RuleContext) -> Iterable[Finding]:
        for call in ctx.analysis.calls:
            name = ctx.analysis.resolve_call(call)
            first = call.args[0] if call.args else None
            if name in _SSTI_RENDER_STRING and is_model_controlled(first):
                yield self.make_finding(
                    ctx, call, evidence="render_template_string() with model-controlled template"
                )
            elif name in _SSTI_TEMPLATE_CTORS and is_model_controlled(first):
                yield self.make_finding(
                    ctx, call, evidence="Template built from a model-controlled string"
                )
            elif self._is_template_from_string(ctx, call) and is_model_controlled(first):
                yield self.make_finding(
                    ctx, call, evidence="Environment.from_string() with a model-controlled template"
                )

    @staticmethod
    def _is_template_from_string(ctx: RuleContext, call: ast.Call) -> bool:
        """A jinja ``Environment(...).from_string`` / ``env.from_string`` — not any from_string.

        Scoped so unrelated ``X.from_string`` deserializers (e.g. RunState.from_string) don't match.
        """
        func = call.func
        if not (isinstance(func, ast.Attribute) and func.attr == "from_string"):
            return False
        receiver = func.value
        if isinstance(receiver, ast.Call):
            name = ctx.analysis.resolve_call(receiver) or ""
            return name.rsplit(".", 1)[-1] in _SSTI_ENVIRONMENTS
        if isinstance(receiver, ast.Name):
            lowered = receiver.id.lower()
            return "env" in lowered or "jinja" in lowered
        return False
