"""Network rules: outbound HTTP, SSRF, token passthrough, and missing timeouts."""

from __future__ import annotations

import ast
from collections.abc import Iterable

from autonomyproof.astutils import is_model_controlled, keyword, string_literals
from autonomyproof.models import Finding, Mappings, Severity
from autonomyproof.rules.base import Rule, RuleContext

_HTTP_SINKS = {
    "requests.get",
    "requests.post",
    "requests.put",
    "requests.delete",
    "requests.patch",
    "requests.head",
    "requests.request",
    "httpx.get",
    "httpx.post",
    "httpx.put",
    "httpx.delete",
    "httpx.patch",
    "httpx.request",
    "httpx.stream",
    "urllib.request.urlopen",
}
_SESSION_METHODS = {"get", "post", "put", "delete", "patch", "request"}

_SUBPROCESS_SINKS = {
    "subprocess.run",
    "subprocess.Popen",
    "subprocess.call",
    "subprocess.check_call",
    "subprocess.check_output",
}

_SSRF_MARKERS = [
    "127.0.0.1",
    "localhost",
    "0.0.0.0",
    "::1",
    "169.254.169.254",
    "metadata.google.internal",
    "192.168.",
    "10.0.",
    "172.16.",
    ".internal",
]

_TOKEN_MARKERS = ("token", "auth", "bearer", "credential", "jwt", "access")
_NET_MAPPINGS = Mappings(
    owaspAgentic=["Tool misuse", "Unrestricted network access"],
    nistAiRmf=["Measure", "Manage"],
    iso42001Alignment=["Operational control", "Monitoring"],
)


def http_url_arg(ctx: RuleContext, call: ast.Call) -> ast.expr | None:
    """Return the URL argument if ``call`` is a recognized HTTP request, else ``None``."""
    name = ctx.analysis.resolve_call(call)
    if name in _HTTP_SINKS and call.args:
        return call.args[0]
    func = call.func
    if isinstance(func, ast.Attribute) and func.attr in _SESSION_METHODS:
        receiver = func.value
        if isinstance(receiver, ast.Call):
            recv_name = ctx.analysis.resolve_call(receiver)
            if recv_name in {"aiohttp.ClientSession", "httpx.Client", "httpx.AsyncClient"}:
                return call.args[0] if call.args else None
    return None


def is_http_call(ctx: RuleContext, call: ast.Call) -> bool:
    """Whether ``call`` performs an outbound HTTP request."""
    name = ctx.analysis.resolve_call(call)
    if name in _HTTP_SINKS:
        return True
    return http_url_arg(ctx, call) is not None and bool(call.args)


class UnrestrictedHttpRule(Rule):
    """AG005 — Unrestricted outbound HTTP."""

    id = "AG005"
    name = "Unrestricted outbound HTTP request"
    default_severity = Severity.HIGH
    description = "A model-controlled URL is fetched without domain allowlisting."
    risk = "A manipulated agent could reach arbitrary external or internal destinations."
    remediation = [
        "Validate the URL scheme and host against an allowlist",
        "Block private and link-local address ranges",
        "Disable or restrict redirects",
        "Apply a timeout",
    ]
    mappings = _NET_MAPPINGS

    def check(self, ctx: RuleContext) -> Iterable[Finding]:
        for call in ctx.analysis.calls:
            url = http_url_arg(ctx, call)
            if url is not None and is_model_controlled(url):
                unbounded = not ctx.config.allowed_domains and keyword(call, "timeout") is None
                yield self.make_finding(
                    ctx,
                    call,
                    evidence="HTTP request with a model-controlled URL",
                    severity=Severity.CRITICAL if unbounded else Severity.HIGH,
                )


class SsrfRule(Rule):
    """AG006 — Potential SSRF."""

    id = "AG006"
    name = "Potential server-side request forgery"
    default_severity = Severity.CRITICAL
    description = "An HTTP request targets localhost, a private range, or a metadata host."
    risk = "An agent could reach internal services or cloud metadata credentials."
    remediation = [
        "Block requests to private, loopback, and link-local ranges",
        "Deny cloud metadata endpoints (169.254.169.254)",
        "Resolve and validate the host before connecting",
    ]
    mappings = _NET_MAPPINGS

    def check(self, ctx: RuleContext) -> Iterable[Finding]:
        for call in ctx.analysis.calls:
            if http_url_arg(ctx, call) is None:
                continue
            for literal in string_literals(call):
                lowered = literal.lower()
                marker = next((m for m in _SSRF_MARKERS if m in lowered), None)
                if marker is not None:
                    yield self.make_finding(
                        ctx,
                        call,
                        evidence=f"Request target references internal host: {marker!r}",
                        pattern=f"{self.id}:{marker}",
                    )
                    break


class TokenPassthroughRule(Rule):
    """AG014 — Token passthrough."""

    id = "AG014"
    name = "Bearer token forwarded without audience separation"
    default_severity = Severity.CRITICAL
    description = "An inbound credential is forwarded directly to an outbound request."
    risk = "Passing a caller's token downstream lets one service impersonate another."
    remediation = [
        "Exchange the inbound token for a scoped downstream credential",
        "Never forward Authorization headers verbatim",
        "Validate the audience of every token",
    ]
    mappings = _NET_MAPPINGS

    def check(self, ctx: RuleContext) -> Iterable[Finding]:
        for call in ctx.analysis.calls:
            if http_url_arg(ctx, call) is None:
                continue
            headers = keyword(call, "headers")
            if not isinstance(headers, ast.Dict):
                continue
            for key, value in zip(headers.keys, headers.values, strict=False):
                if (
                    isinstance(key, ast.Constant)
                    and isinstance(key.value, str)
                    and "authorization" in key.value.lower()
                    and is_model_controlled(value)
                    and self._references_token(value)
                ):
                    yield self.make_finding(
                        ctx,
                        call,
                        evidence="Authorization header set from a forwarded token",
                    )
                    break

    @staticmethod
    def _references_token(node: ast.AST) -> bool:
        for child in ast.walk(node):
            identifier = ""
            if isinstance(child, ast.Name):
                identifier = child.id.lower()
            elif isinstance(child, ast.Attribute):
                identifier = child.attr.lower()
            if any(marker in identifier for marker in _TOKEN_MARKERS):
                return True
        return False


class MissingTimeoutRule(Rule):
    """AG018 — Missing tool timeout."""

    id = "AG018"
    name = "External operation without a timeout"
    default_severity = Severity.MEDIUM
    description = "A subprocess or HTTP call has no timeout and can hang indefinitely."
    risk = "Missing timeouts allow an agent operation to stall or exhaust resources."
    remediation = [
        "Pass an explicit timeout to every subprocess and HTTP call",
        "Fail closed when the timeout is exceeded",
    ]
    mappings = _NET_MAPPINGS

    def check(self, ctx: RuleContext) -> Iterable[Finding]:
        for call in ctx.analysis.calls:
            name = ctx.analysis.resolve_call(call)
            is_target = name in _SUBPROCESS_SINKS or is_http_call(ctx, call)
            if is_target and keyword(call, "timeout") is None:
                label = name if name in _SUBPROCESS_SINKS else "HTTP request"
                yield self.make_finding(ctx, call, evidence=f"{label} without a timeout")
