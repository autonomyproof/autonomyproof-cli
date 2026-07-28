"""Network rules: outbound HTTP, SSRF, token passthrough, and missing timeouts."""

from __future__ import annotations

import ast
import ipaddress
from collections.abc import Iterable
from urllib.parse import urlsplit

from autonomyproof.astutils import is_model_controlled, keyword
from autonomyproof.models import Finding, Mappings, Severity
from autonomyproof.rules.base import Rule, RuleContext
from autonomyproof.rules.sources import classify_source, resolved_strings

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
_SESSION_METHODS = {"get", "post", "put", "delete", "patch", "head", "request"}
# Constructors whose instances expose the HTTP verbs above.
_SESSION_CTORS = {
    "aiohttp.ClientSession",
    "httpx.Client",
    "httpx.AsyncClient",
    "requests.Session",
    "requests.session",
}

_SUBPROCESS_SINKS = {
    "subprocess.run",
    "subprocess.Popen",
    "subprocess.call",
    "subprocess.check_call",
    "subprocess.check_output",
}

# Hostnames that resolve to internal/credential endpoints (belt-and-suspenders with
# the ipaddress classification below, and covers the DNS name for GCP metadata).
_METADATA_HOSTS = {"169.254.169.254", "metadata.google.internal", "metadata"}

_TOKEN_MARKERS = ("token", "auth", "bearer", "credential", "jwt", "access")
_NET_MAPPINGS = Mappings(
    owaspAgentic=["Tool misuse", "Unrestricted network access"],
    nistAiRmf=["Measure", "Manage"],
    iso42001Alignment=["Operational control", "Monitoring"],
)


def _session_ctor(ctx: RuleContext, receiver: ast.expr) -> str | None:
    """Resolve the constructor behind an HTTP-session receiver, inline or via a variable."""
    if isinstance(receiver, ast.Call):
        return ctx.analysis.resolve_call(receiver)
    if isinstance(receiver, ast.Name):
        value = ctx.analysis.resolve_local_value(receiver.id, receiver)
        if isinstance(value, ast.Call):
            return ctx.analysis.resolve_call(value)
    return None


def http_url_arg(ctx: RuleContext, call: ast.Call) -> ast.expr | None:
    """Return the URL argument if ``call`` is a recognized HTTP request, else ``None``."""
    name = ctx.analysis.resolve_call(call)
    if name in _HTTP_SINKS and call.args:
        return call.args[0]
    func = call.func
    if (
        isinstance(func, ast.Attribute)
        and func.attr in _SESSION_METHODS
        and _session_ctor(ctx, func.value) in _SESSION_CTORS
    ):
        return call.args[0] if call.args else None
    return None


def is_http_call(ctx: RuleContext, call: ast.Call) -> bool:
    """Whether ``call`` performs an outbound HTTP request."""
    name = ctx.analysis.resolve_call(call)
    if name in _HTTP_SINKS:
        return True
    return http_url_arg(ctx, call) is not None and bool(call.args)


def _candidate_hosts(text: str) -> list[str]:
    """Best-effort host extraction from a URL or bare host string."""
    text = text.strip()
    hosts: list[str] = []
    targets = [text] if "://" in text else [text, "//" + text]
    for target in targets:
        try:
            host = urlsplit(target).hostname
        except ValueError:
            host = None
        if host:
            hosts.append(host)
    hosts.append(text)  # bare literal (e.g. IPv6 "::1")
    return hosts


def _ssrf_host(text: str) -> str | None:
    """Return the internal host referenced by ``text``, or ``None`` if it looks external."""
    for host in _candidate_hosts(text):
        lowered = host.lower().rstrip(".")
        if lowered == "localhost" or lowered in _METADATA_HOSTS:
            return host
        if lowered.endswith((".internal", ".local")):
            return host
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            continue
        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_unspecified
        ):
            return host
    return None


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
            if url is None or not is_model_controlled(url):
                continue
            if classify_source(ctx, call, url) == "safe":
                # URL provably comes from a hardcoded constant or trusted config,
                # not from model/attacker input — not what this rule is about.
                continue
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
            url = http_url_arg(ctx, call)
            if url is None:
                continue
            for text in resolved_strings(ctx, call):
                host = _ssrf_host(text)
                if host is not None:
                    yield self.make_finding(
                        ctx,
                        call,
                        evidence=f"Request target references internal host: {host!r}",
                        pattern=f"{self.id}:{host}",
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
