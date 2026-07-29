"""Filesystem rules: arbitrary path access and sensitive credential-path access."""

from __future__ import annotations

import ast
from collections.abc import Iterable
from dataclasses import replace

from autonomyproof.astutils import is_model_controlled, keyword
from autonomyproof.models import Finding, Mappings, Severity
from autonomyproof.rules.base import Rule, RuleContext
from autonomyproof.rules.sources import classify_source, resolved_strings

_DELETE_SINKS = {"os.remove", "os.unlink", "shutil.rmtree"}
_FS_MAPPINGS = Mappings(
    owaspAgentic=["Tool misuse", "Sensitive information disclosure"],
    nistAiRmf=["Measure", "Manage"],
    iso42001Alignment=["Operational control", "Data governance"],
)

_SENSITIVE_MARKERS = [
    ".env",
    ".aws",
    ".ssh",
    ".gnupg",
    "kubeconfig",
    "credentials",
    "id_rsa",
    "id_ed25519",
    ".pem",
    "service_account",
    ".netrc",
    "/secrets",
]


def _first_positional(call: ast.Call) -> ast.expr | None:
    return call.args[0] if call.args else None


def _model_controlled_from_input(ctx: RuleContext, call: ast.Call, arg: ast.expr | None) -> bool:
    """A path that is model-controlled and not provably a hardcoded constant / trusted config."""
    if arg is None or not is_model_controlled(arg):
        return False
    return classify_source(ctx, call, arg) != "safe"


def _mode_is_write(call: ast.Call) -> bool:
    """Return ``True`` if an ``open`` call is in a write/append/create mode."""
    mode = call.args[1] if len(call.args) > 1 else keyword(call, "mode")
    if isinstance(mode, ast.Constant) and isinstance(mode.value, str):
        return any(flag in mode.value for flag in ("w", "a", "x", "+"))
    return False


class FilesystemAccessRule(Rule):
    """AG003 — Arbitrary filesystem access."""

    id = "AG003"
    name = "Arbitrary filesystem access exposed to agent"
    default_severity = Severity.HIGH
    description = "A model-controlled path reaches a filesystem read, write, or delete."
    risk = "A manipulated agent could read, overwrite, or delete arbitrary files."
    remediation = [
        "Resolve and confine paths to an allowlisted base directory",
        "Reject absolute paths and parent-directory traversal",
        "Separate read and write capabilities",
        "Require approval for deletes",
    ]
    mappings = _FS_MAPPINGS

    def check(self, ctx: RuleContext) -> Iterable[Finding]:
        for call in ctx.analysis.calls:
            name = ctx.analysis.resolve_call(call)
            arg = _first_positional(call)
            if name == "open" and _model_controlled_from_input(ctx, call, arg):
                severity = Severity.CRITICAL if _mode_is_write(call) else Severity.HIGH
                yield self.make_finding(
                    ctx,
                    call,
                    evidence="open() called with a model-controlled path",
                    severity=severity,
                )
            elif name in _DELETE_SINKS and _model_controlled_from_input(ctx, call, arg):
                yield self.make_finding(
                    ctx,
                    call,
                    evidence=f"{name} called with a model-controlled path",
                    severity=Severity.CRITICAL,
                )
            else:
                yield from self._check_path_method(ctx, call)

    def _check_path_method(self, ctx: RuleContext, call: ast.Call) -> Iterable[Finding]:
        func = call.func
        if not isinstance(func, ast.Attribute):
            return
        if func.attr not in {"read_text", "read_bytes", "write_text", "write_bytes", "unlink"}:
            return
        receiver = func.value
        if not (
            isinstance(receiver, ast.Call)
            and ctx.analysis.resolve_call(receiver) in {"pathlib.Path", "Path"}
        ):
            return
        path_arg = _first_positional(receiver)
        if not _model_controlled_from_input(ctx, call, path_arg):
            return
        writes = func.attr in {"write_text", "write_bytes", "unlink"}
        yield self.make_finding(
            ctx,
            call,
            evidence=f"Path(...).{func.attr}() with a model-controlled path",
            severity=Severity.CRITICAL if writes else Severity.HIGH,
        )


class CredentialPathAccessRule(Rule):
    """AG004 — Sensitive credential-path access."""

    id = "AG004"
    name = "Sensitive credential-path access"
    default_severity = Severity.CRITICAL
    description = "Code references a path that commonly holds credentials or private keys."
    risk = "An agent reaching these paths could exfiltrate credentials or private keys."
    remediation = [
        "Never expose credential directories to agent tools",
        "Confine file access to a dedicated working directory",
        "Load secrets from a managed secret store, not the filesystem",
    ]
    mappings = replace(_FS_MAPPINGS, mitre=["T1552"])  # Unsecured Credentials

    def check(self, ctx: RuleContext) -> Iterable[Finding]:
        for call in ctx.analysis.calls:
            if not self._is_fs_sink(ctx, call):
                continue
            for literal in resolved_strings(ctx, call):
                lowered = literal.lower()
                marker = next((m for m in _SENSITIVE_MARKERS if m in lowered), None)
                if marker is not None:
                    yield self.make_finding(
                        ctx,
                        call,
                        evidence=f"Credential path referenced: {marker!r}",
                        pattern=f"{self.id}:{marker}",
                    )
                    break

    @staticmethod
    def _is_fs_sink(ctx: RuleContext, call: ast.Call) -> bool:
        name = ctx.analysis.resolve_call(call)
        if name in {"open", "io.open", "os.open", "pathlib.Path", "Path"}:
            return True
        func = call.func
        return isinstance(func, ast.Attribute) and func.attr in {
            "read_text",
            "read_bytes",
            "open",
        }
