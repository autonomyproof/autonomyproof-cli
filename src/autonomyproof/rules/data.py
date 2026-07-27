"""Data rules: model-controlled SQL, memory isolation, secrets in model context."""

from __future__ import annotations

import ast
from collections.abc import Iterable

from autonomyproof.astutils import is_model_controlled, string_literals
from autonomyproof.models import Finding, Mappings, Severity
from autonomyproof.rules.base import Rule, RuleContext

_DB_RECEIVERS = {
    "cursor",
    "conn",
    "connection",
    "session",
    "db",
    "engine",
    "cur",
    "tx",
    "transaction",
}
_SQL_MUTATIONS = ("insert", "update", "delete", "drop", "alter", "create", "truncate", "grant")

_MEMORY_CTORS = {
    "MemorySaver",
    "ConversationBufferMemory",
    "ConversationBufferWindowMemory",
    "RedisChatMessageHistory",
    "RedisSaver",
    "SqliteSaver",
    "InMemoryStore",
    "Chroma",
    "FAISS",
    "VectorStore",
    "RedisVectorStore",
}
_ISOLATION_KEYS = (
    "namespace",
    "user_id",
    "tenant",
    "tenant_id",
    "session_id",
    "thread_id",
    "partition",
    "user",
    "key_prefix",
)

_PROMPT_MARKERS = (
    "prompt",
    "system",
    "you are",
    "instruction",
    "message",
    "context",
    "role",
    "assistant",
)
_SECRET_MARKERS = ("secret", "token", "api_key", "apikey", "password", "passwd", "credential")

_DATA_MAPPINGS = Mappings(
    owaspAgentic=["Tool misuse", "Sensitive information disclosure"],
    nistAiRmf=["Measure", "Manage"],
    iso42001Alignment=["Operational control", "Data governance"],
)


def _receiver_name(func: ast.Attribute) -> str:
    inner = func.value
    if isinstance(inner, ast.Name):
        return inner.id.lower()
    if isinstance(inner, ast.Attribute):
        return inner.attr.lower()
    return ""


class ModelControlledSqlRule(Rule):
    """AG012 — Model-controlled SQL."""

    id = "AG012"
    name = "Model-controlled SQL query"
    default_severity = Severity.HIGH
    description = "A query string controlled by the agent is executed against a database."
    risk = "A manipulated agent could read or modify arbitrary database records."
    remediation = [
        "Use parameterized queries with bound parameters",
        "Never interpolate model output into SQL",
        "Grant the database identity least privilege",
    ]
    mappings = _DATA_MAPPINGS

    def check(self, ctx: RuleContext) -> Iterable[Finding]:
        for call in ctx.analysis.calls:
            func = call.func
            if not (isinstance(func, ast.Attribute) and func.attr == "execute"):
                continue
            if not call.args:
                continue
            arg = call.args[0]
            wraps_text = isinstance(arg, ast.Call) and ctx.analysis.resolve_call(arg) in {
                "text",
                "sqlalchemy.text",
            }
            if not (
                is_model_controlled(arg) and (_receiver_name(func) in _DB_RECEIVERS or wraps_text)
            ):
                continue
            mutates = any(
                mutation in literal.lower()
                for literal in string_literals(call)
                for mutation in _SQL_MUTATIONS
            )
            yield self.make_finding(
                ctx,
                call,
                evidence="execute() called with a model-controlled query",
                severity=Severity.CRITICAL if mutates else Severity.HIGH,
            )


class MemoryIsolationRule(Rule):
    """AG011 — Persistent memory without isolation."""

    id = "AG011"
    name = "Persistent memory without tenant isolation"
    default_severity = Severity.HIGH
    description = "Shared memory, checkpoint, or vector store is created without a tenant key."
    risk = "Without isolation, one user's data can leak into another user's session."
    remediation = [
        "Namespace memory and checkpoints by tenant and user",
        "Pass a per-user key to the store or saver",
        "Bound conversation retention",
    ]
    mappings = _DATA_MAPPINGS

    def check(self, ctx: RuleContext) -> Iterable[Finding]:
        for call in ctx.analysis.calls:
            name = ctx.analysis.resolve_call(call)
            if name is None or name.split(".")[-1] not in _MEMORY_CTORS:
                continue
            if not self._has_isolation(call):
                yield self.make_finding(
                    ctx,
                    call,
                    evidence=f"{name.split('.')[-1]} created without a tenant/user key",
                )

    @staticmethod
    def _has_isolation(call: ast.Call) -> bool:
        for kw in call.keywords:
            if kw.arg and any(key in kw.arg.lower() for key in _ISOLATION_KEYS):
                return True
        for literal in string_literals(call):
            if any(key in literal.lower() for key in _ISOLATION_KEYS):
                return True
        return False


class SecretInContextRule(Rule):
    """AG017 — Secret inserted into model context."""

    id = "AG017"
    name = "Secret interpolated into model context"
    default_severity = Severity.CRITICAL
    description = "A secret value is interpolated into a prompt, message, or instruction."
    risk = "A model or its logs could expose secrets embedded in the context window."
    remediation = [
        "Never place secrets into prompts or messages",
        "Reference secrets only inside tool implementations, server-side",
        "Redact secrets before they reach the model",
    ]
    mappings = _DATA_MAPPINGS

    def check(self, ctx: RuleContext) -> Iterable[Finding]:
        for node in ast.walk(ctx.analysis.tree):
            if not isinstance(node, ast.JoinedStr):
                continue
            literal_text = " ".join(
                part.value
                for part in node.values
                if isinstance(part, ast.Constant) and isinstance(part.value, str)
            ).lower()
            if not any(marker in literal_text for marker in _PROMPT_MARKERS):
                continue
            if self._interpolates_secret(node):
                yield self.make_finding(
                    ctx,
                    node,
                    evidence="Secret interpolated into a prompt/message f-string",
                )

    def _interpolates_secret(self, node: ast.JoinedStr) -> bool:
        for part in node.values:
            if isinstance(part, ast.FormattedValue) and self._is_secret_expr(part.value):
                return True
        return False

    @staticmethod
    def _is_secret_expr(expr: ast.AST) -> bool:
        for child in ast.walk(expr):
            token = ""
            if isinstance(child, ast.Name):
                token = child.id.lower()
            elif isinstance(child, ast.Attribute):
                token = child.attr.lower()
            elif isinstance(child, ast.Constant) and isinstance(child.value, str):
                token = child.value.lower()
            if any(marker in token for marker in _SECRET_MARKERS):
                return True
        return False
