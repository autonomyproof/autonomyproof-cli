"""Project-level rules: missing limits, missing tracing, missing accountable metadata."""

from __future__ import annotations

from collections.abc import Iterable

from autonomyproof.models import Finding, Mappings, Severity
from autonomyproof.rules.base import ProjectContext, Rule

_META_MAPPINGS = Mappings(
    owaspAgentic=["Insufficient oversight", "Excessive agency"],
    nistAiRmf=["Govern", "Measure", "Manage"],
    iso42001Alignment=["Accountability", "Monitoring", "Operational control"],
)

_LIMIT_INDICATORS = [
    "max_iterations",
    "recursion_limit",
    "max_execution_time",
    "timeout",
    "max_retries",
    "max_tool_calls",
    "max_tokens",
    "max_steps",
    "iteration_limit",
]
_TRACING_INDICATORS = [
    "opentelemetry",
    "langsmith",
    "callbackhandler",
    "callbacks",
    "tracer",
    "logging.getlogger",
    "run_id",
    "on_tool_start",
    "langfuse",
    "set_tracer",
]


class MissingExecutionLimitsRule(Rule):
    """AG008 — Missing execution limits."""

    id = "AG008"
    name = "Missing execution limits"
    default_severity = Severity.HIGH
    description = "No iteration, recursion, timeout, retry, or token limit was found."
    risk = "Without limits, an agent can loop, retry, or spend without bound."
    remediation = [
        "Set maximum iterations and a recursion limit",
        "Add a runtime timeout and a retry cap",
        "Bound tool-call count and token/cost budgets",
    ]
    mappings = _META_MAPPINGS
    project_level = True

    def check_project(self, pctx: ProjectContext) -> Iterable[Finding]:
        if pctx.has_agent_framework and not pctx.code_contains_any(_LIMIT_INDICATORS):
            yield self.make_project_finding(
                pctx,
                evidence="No execution-limit configuration detected in the project",
                pattern=f"{self.id}:missing-limits",
            )


class MissingTracingRule(Rule):
    """AG010 — Missing action tracing."""

    id = "AG010"
    name = "Missing action tracing"
    default_severity = Severity.MEDIUM
    description = "No tracing, tool-call logging, or run identifiers were found."
    risk = "Without tracing, agent actions cannot be audited or reconstructed."
    remediation = [
        "Enable framework tracing or OpenTelemetry",
        "Log every tool call with a run identifier",
        "Emit audit events for high-impact actions",
    ]
    mappings = _META_MAPPINGS
    project_level = True

    def check_project(self, pctx: ProjectContext) -> Iterable[Finding]:
        if pctx.has_agent_framework and not pctx.code_contains_any(_TRACING_INDICATORS):
            yield self.make_project_finding(
                pctx,
                evidence="No tracing or tool-call logging detected in the project",
                pattern=f"{self.id}:missing-tracing",
            )


class MissingAgentMetadataRule(Rule):
    """AG020 — Missing accountable-agent metadata."""

    id = "AG020"
    name = "Missing accountable-agent metadata"
    default_severity = Severity.MEDIUM
    description = (
        "Required agent metadata (name, owner, purpose, environment, criticality) is missing."
    )
    risk = "Without accountable metadata, findings cannot be assigned or governed."
    remediation = [
        "Set agent name, owner, purpose, environment, and criticality",
        "Keep the metadata in autonomyproof.yaml under version control",
    ]
    mappings = _META_MAPPINGS
    project_level = True

    def check_project(self, pctx: ProjectContext) -> Iterable[Finding]:
        config = pctx.config
        fields = {
            "name": config.agent_name,
            "owner": config.agent_owner,
            "purpose": config.agent_purpose,
            "environment": config.environment,
            "criticality": config.criticality,
        }
        missing = [name for name, value in fields.items() if not value]
        if missing:
            yield self.make_project_finding(
                pctx,
                evidence=f"Missing agent metadata: {', '.join(missing)}",
                pattern=f"{self.id}:{','.join(missing)}",
            )
