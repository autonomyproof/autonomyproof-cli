"""Central registry of all rules, ordered by rule ID."""

from __future__ import annotations

from autonomyproof.rules.agent_controls import (
    DangerousOperationRule,
    ExcessiveLimitRule,
    GuardrailSelfModificationRule,
    McpArgumentValidationRule,
    SubAgentCreationRule,
)
from autonomyproof.rules.base import Rule
from autonomyproof.rules.data import (
    MemoryIsolationRule,
    ModelControlledSqlRule,
    SecretInContextRule,
)
from autonomyproof.rules.execution import (
    DestructiveCommandRule,
    DynamicCodeExecutionRule,
    ShellExecutionRule,
)
from autonomyproof.rules.filesystem import CredentialPathAccessRule, FilesystemAccessRule
from autonomyproof.rules.harness import (
    DangerousFrameworkFlagRule,
    InterpreterToolExposedRule,
    KnownVulnerableDependencyRule,
    SandboxDisabledRule,
)
from autonomyproof.rules.insecure import (
    DisabledCertVerificationRule,
    InsecureDeserializationRule,
    TemplateInjectionRule,
)
from autonomyproof.rules.metadata import (
    MissingAgentMetadataRule,
    MissingExecutionLimitsRule,
    MissingTracingRule,
)
from autonomyproof.rules.network import (
    MissingTimeoutRule,
    SsrfRule,
    TokenPassthroughRule,
    UnrestrictedHttpRule,
)

_RULE_CLASSES: list[type[Rule]] = [
    ShellExecutionRule,  # AG001
    DynamicCodeExecutionRule,  # AG002
    FilesystemAccessRule,  # AG003
    CredentialPathAccessRule,  # AG004
    UnrestrictedHttpRule,  # AG005
    SsrfRule,  # AG006
    DangerousOperationRule,  # AG007
    MissingExecutionLimitsRule,  # AG008
    ExcessiveLimitRule,  # AG009
    MissingTracingRule,  # AG010
    MemoryIsolationRule,  # AG011
    ModelControlledSqlRule,  # AG012
    McpArgumentValidationRule,  # AG013
    TokenPassthroughRule,  # AG014
    GuardrailSelfModificationRule,  # AG015
    SubAgentCreationRule,  # AG016
    SecretInContextRule,  # AG017
    MissingTimeoutRule,  # AG018
    DestructiveCommandRule,  # AG019
    MissingAgentMetadataRule,  # AG020
    InsecureDeserializationRule,  # AG021
    DisabledCertVerificationRule,  # AG022
    TemplateInjectionRule,  # AG023
    DangerousFrameworkFlagRule,  # AG024
    InterpreterToolExposedRule,  # AG025
    KnownVulnerableDependencyRule,  # AG026
    SandboxDisabledRule,  # AG027
]


def all_rules() -> list[Rule]:
    """Return a fresh, ID-ordered list of every rule instance."""
    return [cls() for cls in _RULE_CLASSES]


def get_rule(rule_id: str) -> Rule:
    """Return the rule with ``rule_id`` (case-insensitive), or raise ``KeyError``."""
    wanted = rule_id.upper()
    for rule in all_rules():
        if rule.id == wanted:
            return rule
    raise KeyError(rule_id)
