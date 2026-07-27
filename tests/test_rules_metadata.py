"""Tests for project-level metadata rules (AG008, AG010, AG020)."""

from __future__ import annotations

from autonomyproof.config import Config
from autonomyproof.rules.metadata import (
    MissingAgentMetadataRule,
    MissingExecutionLimitsRule,
    MissingTracingRule,
)
from helpers import run_project_rule

_FULL_META = Config(
    agent_name="a",
    agent_owner="o@e.com",
    agent_purpose="p",
    environment="development",
    criticality="high",
)


def test_ag008_missing_limits() -> None:
    findings = run_project_rule(MissingExecutionLimitsRule(), {"a.py": "run(cmd)\n"})
    assert findings[0].ruleId == "AG008"
    assert findings[0].file == "a.py"


def test_ag008_with_limit_token_clean() -> None:
    files = {"a.py": "import numpy as np\nAgent(max_iterations=10)\n"}
    assert run_project_rule(MissingExecutionLimitsRule(), files) == []


def test_ag008_no_framework_clean() -> None:
    assert (
        run_project_rule(MissingExecutionLimitsRule(), {"a.py": "run(cmd)\n"}, frameworks=[]) == []
    )


def test_ag010_missing_tracing() -> None:
    assert run_project_rule(MissingTracingRule(), {"a.py": "run(cmd)\n"})


def test_ag010_with_logging_clean() -> None:
    files = {"a.py": "import logging\nlogging.getLogger('x')\n"}
    assert run_project_rule(MissingTracingRule(), files) == []


def test_ag010_no_framework_clean() -> None:
    assert run_project_rule(MissingTracingRule(), {"a.py": "run(cmd)\n"}, frameworks=[]) == []


def test_ag010_import_alias_and_from_import_tokens_clean() -> None:
    # Exercises alias.asname and ImportFrom.module token extraction.
    files = {"a.py": "from opentelemetry import trace as t\nfoo().bar\n"}
    assert run_project_rule(MissingTracingRule(), files) == []


def test_ag020_missing_metadata_lists_fields() -> None:
    findings = run_project_rule(MissingAgentMetadataRule(), {"a.py": "x = 1\n"}, config=Config())
    assert findings[0].ruleId == "AG020"
    assert "name" in findings[0].evidence


def test_ag020_full_metadata_clean() -> None:
    assert (
        run_project_rule(MissingAgentMetadataRule(), {"a.py": "x = 1\n"}, config=_FULL_META) == []
    )


def test_ag020_anchor_when_no_files() -> None:
    findings = run_project_rule(MissingAgentMetadataRule(), {}, config=Config())
    assert findings[0].file == "autonomyproof.yaml"
