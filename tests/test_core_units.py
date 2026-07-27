"""Unit tests for models, scoring, fingerprint, and redaction."""

from __future__ import annotations

import pytest

from autonomyproof import __version__
from autonomyproof.fingerprint import compute_fingerprint, normalize_pattern
from autonomyproof.models import (
    Capability,
    Finding,
    Mappings,
    ProjectMetadata,
    ScanError,
    ScanResult,
    Severity,
)
from autonomyproof.redaction import contains_secret, redact
from autonomyproof.scoring import compute_score, risk_level


def _finding(rule_id: str, severity: Severity) -> Finding:
    return Finding(
        ruleId=rule_id,
        severity=severity,
        title="t",
        description="d",
        file="f.py",
        line=1,
        column=0,
        evidence="e",
        risk="r",
        remediation=["fix"],
        mappings=Mappings(owaspAgentic=["x"]),
        fingerprint="sha256:abc",
    )


def test_version_is_string() -> None:
    assert isinstance(__version__, str)


@pytest.mark.parametrize(
    ("severity", "deduction", "rank"),
    [
        (Severity.CRITICAL, 20, 4),
        (Severity.HIGH, 10, 3),
        (Severity.MEDIUM, 5, 2),
        (Severity.LOW, 2, 1),
    ],
)
def test_severity_properties(severity: Severity, deduction: int, rank: int) -> None:
    assert severity.score_deduction == deduction
    assert severity.rank == rank


def test_severity_ordering() -> None:
    assert Severity.LOW < Severity.HIGH
    assert not (Severity.CRITICAL < Severity.MEDIUM)


def test_finding_to_dict_serializes_severity() -> None:
    data = _finding("AG001", Severity.CRITICAL).to_dict()
    assert data["severity"] == "critical"
    assert data["ruleId"] == "AG001"


def test_scan_result_severity_counts() -> None:
    result = ScanResult(
        scan_id="s",
        scanner_version="0",
        project=ProjectMetadata(name="p"),
        frameworks=[],
        tools=[],
        capabilities=[Capability("Framework", "LangGraph")],
        findings=[_finding("AG001", Severity.CRITICAL), _finding("AG002", Severity.CRITICAL)],
        score=60,
        risk_level="Moderate",
        files_scanned=1,
        rules_executed=["AG001"],
        duration_ms=5,
        errors=[ScanError(file="x.py", message="bad")],
    )
    assert result.severity_counts() == {"critical": 2, "high": 0, "medium": 0, "low": 0}


def test_compute_score_and_floor() -> None:
    assert compute_score([]) == 100
    assert compute_score([_finding("AG001", Severity.CRITICAL)]) == 80
    many = [_finding("AG001", Severity.CRITICAL) for _ in range(10)]
    assert compute_score(many) == 0


@pytest.mark.parametrize(
    ("score", "level"),
    [
        (100, "Low"),
        (80, "Low"),
        (79, "Moderate"),
        (60, "Moderate"),
        (59, "High"),
        (40, "High"),
        (39, "Critical"),
        (0, "Critical"),
    ],
)
def test_risk_level_bands(score: int, level: str) -> None:
    assert risk_level(score) == level


def test_fingerprint_stable_across_line_changes() -> None:
    a = compute_fingerprint("AG001", "a/b.py", "fn", "subprocess.run(x, shell=True)")
    b = compute_fingerprint("AG001", "a\\b.py", "fn", "subprocess.run(x,  shell=True)  ")
    assert a == b
    assert a.startswith("sha256:")


def test_fingerprint_changes_with_rule() -> None:
    a = compute_fingerprint("AG001", "b.py", "fn", "p")
    b = compute_fingerprint("AG002", "b.py", "fn", "p")
    assert a != b


def test_normalize_pattern() -> None:
    assert normalize_pattern("  Foo   Bar ") == "foo bar"


@pytest.mark.parametrize(
    "secret",
    [
        "-----BEGIN RSA PRIVATE KEY-----\nabc\n-----END RSA PRIVATE KEY-----",
        "AKIAIOSFODNN7EXAMPLE",
        "ghp_1234567890123456789012345678901234567890",
        "xoxb-1234567890-abcdefghij",
        "eyJhbGciOi.eyJzdWIi.SflKxwRJ",
        "Authorization: Bearer abcdefghijklmnop1234",
        "postgres://user:password@host/db",
        "sk-abcdefghijklmnopqrstuvwx",
        "ap_live_abcdefghijklmnopqrstuvwx",
        "password = 'hunter2secret'",
    ],
)
def test_redact_masks_secrets(secret: str) -> None:
    assert contains_secret(secret)
    assert "REDACTED" in redact(secret)


def test_redact_leaves_clean_text() -> None:
    text = "subprocess.run(cmd, shell=True)"
    assert not contains_secret(text)
    assert redact(text) == text
