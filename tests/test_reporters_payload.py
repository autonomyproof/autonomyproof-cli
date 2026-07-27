"""Tests for reporters and the sanitized cloud payload."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from autonomyproof.models import (
    Capability,
    Finding,
    Mappings,
    ProjectMetadata,
    ScanError,
    ScanResult,
    Severity,
)
from autonomyproof.payload import assert_sanitized, build_scan_payload
from autonomyproof.reporters import (
    build_report_dict,
    build_sarif,
    render_html,
    write_html,
    write_json,
    write_sarif,
)


def _finding(rule_id: str, severity: Severity) -> Finding:
    return Finding(
        ruleId=rule_id,
        severity=severity,
        title=f"{rule_id} title",
        description="desc",
        file="tools/x.py",
        line=10,
        column=4,
        evidence="evidence",
        risk="risk",
        remediation=["fix it"],
        mappings=Mappings(
            owaspAgentic=["Tool misuse"], nistAiRmf=["Manage"], iso42001Alignment=["Control"]
        ),
        fingerprint="sha256:abc",
        framework="LangGraph",
        toolName="x",
    )


def _result(findings: list[Finding]) -> ScanResult:
    return ScanResult(
        scan_id="scan-1",
        scanner_version="0.1.0",
        project=ProjectMetadata(name="p", branch="main", commit="sha"),
        frameworks=["LangGraph"],
        tools=["x"],
        capabilities=[Capability("Shell execution", "runs commands")],
        findings=findings,
        score=55,
        risk_level="High",
        files_scanned=3,
        rules_executed=["AG001"],
        duration_ms=12,
        errors=[ScanError(file="b.py", message="bad")],
    )


@pytest.fixture
def result_with_findings() -> ScanResult:
    return _result([_finding("AG001", Severity.CRITICAL), _finding("AG010", Severity.MEDIUM)])


def test_build_report_dict(result_with_findings: ScanResult) -> None:
    report = build_report_dict(result_with_findings)
    assert report["scanId"] == "scan-1"
    assert report["score"] == 55
    assert report["commit"] == {"branch": "main", "sha": "sha"}
    assert len(report["findings"]) == 2  # type: ignore[arg-type]


def test_write_json(result_with_findings: ScanResult, tmp_path: Path) -> None:
    path = write_json(result_with_findings, tmp_path / "r.json")
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["riskLevel"] == "High"


def test_render_html_with_findings(result_with_findings: ScanResult) -> None:
    html = render_html(result_with_findings)
    assert "<!doctype html>" in html
    assert "AG001" in html
    assert "noindex" in html
    assert "cdn" not in html.lower()


def test_render_html_no_findings() -> None:
    html = render_html(_result([]))
    assert "No findings." in html


def test_write_html(result_with_findings: ScanResult, tmp_path: Path) -> None:
    path = write_html(result_with_findings, tmp_path / "r.html")
    assert "AutonomyProof" in path.read_text(encoding="utf-8")


def test_build_sarif_levels(result_with_findings: ScanResult) -> None:
    sarif = build_sarif(result_with_findings)
    run = sarif["runs"][0]  # type: ignore[index]
    assert run["tool"]["driver"]["name"] == "AutonomyProof"
    levels = {r["ruleId"]: r["level"] for r in run["results"]}
    assert levels["AG001"] == "error"
    assert levels["AG010"] == "warning"


def test_write_sarif(result_with_findings: ScanResult, tmp_path: Path) -> None:
    path = write_sarif(result_with_findings, tmp_path / "r.sarif")
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["version"] == "2.1.0"


def test_build_scan_payload_is_sanitized(result_with_findings: ScanResult) -> None:
    payload = build_scan_payload(result_with_findings)
    assert_sanitized(payload)
    assert payload["clientScanId"] == "scan-1"
    assert payload["findings"][0]["ruleId"] == "AG001"  # type: ignore[index]


def test_assert_sanitized_rejects_forbidden_keys() -> None:
    with pytest.raises(ValueError, match="forbidden"):
        assert_sanitized({"findings": [{"source": "secret code"}]})


def test_assert_sanitized_allows_clean_nested() -> None:
    assert_sanitized({"a": [{"b": 1}], "c": {"d": [1, 2]}})
