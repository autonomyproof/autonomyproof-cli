"""Tests for the authority-regression baseline."""

from __future__ import annotations

from pathlib import Path

import pytest

from autonomyproof.baseline import (
    BASELINE_VERSION,
    BaselineError,
    build_baseline,
    load_baseline_fingerprints,
    new_findings,
    write_baseline,
)
from autonomyproof.models import (
    Capability,
    Finding,
    Mappings,
    ProjectMetadata,
    ScanResult,
    Severity,
)


def _finding(rule_id: str, fingerprint: str, *, file: str = "tools/x.py") -> Finding:
    return Finding(
        ruleId=rule_id,
        severity=Severity.HIGH,
        title=f"{rule_id} title",
        description="desc",
        file=file,
        line=10,
        column=4,
        evidence="evidence",
        risk="risk",
        remediation=["fix it"],
        mappings=Mappings(),
        fingerprint=fingerprint,
    )


def _result(findings: list[Finding]) -> ScanResult:
    return ScanResult(
        scan_id="scan-1",
        scanner_version="9.9.9",
        project=ProjectMetadata(name="p"),
        frameworks=[],
        tools=[],
        capabilities=[Capability("Shell", "runs")],
        findings=findings,
        score=50,
        risk_level="High",
        files_scanned=1,
        rules_executed=["AG001"],
        duration_ms=1,
    )


def test_build_baseline_is_sorted_and_structured() -> None:
    result = _result([_finding("AG010", "sha256:zzz"), _finding("AG001", "sha256:aaa")])
    document = build_baseline(result)

    assert document["version"] == BASELINE_VERSION
    assert document["scannerVersion"] == "9.9.9"
    entries = document["findings"]
    assert isinstance(entries, list)
    assert [e["fingerprint"] for e in entries] == ["sha256:aaa", "sha256:zzz"]
    assert entries[0] == {"fingerprint": "sha256:aaa", "ruleId": "AG001", "file": "tools/x.py"}


def test_write_then_load_round_trips(tmp_path: Path) -> None:
    result = _result([_finding("AG001", "sha256:aaa"), _finding("AG002", "sha256:bbb")])
    path = write_baseline(result, tmp_path / "baseline.json")

    assert path.exists()
    assert load_baseline_fingerprints(path) == {"sha256:aaa", "sha256:bbb"}


def test_new_findings_filters_known() -> None:
    findings = [_finding("AG001", "sha256:aaa"), _finding("AG002", "sha256:bbb")]
    fresh = new_findings(findings, {"sha256:aaa"})

    assert [f.fingerprint for f in fresh] == ["sha256:bbb"]


def test_load_rejects_invalid_json(tmp_path: Path) -> None:
    path = tmp_path / "baseline.json"
    path.write_text("{not json", encoding="utf-8")
    with pytest.raises(BaselineError, match="not valid JSON"):
        load_baseline_fingerprints(path)


def test_load_rejects_non_object(tmp_path: Path) -> None:
    path = tmp_path / "baseline.json"
    path.write_text("[]", encoding="utf-8")
    with pytest.raises(BaselineError, match="must contain a JSON object"):
        load_baseline_fingerprints(path)


def test_load_rejects_missing_findings_list(tmp_path: Path) -> None:
    path = tmp_path / "baseline.json"
    path.write_text('{"version": 1}', encoding="utf-8")
    with pytest.raises(BaselineError, match="missing a 'findings' list"):
        load_baseline_fingerprints(path)


def test_load_rejects_entry_without_fingerprint(tmp_path: Path) -> None:
    path = tmp_path / "baseline.json"
    path.write_text('{"findings": [{"ruleId": "AG001"}]}', encoding="utf-8")
    with pytest.raises(BaselineError, match="without a string 'fingerprint'"):
        load_baseline_fingerprints(path)


def test_load_rejects_non_dict_entry(tmp_path: Path) -> None:
    path = tmp_path / "baseline.json"
    path.write_text('{"findings": ["nope"]}', encoding="utf-8")
    with pytest.raises(BaselineError, match="without a string 'fingerprint'"):
        load_baseline_fingerprints(path)
