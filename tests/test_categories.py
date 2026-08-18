"""Tests for assessment-category grouping (Harness / Guardrail / Attack vector)."""

from __future__ import annotations

from pathlib import Path

from autonomyproof.config import Config
from autonomyproof.reporters.html_reporter import render_html
from autonomyproof.reporters.json_reporter import build_report_dict
from autonomyproof.rules.categories import (
    ATTACK_VECTOR,
    CATEGORY_ORDER,
    RULE_CATEGORY,
    category_for,
)
from autonomyproof.rules.registry import all_rules
from autonomyproof.scanner import Scanner

_VULN = "import subprocess\ndef run(cmd):\n    return subprocess.run(cmd, shell=True)\n"


def test_every_registered_rule_has_a_valid_category() -> None:
    ids = {rule.id for rule in all_rules()}
    # The mapping covers exactly the registered rules — no missing, no stale entries.
    assert set(RULE_CATEGORY) == ids
    assert all(value in CATEGORY_ORDER for value in RULE_CATEGORY.values())


def test_rule_category_property_matches_mapping() -> None:
    for rule in all_rules():
        assert rule.category == RULE_CATEGORY[rule.id]


def test_category_for_unknown_defaults_to_attack_vector() -> None:
    assert category_for("AG999") == ATTACK_VECTOR


def test_all_three_lenses_are_represented() -> None:
    present = {rule.category for rule in all_rules()}
    assert present == set(CATEGORY_ORDER)


def test_finding_carries_category(tmp_path: Path) -> None:
    (tmp_path / "agent.py").write_text(_VULN, encoding="utf-8")
    result = Scanner(Config()).scan(tmp_path)
    shell = next(f for f in result.findings if f.ruleId == "AG001")
    assert shell.category == ATTACK_VECTOR


def test_category_counts_and_reports(tmp_path: Path) -> None:
    (tmp_path / "agent.py").write_text(_VULN, encoding="utf-8")
    result = Scanner(Config()).scan(tmp_path)
    counts = result.category_counts()
    assert counts.get(ATTACK_VECTOR, 0) >= 1
    # JSON report exposes the per-lens breakdown and per-finding category.
    report = build_report_dict(result)
    assert report["assessmentCounts"] == counts
    assert all("category" in f for f in report["findings"])  # type: ignore[union-attr]
    # HTML report shows the assessment breakdown.
    html = render_html(result)
    assert "By assessment lens" in html
    assert ATTACK_VECTOR in html
