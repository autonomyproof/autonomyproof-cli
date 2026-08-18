"""Tests for the command-line interface."""

from __future__ import annotations

from pathlib import Path

import pytest
from click.testing import CliRunner

from autonomyproof import cli
from autonomyproof.api import ApiError, PushResult
from autonomyproof.auth import Credentials

_VULN = (
    "import subprocess\n"
    "from langgraph.graph import StateGraph\n"
    "def run(cmd):\n"
    "    return subprocess.run(cmd, shell=True)\n"
)


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture(autouse=True)
def _home(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("AUTONOMYPROOF_HOME", str(tmp_path / "home"))
    monkeypatch.delenv("AUTONOMYPROOF_TOKEN", raising=False)


def test_version(runner: CliRunner) -> None:
    result = runner.invoke(cli.main, ["--version"])
    assert result.exit_code == 0
    assert "0.18.0" in result.output


def test_init_creates_and_is_idempotent(runner: CliRunner) -> None:
    with runner.isolated_filesystem():
        first = runner.invoke(cli.main, ["init"])
        assert "Wrote" in first.output
        assert Path("autonomyproof.yaml").exists()
        second = runner.invoke(cli.main, ["init"])
        assert "already exists" in second.output


def test_rules_list(runner: CliRunner) -> None:
    result = runner.invoke(cli.main, ["rules", "list"])
    assert "AG001" in result.output
    assert result.output.count("AG0") >= 20


def test_rules_explain(runner: CliRunner) -> None:
    result = runner.invoke(cli.main, ["rules", "explain", "ag001"])
    assert "AG001" in result.output
    assert "Remediation" in result.output


def test_rules_explain_unknown(runner: CliRunner) -> None:
    result = runner.invoke(cli.main, ["rules", "explain", "AG999"])
    assert result.exit_code != 0
    assert "Unknown rule" in result.output


def test_rules_explain_shows_mitre(runner: CliRunner) -> None:
    result = runner.invoke(cli.main, ["rules", "explain", "AG024"])
    assert "MITRE:" in result.output
    assert "AML.T0010" in result.output


def test_rules_explain_without_mitre(runner: CliRunner) -> None:
    # AG020 has no MITRE mapping, so that line is omitted.
    result = runner.invoke(cli.main, ["rules", "explain", "AG020"])
    assert "MITRE:" not in result.output


def test_config_validate_ok(runner: CliRunner) -> None:
    with runner.isolated_filesystem():
        Path("autonomyproof.yaml").write_text("project:\n  name: x\n", encoding="utf-8")
        result = runner.invoke(cli.main, ["config", "validate"])
        assert "is valid" in result.output


def test_config_validate_missing(runner: CliRunner) -> None:
    with runner.isolated_filesystem():
        result = runner.invoke(cli.main, ["config", "validate"])
        assert result.exit_code != 0
        assert "not found" in result.output


def test_config_validate_invalid(runner: CliRunner) -> None:
    with runner.isolated_filesystem():
        Path("bad.yaml").write_text("project: not-a-mapping\n", encoding="utf-8")
        result = runner.invoke(cli.main, ["config", "validate", "--config", "bad.yaml"])
        assert result.exit_code != 0


def test_scan_local_only(runner: CliRunner) -> None:
    with runner.isolated_filesystem():
        Path("agent.py").write_text(_VULN, encoding="utf-8")
        result = runner.invoke(
            cli.main, ["scan", ".", "--local-only", "--fail-on", "none", "--verbose"]
        )
        assert result.exit_code == 0
        assert "Score" in result.output
        assert "AG001" in result.output
        assert Path("autonomyproof-report.html").exists()
        assert Path("autonomyproof-report.json").exists()
        assert Path("autonomyproof-report.sarif").exists()


def test_scan_fail_on_critical_exits_nonzero(runner: CliRunner) -> None:
    with runner.isolated_filesystem():
        Path("agent.py").write_text(_VULN, encoding="utf-8")
        result = runner.invoke(cli.main, ["scan", ".", "--local-only", "--fail-on", "critical"])
        assert result.exit_code == 1


def test_scan_include_exclude_override(runner: CliRunner) -> None:
    with runner.isolated_filesystem():
        Path("agent.py").write_text(_VULN, encoding="utf-8")
        result = runner.invoke(
            cli.main,
            [
                "scan",
                ".",
                "--local-only",
                "--fail-on",
                "none",
                "--verbose",
                "--include",
                "nomatch/*.py",
                "--exclude",
                "extra/**",
            ],
        )
        assert result.exit_code == 0
        assert "AG001" not in result.output


def test_scan_with_existing_config_and_single_format(runner: CliRunner) -> None:
    with runner.isolated_filesystem():
        Path("autonomyproof.yaml").write_text(
            "project:\n  name: configured\nagent:\n  name: a\n  owner: o\n"
            "  purpose: p\n  environment: dev\n  criticality: high\n",
            encoding="utf-8",
        )
        Path("agent.py").write_text("x = 1\n", encoding="utf-8")
        html = runner.invoke(cli.main, ["scan", ".", "--local-only", "--format", "html"])
        assert html.exit_code == 0
        assert Path("autonomyproof-report.html").exists()
        assert not Path("autonomyproof-report.json").exists()
        sarif = runner.invoke(cli.main, ["scan", ".", "--local-only", "--format", "sarif"])
        assert Path("autonomyproof-report.sarif").exists()
        assert sarif.exit_code == 0


def test_scan_push_success(runner: CliRunner, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        cli, "load_credentials", lambda: Credentials("ap_live_x", "https://api", "file")
    )

    class _FakeClient:
        def __init__(self, *a: object, **k: object) -> None: ...
        def push_scan(self, result: object) -> PushResult:
            return PushResult(scan_id="s", report_url="https://app/r/1")

        def close(self) -> None: ...

    monkeypatch.setattr(cli, "ApiClient", _FakeClient)
    with runner.isolated_filesystem():
        Path("agent.py").write_text(_VULN, encoding="utf-8")
        result = runner.invoke(cli.main, ["scan", ".", "--fail-on", "none"])
        assert "Hosted report: https://app/r/1" in result.output


def test_scan_push_failure_preserves_local(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        cli, "load_credentials", lambda: Credentials("ap_live_x", "https://api", "file")
    )

    class _FailClient:
        def __init__(self, *a: object, **k: object) -> None: ...
        def push_scan(self, result: object) -> PushResult:
            raise ApiError("server down")

        def close(self) -> None: ...

    monkeypatch.setattr(cli, "ApiClient", _FailClient)
    with runner.isolated_filesystem():
        Path("agent.py").write_text(_VULN, encoding="utf-8")
        result = runner.invoke(cli.main, ["scan", ".", "--fail-on", "none"])
        assert "Cloud push failed" in result.output
        assert Path("autonomyproof-report.json").exists()


def test_scan_push_not_logged_in(runner: CliRunner, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli, "load_credentials", lambda: Credentials(None, "https://api", "none"))
    with runner.isolated_filesystem():
        Path("agent.py").write_text("x = 1\n", encoding="utf-8")
        result = runner.invoke(cli.main, ["scan", ".", "--fail-on", "none"])
        assert "Not logged in" in result.output


def test_scan_target_is_file(runner: CliRunner) -> None:
    with runner.isolated_filesystem():
        Path("agent.py").write_text("x = 1\n", encoding="utf-8")
        result = runner.invoke(cli.main, ["scan", "agent.py", "--local-only", "--fail-on", "none"])
        assert result.exit_code == 0


def test_scan_honors_autonomyproofignore(runner: CliRunner) -> None:
    with runner.isolated_filesystem():
        Path("keep.py").write_text(_VULN, encoding="utf-8")
        Path("drop.py").write_text(_VULN, encoding="utf-8")
        Path(".autonomyproofignore").write_text("drop.py\n", encoding="utf-8")
        result = runner.invoke(
            cli.main, ["scan", ".", "--local-only", "--fail-on", "none", "--verbose"]
        )
        assert result.exit_code == 0
        # drop.py is ignored; keep.py is still scanned and flagged.
        assert "keep.py" in result.output
        assert "drop.py" not in result.output


def test_baseline_writes_file(runner: CliRunner) -> None:
    with runner.isolated_filesystem():
        Path("agent.py").write_text(_VULN, encoding="utf-8")
        result = runner.invoke(cli.main, ["baseline", ".", "--output", "base.json"])
        assert result.exit_code == 0
        assert "Wrote baseline" in result.output
        assert Path("base.json").exists()


def test_scan_baseline_suppresses_known_findings(runner: CliRunner) -> None:
    with runner.isolated_filesystem():
        Path("agent.py").write_text(_VULN, encoding="utf-8")
        assert runner.invoke(cli.main, ["baseline", ".", "--output", "base.json"]).exit_code == 0
        # Every current finding is in the baseline, so even --fail-on critical passes.
        result = runner.invoke(
            cli.main,
            ["scan", ".", "--local-only", "--baseline", "base.json", "--fail-on", "critical"],
        )
        assert result.exit_code == 0
        assert "0 new" in result.output


def test_scan_baseline_fails_on_new_authority(runner: CliRunner) -> None:
    with runner.isolated_filesystem():
        Path("agent.py").write_text(_VULN, encoding="utf-8")
        assert runner.invoke(cli.main, ["baseline", ".", "--output", "base.json"]).exit_code == 0
        # A new file introduces authority absent from the baseline.
        Path("agent2.py").write_text(_VULN, encoding="utf-8")
        result = runner.invoke(
            cli.main,
            ["scan", ".", "--local-only", "--baseline", "base.json", "--fail-on", "critical"],
        )
        assert result.exit_code == 1
        assert "known," in result.output
        assert "0 new" not in result.output


def test_scan_baseline_invalid_file(runner: CliRunner) -> None:
    with runner.isolated_filesystem():
        Path("agent.py").write_text(_VULN, encoding="utf-8")
        Path("base.json").write_text("{not json", encoding="utf-8")
        result = runner.invoke(cli.main, ["scan", ".", "--local-only", "--baseline", "base.json"])
        assert result.exit_code != 0
        assert "not valid JSON" in result.output


def test_login_with_token(runner: CliRunner) -> None:
    result = runner.invoke(cli.main, ["login", "--token", "ap_live_abcdefghijklmnop"])
    assert result.exit_code == 0
    assert "Saved credentials" in result.output


def test_login_prompt(runner: CliRunner) -> None:
    result = runner.invoke(cli.main, ["login"], input="ap_live_abcdefghijklmnop\n")
    assert result.exit_code == 0


def test_login_bad_token(runner: CliRunner) -> None:
    result = runner.invoke(cli.main, ["login", "--token", "wrong"])
    assert result.exit_code != 0
    assert "ap_live_" in result.output


def test_logout(runner: CliRunner) -> None:
    runner.invoke(cli.main, ["login", "--token", "ap_live_abcdefghijklmnop"])
    result = runner.invoke(cli.main, ["logout"])
    assert "Logged out" in result.output
    again = runner.invoke(cli.main, ["logout"])
    assert "No stored credentials" in again.output


def test_report_open(runner: CliRunner, monkeypatch: pytest.MonkeyPatch) -> None:
    opened: list[str] = []
    monkeypatch.setattr(cli.webbrowser, "open", lambda url: opened.append(url) or True)
    with runner.isolated_filesystem():
        Path("autonomyproof-report.html").write_text("<html></html>", encoding="utf-8")
        result = runner.invoke(cli.main, ["report", "open"])
        assert result.exit_code == 0
        assert opened


def test_report_open_missing(runner: CliRunner) -> None:
    with runner.isolated_filesystem():
        result = runner.invoke(cli.main, ["report", "open"])
        assert result.exit_code != 0
        assert "No report found" in result.output
