"""Integration tests for the scan orchestrator."""

from __future__ import annotations

from pathlib import Path

from autonomyproof.config import Config
from autonomyproof.scanner import Scanner

_VULN = (
    "import subprocess\n"
    "from langgraph.graph import StateGraph\n"
    "def run(cmd):\n"
    "    return subprocess.run(cmd, shell=True)\n"
)


def _write(root: Path, name: str, content: str) -> None:
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def test_scan_produces_findings_and_metadata(tmp_path: Path) -> None:
    _write(tmp_path, "agent.py", _VULN)
    result = Scanner(Config()).scan(tmp_path, project_name="demo")
    assert result.project.name == "demo"
    assert "LangGraph" in result.frameworks
    assert any(f.ruleId == "AG001" for f in result.findings)
    assert result.score < 100
    assert result.risk_level
    assert result.files_scanned == 1
    assert len(result.rules_executed) == 33
    assert any(c.name == "Shell execution" for c in result.capabilities)


def test_scan_records_syntax_errors(tmp_path: Path) -> None:
    _write(tmp_path, "broken.py", "def (:\n")
    result = Scanner(Config()).scan(tmp_path)
    assert result.errors
    assert result.errors[0].file == "broken.py"


def test_scan_records_decode_errors(tmp_path: Path) -> None:
    (tmp_path / "bin.py").write_bytes(b"\xff\xfe\x00bad")
    result = Scanner(Config()).scan(tmp_path)
    assert any(e.file == "bin.py" for e in result.errors)


def test_scan_respects_ignored_rules(tmp_path: Path) -> None:
    _write(tmp_path, "agent.py", _VULN)
    config = Config(ignored_rules=["AG001"])
    result = Scanner(config).scan(tmp_path)
    assert not any(f.ruleId == "AG001" for f in result.findings)


def test_scan_respects_accepted_findings(tmp_path: Path) -> None:
    _write(tmp_path, "agent.py", _VULN)
    first = Scanner(Config()).scan(tmp_path)
    ag001 = next(f for f in first.findings if f.ruleId == "AG001")
    config = Config(accepted_findings=[ag001.fingerprint])
    result = Scanner(config).scan(tmp_path)
    assert ag001.fingerprint not in {f.fingerprint for f in result.findings}


def test_scan_reads_git_metadata(tmp_path: Path) -> None:
    _write(tmp_path, "agent.py", "x = 1\n")
    git = tmp_path / ".git"
    (git / "refs" / "heads").mkdir(parents=True)
    (git / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
    (git / "refs" / "heads" / "main").write_text("sha1\n", encoding="utf-8")
    result = Scanner(Config()).scan(tmp_path)
    assert result.project.branch == "main"
    assert result.project.commit == "sha1"


def test_scan_deduplicates_capabilities(tmp_path: Path) -> None:
    _write(tmp_path, "agent.py", "def a(p):\n    return open(p).read() + open(other).read()\n")
    result = Scanner(Config()).scan(tmp_path)
    fs_caps = [c for c in result.capabilities if c.name == "Filesystem access"]
    assert len(fs_caps) == 1


def test_scan_inventories_tools(tmp_path: Path) -> None:
    _write(tmp_path, "srv.py", "@tool\ndef mytool(x):\n    return x\n")
    result = Scanner(Config()).scan(tmp_path)
    assert "mytool" in result.tools
    assert any(c.name == "Agent tool" and c.detail == "mytool" for c in result.capabilities)


def test_scan_uses_config_project_name(tmp_path: Path) -> None:
    _write(tmp_path, "agent.py", "x = 1\n")
    result = Scanner(Config(project_name="from-config")).scan(tmp_path)
    assert result.project.name == "from-config"
