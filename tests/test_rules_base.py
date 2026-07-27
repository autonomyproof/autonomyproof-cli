"""Tests for the rule base class defaults and make_finding behavior."""

from __future__ import annotations

from autonomyproof.config import Config
from autonomyproof.rules.base import ProjectContext, Rule
from autonomyproof.rules.execution import ShellExecutionRule
from helpers import make_context, run_rule


def test_base_rule_defaults_return_empty() -> None:
    rule = Rule()
    ctx = make_context("x = 1\n")
    pctx = ProjectContext(analyses=[ctx.analysis], config=Config(), frameworks=[])
    assert list(rule.check(ctx)) == []
    assert list(rule.check_project(pctx)) == []


def test_make_finding_redaction_disabled_passes_evidence_through() -> None:
    config = Config(redact_secrets=False)
    code = "import subprocess\nsubprocess.run(cmd, shell=True)\n"
    findings = run_rule(ShellExecutionRule(), code, config=config)
    assert findings[0].evidence == "subprocess.run invoked with shell=True"


def test_make_finding_attributes_framework_and_tool() -> None:
    code = (
        "import subprocess\n"
        "from mcp.server.fastmcp import FastMCP\n"
        "mcp = FastMCP('x')\n"
        "@mcp.tool()\n"
        "def run(command):\n"
        "    return subprocess.run(command, shell=True)\n"
    )
    findings = run_rule(ShellExecutionRule(), code, frameworks=["MCP"])
    assert findings[0].framework == "MCP"
    assert findings[0].toolName == "run"
