"""Shared test helpers."""

from __future__ import annotations

from autonomyproof.astutils import FileAnalysis
from autonomyproof.config import Config
from autonomyproof.models import Finding
from autonomyproof.rules.base import ProjectContext, Rule, RuleContext
from autonomyproof.tools import detect_tools


def make_context(
    code: str,
    *,
    config: Config | None = None,
    frameworks: list[str] | None = None,
    path: str = "module.py",
) -> RuleContext:
    """Build a :class:`RuleContext` for ``code``."""
    analysis = FileAnalysis.build(path, code)
    return RuleContext(
        analysis=analysis,
        config=config or Config(),
        frameworks=frameworks or [],
        tool_functions=detect_tools(analysis),
    )


def run_rule(
    rule: Rule,
    code: str,
    *,
    config: Config | None = None,
    frameworks: list[str] | None = None,
    path: str = "module.py",
) -> list[Finding]:
    """Run a per-file ``rule`` over ``code`` and return its findings."""
    return list(rule.check(make_context(code, config=config, frameworks=frameworks, path=path)))


def run_project_rule(
    rule: Rule,
    files: dict[str, str],
    *,
    config: Config | None = None,
    frameworks: list[str] | None = None,
) -> list[Finding]:
    """Run a project-level ``rule`` over multiple files."""
    analyses = [FileAnalysis.build(name, code) for name, code in files.items()]
    pctx = ProjectContext(
        analyses=analyses,
        config=config or Config(),
        frameworks=frameworks if frameworks is not None else ["LangGraph"],
    )
    return list(rule.check_project(pctx))


def rule_ids(findings: list[Finding]) -> set[str]:
    """Return the set of rule IDs present in ``findings``."""
    return {f.ruleId for f in findings}
