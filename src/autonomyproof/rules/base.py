"""Rule base class and shared per-file rule context."""

from __future__ import annotations

import ast
from collections.abc import Iterable
from dataclasses import dataclass

from autonomyproof.astutils import FileAnalysis
from autonomyproof.config import Config
from autonomyproof.fingerprint import compute_fingerprint
from autonomyproof.frameworks import primary_framework
from autonomyproof.models import Finding, Mappings, Severity
from autonomyproof.redaction import redact


def _code_tokens(analysis: FileAnalysis) -> str:
    """Return a lowercased, space-joined string of the file's code identifiers.

    Includes plain names, dotted attribute/call names, keyword-argument names, and import
    module/alias names. Deliberately excludes string literals, comments, and docstrings.
    """
    parts: list[str] = []
    for node in ast.walk(analysis.tree):
        if isinstance(node, ast.Name | ast.Attribute):
            dotted = analysis.dotted_name(node)
            if dotted:
                parts.append(dotted)
        elif isinstance(node, ast.keyword) and node.arg:
            parts.append(node.arg)
        elif isinstance(node, ast.alias):
            parts.append(node.name)
            if node.asname:
                parts.append(node.asname)
        elif isinstance(node, ast.ImportFrom) and node.module:
            parts.append(node.module)
    return " ".join(parts).lower()


@dataclass
class RuleContext:
    """Everything a rule needs to analyze one file."""

    analysis: FileAnalysis
    config: Config
    frameworks: list[str]
    tool_functions: dict[str, str]

    @property
    def framework(self) -> str | None:
        """The primary framework findings should be attributed to."""
        return primary_framework(self.frameworks)

    def tool_name_for(self, node: ast.AST) -> str | None:
        """Return the exposed tool name if ``node`` sits inside a tool function."""
        function_name = self.analysis.enclosing_function(node)
        return self.tool_functions.get(function_name)


@dataclass
class ProjectContext:
    """Whole-project view for project-level rules (missing limits, tracing, metadata)."""

    analyses: list[FileAnalysis]
    config: Config
    frameworks: list[str]

    @property
    def framework(self) -> str | None:
        """The primary framework, if any agent framework was detected."""
        return primary_framework(self.frameworks)

    @property
    def has_agent_framework(self) -> bool:
        """Whether any recognized agent framework is present in the project."""
        return bool(self.frameworks)

    @property
    def anchor_file(self) -> str:
        """A stable file path to anchor project-level findings to."""
        return self.analyses[0].path if self.analyses else "autonomyproof.yaml"

    def code_contains_any(self, needles: list[str]) -> bool:
        """Return ``True`` if any needle appears in the code surface of any file.

        Only executable code tokens are searched — identifiers, dotted call names, keyword
        argument names, and imports — never comments or docstrings, so a control cannot be
        "satisfied" by merely mentioning it in prose.
        """
        lowered = [n.lower() for n in needles]
        for analysis in self.analyses:
            haystack = _code_tokens(analysis)
            if any(needle in haystack for needle in lowered):
                return True
        return False


class Rule:
    """Base class for all rules. Subclasses set the class attributes and ``check``."""

    id: str = ""
    name: str = ""
    default_severity: Severity = Severity.MEDIUM
    description: str = ""
    risk: str = ""
    remediation: list[str] = []
    mappings: Mappings = Mappings()
    project_level: bool = False

    def check(self, ctx: RuleContext) -> Iterable[Finding]:
        """Yield findings for one file. Overridden by per-file rules."""
        return []

    def check_project(self, pctx: ProjectContext) -> Iterable[Finding]:
        """Yield findings for the whole project. Overridden by project-level rules."""
        return []

    def make_project_finding(
        self,
        pctx: ProjectContext,
        *,
        evidence: str,
        pattern: str,
        title: str | None = None,
        description: str | None = None,
        risk: str | None = None,
        remediation: list[str] | None = None,
        severity: Severity | None = None,
    ) -> Finding:
        """Assemble a project-scoped :class:`Finding` anchored to a stable location."""
        return Finding(
            ruleId=self.id,
            severity=severity or self.default_severity,
            title=title or self.name,
            description=description or self.description,
            file=pctx.anchor_file,
            line=1,
            column=0,
            evidence=evidence,
            risk=risk or self.risk,
            remediation=list(remediation if remediation is not None else self.remediation),
            mappings=self.mappings,
            fingerprint=compute_fingerprint(self.id, pctx.anchor_file, "<project>", pattern),
            framework=pctx.framework,
            toolName=None,
        )

    def make_finding(
        self,
        ctx: RuleContext,
        node: ast.AST,
        *,
        evidence: str,
        title: str | None = None,
        description: str | None = None,
        risk: str | None = None,
        remediation: list[str] | None = None,
        severity: Severity | None = None,
        tool_name: str | None = None,
        pattern: str | None = None,
    ) -> Finding:
        """Assemble a :class:`Finding`, applying redaction and computing the fingerprint."""
        function_name = ctx.analysis.enclosing_function(node)
        code_pattern = pattern if pattern is not None else ctx.analysis.snippet(node)
        clean_evidence = redact(evidence) if ctx.config.redact_secrets else evidence
        resolved_tool = tool_name if tool_name is not None else ctx.tool_name_for(node)
        return Finding(
            ruleId=self.id,
            severity=severity or self.default_severity,
            title=title or self.name,
            description=description or self.description,
            file=ctx.analysis.path,
            line=getattr(node, "lineno", 0),
            column=getattr(node, "col_offset", 0),
            evidence=clean_evidence,
            risk=risk or self.risk,
            remediation=list(remediation if remediation is not None else self.remediation),
            mappings=self.mappings,
            fingerprint=compute_fingerprint(
                self.id, ctx.analysis.path, function_name, code_pattern
            ),
            framework=ctx.framework,
            toolName=resolved_tool,
        )
