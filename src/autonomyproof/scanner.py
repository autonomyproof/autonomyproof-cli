"""Scan orchestration: parse files, run rules, aggregate a :class:`ScanResult`."""

from __future__ import annotations

import time
import uuid
from pathlib import Path

from autonomyproof import __version__
from autonomyproof.astutils import FileAnalysis
from autonomyproof.config import Config
from autonomyproof.discovery import (
    dependency_names,
    discover_files,
    read_repo_metadata,
)
from autonomyproof.frameworks import detect_frameworks
from autonomyproof.models import (
    Capability,
    Finding,
    ProjectMetadata,
    ScanError,
    ScanResult,
)
from autonomyproof.rules.base import ProjectContext, RuleContext
from autonomyproof.rules.registry import all_rules
from autonomyproof.scoring import compute_score, risk_level
from autonomyproof.tools import detect_tools

# rule id -> high-level capability surfaced when that rule fires
_RULE_CAPABILITY = {
    "AG001": ("Shell execution", "Agent can run operating-system commands"),
    "AG002": ("Dynamic code execution", "Agent can execute arbitrary code"),
    "AG003": ("Filesystem access", "Agent can read or write files"),
    "AG004": ("Credential access", "Agent can reach credential paths"),
    "AG005": ("Network egress", "Agent can make outbound requests"),
    "AG006": ("Internal network access", "Agent can reach internal hosts"),
    "AG012": ("Database access", "Agent can query a database"),
    "AG016": ("Sub-agent creation", "Agent can spawn other agents"),
}


class Scanner:
    """Runs the full rule catalogue against a repository."""

    def __init__(self, config: Config) -> None:
        self.config = config
        self.rules = all_rules()

    def scan(self, root: Path, project_name: str | None = None) -> ScanResult:
        """Scan ``root`` and return a fully populated :class:`ScanResult`."""
        start = time.perf_counter()
        files = discover_files(root, self.config.include, self.config.exclude)
        python_files = [p for p in files if p.suffix == ".py"]

        analyses: list[FileAnalysis] = []
        errors: list[ScanError] = []
        for path in python_files:
            rel = path.relative_to(root).as_posix()
            try:
                source = path.read_text(encoding="utf-8")
                analyses.append(FileAnalysis.build(rel, source))
            except (SyntaxError, UnicodeDecodeError, ValueError) as exc:
                errors.append(ScanError(file=rel, message=str(exc)))

        frameworks = detect_frameworks(analyses, dependency_names(root))
        findings = self._run_rules(analyses, frameworks)
        findings = self._apply_policy(findings)
        findings.sort(key=lambda f: (-f.severity.rank, f.ruleId, f.file, f.line))

        tools = sorted({name for a in analyses for name in detect_tools(a).values()})
        score = compute_score(findings)
        duration_ms = int((time.perf_counter() - start) * 1000)

        return ScanResult(
            scan_id=str(uuid.uuid4()),
            scanner_version=__version__,
            project=self._project_metadata(root, project_name),
            frameworks=frameworks,
            tools=tools,
            capabilities=self._capabilities(frameworks, tools, findings),
            findings=findings,
            score=score,
            risk_level=risk_level(score),
            files_scanned=len(python_files),
            rules_executed=[rule.id for rule in self.rules],
            duration_ms=duration_ms,
            errors=errors,
        )

    def _run_rules(self, analyses: list[FileAnalysis], frameworks: list[str]) -> list[Finding]:
        findings: list[Finding] = []
        for analysis in analyses:
            ctx = RuleContext(
                analysis=analysis,
                config=self.config,
                frameworks=frameworks,
                tool_functions=detect_tools(analysis),
            )
            for rule in self.rules:
                if not rule.project_level:
                    findings.extend(rule.check(ctx))

        pctx = ProjectContext(analyses=analyses, config=self.config, frameworks=frameworks)
        for rule in self.rules:
            if rule.project_level:
                findings.extend(rule.check_project(pctx))
        return findings

    def _apply_policy(self, findings: list[Finding]) -> list[Finding]:
        ignored = {rule_id.upper() for rule_id in self.config.ignored_rules}
        accepted = set(self.config.accepted_findings)
        return [f for f in findings if f.ruleId not in ignored and f.fingerprint not in accepted]

    def _project_metadata(self, root: Path, project_name: str | None) -> ProjectMetadata:
        repo = read_repo_metadata(root)
        return ProjectMetadata(
            name=project_name or self.config.project_name,
            repository=None,
            branch=repo.branch,
            commit=repo.commit,
            agent_name=self.config.agent_name,
            agent_owner=self.config.agent_owner,
            agent_purpose=self.config.agent_purpose,
            environment=self.config.environment,
            criticality=self.config.criticality,
        )

    @staticmethod
    def _capabilities(
        frameworks: list[str], tools: list[str], findings: list[Finding]
    ) -> list[Capability]:
        capabilities: list[Capability] = []
        seen: set[str] = set()
        for framework in frameworks:
            capabilities.append(Capability(name="Framework", detail=framework))
        for tool in tools:
            capabilities.append(Capability(name="Agent tool", detail=tool))
        for finding in findings:
            entry = _RULE_CAPABILITY.get(finding.ruleId)
            if entry and entry[0] not in seen:
                seen.add(entry[0])
                capabilities.append(Capability(name=entry[0], detail=entry[1]))
        return capabilities
