"""Core data models shared across the scanner, reporters, and API client."""

from __future__ import annotations

import enum
from dataclasses import asdict, dataclass, field


class Severity(enum.Enum):
    """Finding severity, ordered from most to least serious."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

    @property
    def rank(self) -> int:
        """Numeric rank where higher means more severe (critical=4 .. low=1)."""
        return {"critical": 4, "high": 3, "medium": 2, "low": 1}[self.value]

    @property
    def score_deduction(self) -> int:
        """Points removed from the readiness score for one finding of this severity."""
        return {"critical": 20, "high": 10, "medium": 5, "low": 2}[self.value]

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, Severity):  # pragma: no cover - guarded by type checker
            return NotImplemented
        return self.rank < other.rank


@dataclass(frozen=True)
class Mappings:
    """Compliance / framework mappings attached to a finding.

    ``mitre`` holds MITRE technique IDs — ATLAS (``AML.T*``) for AI/ML-specific
    techniques and ATT&CK (``T*``) for classic ones. ``cve`` lists directly-related
    CVE IDs. Both are populated only where a genuine mapping exists.
    """

    owaspAgentic: list[str] = field(default_factory=list)
    nistAiRmf: list[str] = field(default_factory=list)
    iso42001Alignment: list[str] = field(default_factory=list)
    mitre: list[str] = field(default_factory=list)
    cve: list[str] = field(default_factory=list)


@dataclass
class Finding:
    """A single detected issue, matching the published finding schema (PRD §12)."""

    ruleId: str
    severity: Severity
    title: str
    description: str
    file: str
    line: int
    column: int
    evidence: str
    risk: str
    remediation: list[str]
    mappings: Mappings
    fingerprint: str
    framework: str | None = None
    toolName: str | None = None
    category: str = "Attack vector"

    def to_dict(self) -> dict[str, object]:
        """Serialize to a JSON-ready dict with the severity as a string."""
        data = asdict(self)
        data["severity"] = self.severity.value
        return data


@dataclass
class Capability:
    """An observed agent capability (e.g. shell execution, network egress)."""

    name: str
    detail: str


@dataclass
class ScanError:
    """A file that could not be parsed or was skipped, with the reason."""

    file: str
    message: str


@dataclass
class ProjectMetadata:
    """Project / repository identity carried into the report and cloud payload."""

    name: str
    repository: str | None = None
    branch: str | None = None
    commit: str | None = None
    agent_name: str | None = None
    agent_owner: str | None = None
    agent_purpose: str | None = None
    environment: str | None = None
    criticality: str | None = None


@dataclass
class ScanResult:
    """The complete outcome of a scan."""

    scan_id: str
    scanner_version: str
    project: ProjectMetadata
    frameworks: list[str]
    tools: list[str]
    capabilities: list[Capability]
    findings: list[Finding]
    score: int
    risk_level: str
    files_scanned: int
    rules_executed: list[str]
    duration_ms: int
    errors: list[ScanError] = field(default_factory=list)

    def severity_counts(self) -> dict[str, int]:
        """Return a count of findings per severity value."""
        counts = {s.value: 0 for s in Severity}
        for finding in self.findings:
            counts[finding.severity.value] += 1
        return counts

    def category_counts(self) -> dict[str, int]:
        """Return a count of findings per assessment lens, in display order."""
        counts: dict[str, int] = {}
        for finding in self.findings:
            counts[finding.category] = counts.get(finding.category, 0) + 1
        return counts
