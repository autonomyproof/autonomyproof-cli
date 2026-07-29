"""Version-validated CVE matching for agent-framework dependencies.

A CVE is reported only when a project pins a dependency version that provably falls in a
vulnerable range. No version, an unparseable version, or a version outside the range means
no claim — so a CVE finding is never a guess.
"""

from __future__ import annotations

from dataclasses import dataclass

from packaging.specifiers import SpecifierSet
from packaging.version import InvalidVersion, Version


@dataclass(frozen=True)
class CveRecord:
    """A known CVE with the affected package and its vulnerable version ranges."""

    cve: str
    package: str
    ranges: tuple[str, ...]
    summary: str
    mitre: tuple[str, ...]


@dataclass(frozen=True)
class CveMatch:
    """A confirmed match: the project pins ``version`` and it is in a vulnerable range."""

    cve: str
    package: str
    version: str
    summary: str
    mitre: list[str]


# Curated, version-scoped registry. Ranges taken directly from the published advisories.
_CVE_DB: tuple[CveRecord, ...] = (
    CveRecord(
        cve="CVE-2025-68664",
        package="langchain-core",
        ranges=("<0.3.81", ">=1.0.0,<1.2.5"),
        summary="LangChain serialization injection (LangGrinch): secret exfiltration / RCE",
        mitre=("AML.T0010",),
    ),
    CveRecord(
        cve="CVE-2026-44843",
        package="langchain-core",
        ranges=("<0.3.85", ">=1.0.0,<1.3.3"),
        summary="LangChain unsafe deserialization via overly broad load() allowlists",
        mitre=("AML.T0010",),
    ),
    CveRecord(
        cve="CVE-2025-3248",
        package="langflow",
        ranges=("<1.3.0",),
        summary="Langflow unauthenticated RCE via /api/v1/validate/code (exec of user code)",
        mitre=("T1190",),  # Exploit Public-Facing Application
    ),
)


def _normalize(name: str) -> str:
    return name.lower().replace("_", "-")


def known_vulnerabilities(versions: dict[str, str]) -> list[CveMatch]:
    """Return CVE matches for the pinned ``versions`` (package -> exact version)."""
    normalized = {_normalize(name): ver for name, ver in versions.items()}
    matches: list[CveMatch] = []
    for record in _CVE_DB:
        installed = normalized.get(_normalize(record.package))
        if installed is None:
            continue
        try:
            parsed = Version(installed)
        except InvalidVersion:
            continue
        if any(parsed in SpecifierSet(spec) for spec in record.ranges):
            matches.append(
                CveMatch(
                    cve=record.cve,
                    package=record.package,
                    version=installed,
                    summary=record.summary,
                    mitre=list(record.mitre),
                )
            )
    return matches
