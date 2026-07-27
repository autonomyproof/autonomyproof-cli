"""Authority-regression baseline — fail the PR that grants *new* authority.

A baseline records the fingerprints of the findings that already exist on a
known-good ref. A later scan can then be gated so that it fails only when it
introduces findings whose fingerprints are absent from the baseline — i.e. when
a change grants new unsafe authority, rather than for pre-existing debt.

Fingerprints are stable across unrelated line edits (see :mod:`fingerprint`), so
a finding that merely moves does not read as new.
"""

from __future__ import annotations

import json
from pathlib import Path

from autonomyproof.models import Finding, ScanResult

BASELINE_FILENAME = "autonomyproof-baseline.json"
BASELINE_VERSION = 1


class BaselineError(Exception):
    """Raised when a baseline file cannot be parsed or is structurally invalid."""


def build_baseline(result: ScanResult) -> dict[str, object]:
    """Build a JSON-ready, deterministically-ordered baseline from a scan result."""
    ordered = sorted(result.findings, key=lambda f: (f.fingerprint, f.ruleId, f.file))
    entries = [{"fingerprint": f.fingerprint, "ruleId": f.ruleId, "file": f.file} for f in ordered]
    return {
        "version": BASELINE_VERSION,
        "scannerVersion": result.scanner_version,
        "findings": entries,
    }


def write_baseline(result: ScanResult, path: Path) -> Path:
    """Write ``result``'s baseline to ``path`` and return the path written."""
    document = build_baseline(result)
    path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    return path


def load_baseline_fingerprints(path: Path) -> set[str]:
    """Return the set of fingerprints recorded in the baseline at ``path``.

    Raises :class:`BaselineError` if the file is not valid JSON or does not have
    the expected shape.
    """
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise BaselineError(f"{path} is not valid JSON: {exc}") from exc
    if not isinstance(document, dict):
        raise BaselineError(f"{path} must contain a JSON object.")
    findings = document.get("findings")
    if not isinstance(findings, list):
        raise BaselineError(f"{path} is missing a 'findings' list.")
    fingerprints: set[str] = set()
    for entry in findings:
        fingerprint = entry.get("fingerprint") if isinstance(entry, dict) else None
        if not isinstance(fingerprint, str):
            raise BaselineError(f"{path} has an entry without a string 'fingerprint'.")
        fingerprints.add(fingerprint)
    return fingerprints


def new_findings(findings: list[Finding], baseline: set[str]) -> list[Finding]:
    """Return the findings whose fingerprint is not present in ``baseline``."""
    return [finding for finding in findings if finding.fingerprint not in baseline]
