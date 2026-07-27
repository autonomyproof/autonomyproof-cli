"""Authority-regression diff — what a code change *added* vs. a baseline (the PR gate).

This is the mechanism behind the product thesis: fail a change that grants the agent new
unsafe authority. Findings are matched by fingerprint (stable across unrelated edits), so a
"new" finding means this change genuinely introduced authority that was not there before.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from autonomyproof.models import Finding, Severity


@dataclass
class AuthorityDiff:
    """Classification of the current findings against a baseline."""

    new: list[Finding]  # unsafe authority introduced by this change
    existing: list[Finding]  # authority already present in the baseline
    fixed: int  # baseline findings no longer present

    def has_new_at_or_above(self, threshold: Severity) -> bool:
        """Whether any newly-introduced finding is at or above ``threshold``."""
        return any(finding.severity.rank >= threshold.rank for finding in self.new)


def load_baseline_fingerprints(path: Path) -> set[str]:
    """Read a prior ``autonomyproof-report.json`` and return its finding fingerprints."""
    data = json.loads(path.read_text(encoding="utf-8"))
    findings = data.get("findings", []) if isinstance(data, dict) else []
    return {
        finding["fingerprint"]
        for finding in findings
        if isinstance(finding, dict) and "fingerprint" in finding
    }


def compare(baseline_fingerprints: set[str], current: list[Finding]) -> AuthorityDiff:
    """Classify ``current`` findings as new / existing, and count what was fixed."""
    new = [f for f in current if f.fingerprint not in baseline_fingerprints]
    existing = [f for f in current if f.fingerprint in baseline_fingerprints]
    current_fingerprints = {f.fingerprint for f in current}
    fixed = len(baseline_fingerprints - current_fingerprints)
    return AuthorityDiff(new=new, existing=existing, fixed=fixed)
