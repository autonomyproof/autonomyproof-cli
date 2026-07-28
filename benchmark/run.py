#!/usr/bin/env python3
"""Real-world benchmark harness.

Shallow-clones each repository in ``repos.txt``, runs the AutonomyProof scanner over
its Python source, and aggregates findings per rule. Writes ``results.json`` (machine
readable) and ``findings.jsonl`` (one finding per line, for manual precision labeling).

Usage:  python benchmark/run.py [--keep-clones] [--limit N]

This measures how the scanner behaves on real code. Recall is NOT measured here (that
needs labeled ground truth — see the vulnerable example for a recall smoke test);
precision is estimated by manually labeling a sample of the emitted findings.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from autonomyproof.config import Config  # noqa: E402
from autonomyproof.scanner import Scanner  # noqa: E402

HERE = Path(__file__).resolve().parent


def load_repos(limit: int | None) -> list[tuple[str, str]]:
    repos: list[tuple[str, str]] = []
    for line in (HERE / "repos.txt").read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        name, url = line.split()
        repos.append((name, url))
    return repos[:limit] if limit else repos


def clone(url: str, dest: Path) -> bool:
    result = subprocess.run(
        ["git", "clone", "--depth", "1", "--quiet", url, str(dest)],
        capture_output=True,
        text=True,
    )
    return result.returncode == 0


def _source_line(root: Path, rel: str, line: int) -> str:
    try:
        lines = (root / rel).read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return ""
    return lines[line - 1].strip() if 1 <= line <= len(lines) else ""


def scan_repo(name: str, path: Path) -> dict[str, object]:
    result = Scanner(Config()).scan(path)
    findings = [
        {
            "repo": name,
            "ruleId": f.ruleId,
            "severity": f.severity.value,
            "file": f.file,
            "line": f.line,
            "evidence": f.evidence,
            "code": _source_line(path, f.file, f.line),
        }
        for f in result.findings
    ]
    return {"files_scanned": result.files_scanned, "findings": findings}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--keep-clones", action="store_true")
    args = parser.parse_args()

    repos = load_repos(args.limit)
    all_findings: list[dict[str, object]] = []
    per_repo: list[dict[str, object]] = []
    workroot = Path(tempfile.mkdtemp(prefix="ap-bench-"))
    print(f"Cloning + scanning {len(repos)} repos into {workroot}\n")

    for name, url in repos:
        dest = workroot / name
        print(f"  {name:16} cloning… ", end="", flush=True)
        if not clone(url, dest):
            print("CLONE FAILED (skipped)")
            per_repo.append({"repo": name, "status": "clone_failed"})
            continue
        scanned = scan_repo(name, dest)
        findings = scanned["findings"]
        assert isinstance(findings, list)
        all_findings.extend(findings)
        counts: dict[str, int] = {}
        for f in findings:
            counts[f["ruleId"]] = counts.get(f["ruleId"], 0) + 1
        per_repo.append(
            {
                "repo": name,
                "status": "ok",
                "files_scanned": scanned["files_scanned"],
                "findings": len(findings),
                "by_rule": dict(sorted(counts.items())),
            }
        )
        print(f"{scanned['files_scanned']:>5} files, {len(findings):>4} findings")
        if not args.keep_clones:
            subprocess.run(["rm", "-rf", str(dest)])

    rule_totals: dict[str, int] = {}
    for f in all_findings:
        rule_totals[f["ruleId"]] = rule_totals.get(f["ruleId"], 0) + 1

    results = {
        "repo_count": len([r for r in per_repo if r.get("status") == "ok"]),
        "total_files": sum(int(r.get("files_scanned", 0)) for r in per_repo),
        "total_findings": len(all_findings),
        "by_rule": dict(sorted(rule_totals.items())),
        "per_repo": per_repo,
    }
    (HERE / "results.json").write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
    with (HERE / "findings.jsonl").open("w", encoding="utf-8") as fh:
        for f in all_findings:
            fh.write(json.dumps(f) + "\n")

    print("\n=== totals ===")
    print(json.dumps(results["by_rule"], indent=2))
    print(
        f"\n{results['total_findings']} findings over {results['total_files']} files "
        f"in {results['repo_count']} repos"
    )
    print("Wrote benchmark/results.json and benchmark/findings.jsonl")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
