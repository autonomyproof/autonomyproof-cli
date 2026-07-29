#!/usr/bin/env python3
"""Ground-truth corpus evaluation: precision AND recall per rule.

Each case in ``corpus.yaml`` targets one rule and is labeled ``positive`` (the rule
should fire) or ``negative`` (it must not). We scan each case in isolation and compare
the target rule's presence against the label, then aggregate per-rule TP/FP/FN/TN.

Unlike the real-repo benchmark (precision only, author-labeled samples), this measures
both precision and recall against known ground truth. A single FP or FN fails the run.

Usage:  python benchmark/corpus_eval.py
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from autonomyproof.config import Config  # noqa: E402
from autonomyproof.scanner import Scanner  # noqa: E402

HERE = Path(__file__).resolve().parent


def fired_rules(case: dict[str, object]) -> set[str]:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        code = case.get("code")
        if isinstance(code, str):
            (root / "agent.py").write_text(code, encoding="utf-8")
        files = case.get("files")
        if isinstance(files, dict):
            for name, content in files.items():
                (root / str(name)).write_text(str(content), encoding="utf-8")
        result = Scanner(Config()).scan(root)
        return {f.ruleId for f in result.findings}


def main() -> int:
    manifest = yaml.safe_load((HERE / "corpus.yaml").read_text(encoding="utf-8"))
    cases: list[dict[str, object]] = manifest["cases"]

    stats: dict[str, dict[str, int]] = {}
    mislabels: list[str] = []
    for case in cases:
        rule = str(case["rule"])
        label = str(case["label"])
        hit = rule in fired_rules(case)
        s = stats.setdefault(rule, {"tp": 0, "fp": 0, "fn": 0, "tn": 0})
        if label == "positive":
            if hit:
                s["tp"] += 1
            else:
                s["fn"] += 1
                mislabels.append(f"FN  {case['id']:24} {rule} should fire but did not")
        else:
            if hit:
                s["fp"] += 1
                mislabels.append(f"FP  {case['id']:24} {rule} fired but should not")
            else:
                s["tn"] += 1

    rows = []
    tot = {"tp": 0, "fp": 0, "fn": 0, "tn": 0}
    for rule in sorted(stats):
        s = stats[rule]
        for k in tot:
            tot[k] += s[k]
        prec = s["tp"] / (s["tp"] + s["fp"]) if (s["tp"] + s["fp"]) else 1.0
        rec = s["tp"] / (s["tp"] + s["fn"]) if (s["tp"] + s["fn"]) else 1.0
        f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
        rows.append((rule, s, prec, rec, f1))

    p = tot["tp"] / (tot["tp"] + tot["fp"]) if (tot["tp"] + tot["fp"]) else 1.0
    r = tot["tp"] / (tot["tp"] + tot["fn"]) if (tot["tp"] + tot["fn"]) else 1.0
    n_cases = len(cases)

    lines = [
        "# Labeled-corpus results (ground-truth precision & recall)",
        "",
        f"**Cases:** {n_cases} · **Rules covered:** {len(stats)} · "
        f"**Overall precision:** {p:.3f} · **Overall recall:** {r:.3f}",
        "",
        "| Rule | pos | neg | TP | FP | FN | Precision | Recall | F1 |",
        "|---|--:|--:|--:|--:|--:|--:|--:|--:|",
    ]
    for rule, s, prec, rec, f1 in rows:
        pos, neg = s["tp"] + s["fn"], s["fp"] + s["tn"]
        lines.append(
            f"| {rule} | {pos} | {neg} | {s['tp']} | {s['fp']} | {s['fn']} | "
            f"{prec:.2f} | {rec:.2f} | {f1:.2f} |"
        )
    lines += [
        "",
        f"**Totals:** TP {tot['tp']} · FP {tot['fp']} · FN {tot['fn']} · TN {tot['tn']}",
        "",
        "Precision = of the cases where a rule fired, how many were true positives. "
        "Recall = of the cases where a rule should fire, how many did. "
        "Reproduce with `python benchmark/corpus_eval.py`.",
        "",
    ]
    (HERE / "CORPUS_RESULTS.md").write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(f"Cases: {n_cases} | precision {p:.3f} | recall {r:.3f} | "
          f"FP {tot['fp']} | FN {tot['fn']}")
    if mislabels:
        print("\n".join(mislabels))
        print(f"\n{len(mislabels)} case(s) did not match ground truth (FP/FN above).")
        return 1
    print("All cases match ground truth. Wrote benchmark/CORPUS_RESULTS.md")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
