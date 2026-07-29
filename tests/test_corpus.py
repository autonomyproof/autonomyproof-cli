"""Ground-truth corpus as an enforced regression gate.

Each labeled case in ``benchmark/corpus.yaml`` becomes a test: a ``positive`` case must
make its target rule fire, a ``negative`` case must not. This keeps precision and recall
at 1.0 on the corpus across every change.
"""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Any

import pytest
import yaml

from autonomyproof.config import Config
from autonomyproof.scanner import Scanner

_CORPUS = Path(__file__).resolve().parent.parent / "benchmark" / "corpus.yaml"
_CASES: list[dict[str, Any]] = yaml.safe_load(_CORPUS.read_text(encoding="utf-8"))["cases"]


def _fired_rules(case: dict[str, Any]) -> set[str]:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        code = case.get("code")
        if isinstance(code, str):
            (root / "agent.py").write_text(code, encoding="utf-8")
        for name, content in (case.get("files") or {}).items():
            (root / str(name)).write_text(str(content), encoding="utf-8")
        return {f.ruleId for f in Scanner(Config()).scan(root).findings}


@pytest.mark.parametrize("case", _CASES, ids=[c["id"] for c in _CASES])
def test_corpus_case_matches_ground_truth(case: dict[str, Any]) -> None:
    fired = case["rule"] in _fired_rules(case)
    should_fire = case["label"] == "positive"
    assert fired is should_fire
