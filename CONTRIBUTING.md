# Contributing to AutonomyProof Community

Thanks for helping make autonomous agents safer to deploy.

## Ground rules

- All contributions are licensed under **Apache-2.0**.
- Every commit must be **signed off** under the [Developer Certificate of Origin](DCO):
  use `git commit -s`. CI rejects unsigned commits.
- Be respectful. See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## Development setup

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pre-commit install
```

## Quality gates (all enforced in CI)

| Gate            | Command                    |
| --------------- | -------------------------- |
| Lint            | `ruff check .`             |
| Format          | `ruff format --check .`    |
| Types           | `mypy`                     |
| Tests           | `pytest`                   |
| Coverage (100%) | enforced by `pytest` addopts (`--cov-fail-under=100`) |

**Coverage is 100% and non-negotiable.** Every rule and code path must have a test.
If a line genuinely cannot be covered, justify it with `# pragma: no cover` in the PR.

## Adding a security rule

This is the best first contribution — small, self-contained, and objectively gradeable by
the benchmark. Looking for something to build? See [ROADMAP.md](ROADMAP.md) for a wishlist of
`good first issue` rules.

**The bar:** a rule must add **zero false positives** on the real-repo benchmark. A detection
that can't stay clean on real code doesn't ship — that discipline is the whole point.

### The six-step loop

1. **Write the rule.** Add a `Rule` subclass to the matching module under
   `src/autonomyproof/rules/` (`execution.py`, `filesystem.py`, `network.py`, `data.py`,
   `agent_controls.py`, `metadata.py`, `harness.py`), or a new module for a new theme. One
   class per rule ID. Skeleton:

   ```python
   class MyNewRule(Rule):
       """AG034 — one-line summary."""

       id = "AG034"
       name = "Human-readable name"
       default_severity = Severity.HIGH
       description = "What the rule detects."
       risk = "Why it is dangerous."
       remediation = ["Do X", "Prefer Y"]
       mappings = Mappings(owaspAgentic=["Excessive agency"], mitre=["T1485"])

       def check(self, ctx: RuleContext) -> Iterable[Finding]:
           for call in ctx.analysis.calls:
               if ctx.analysis.resolve_call(call) == "some.dangerous.sink":
                   yield self.make_finding(ctx, call, evidence="what was found")
   ```

   Use `ctx.tool_functions` to scope a rule to registered agent tools, and the shared helpers
   in `astutils.py` / `rules/sources.py` (import resolution, source classification) — that's
   how rules stay zero-FP. Read a rule near your theme first; they're short.

2. **Register it** in `rules/registry.py` (import + add to the ID-ordered list).
3. **Unit tests** — a **positive** fixture (fires) and at least one **negative** (a benign
   look-alike that must not fire) in the matching `tests/test_rules_*.py`. Use the `run_rule`
   helper. Coverage is 100% and enforced.
4. **Ground-truth cases** — add a positive and a negative to `benchmark/corpus.yaml`. These
   are enforced in CI (`tests/test_corpus.py`): precision and recall must stay 1.000.
5. **Prove zero-FP on real code** — run `python benchmark/run.py` and confirm your rule adds
   no false positives across the 41 repos. Include the count in your PR.
6. **Run the gates** — `pytest`, `ruff check .`, `ruff format .`, `mypy`. All green.

## Reporting a security vulnerability

Do **not** open a public issue. Email `security@autonomyproof.io`. See [SECURITY.md](SECURITY.md).
