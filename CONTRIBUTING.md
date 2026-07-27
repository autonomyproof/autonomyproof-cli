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

1. Add a `Rule` subclass to the matching thematic module under `src/autonomyproof/rules/`
   (`execution.py`, `filesystem.py`, `network.py`, `data.py`, `agent_controls.py`,
   `metadata.py`), or create a new module for a new theme. One class per rule ID.
2. Register it in `rules/registry.py`.
3. Add a positive fixture (triggers) and a negative fixture (does not) under `tests/`.
4. Document the rule ID, severity, and framework mappings.

## Reporting a security vulnerability

Do **not** open a public issue. Email `security@autonomyproof.io`. See [SECURITY.md](SECURITY.md).
