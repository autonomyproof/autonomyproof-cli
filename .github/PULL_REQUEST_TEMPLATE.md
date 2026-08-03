<!-- Thanks for contributing! Keep PRs focused — one rule or one fix per PR is ideal. -->

## What this changes

<!-- One or two sentences. Link the issue it closes, e.g. "Closes #123". -->

## Checklist

- [ ] Commits are signed off (`git commit -s`) — required by CI (DCO)
- [ ] `pytest` passes (100% branch coverage is enforced)
- [ ] `ruff check .` and `ruff format --check .` pass
- [ ] `mypy` passes

### If this adds or changes a detection rule

- [ ] Added a **positive** test (the rule fires) and a **negative** test (it does not)
- [ ] Added a positive and negative case to `benchmark/corpus.yaml`
- [ ] Ran `python benchmark/run.py` and confirmed **no new false positives** on the real-repo corpus
- [ ] Registered the rule in `rules/registry.py` and added standards mappings

<!-- The zero-false-positive bar is the whole point of the project. A rule that can't
     stay clean on real code won't be merged — and that's a feature, not a rejection. -->
