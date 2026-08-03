# Roadmap & rule wishlist

AutonomyProof detects the **authority an AI agent holds in code** — can it move money, run
shell, wipe data, reach any URL, rewrite its own guardrails — and fails the PR that quietly
grants new dangerous authority. The engine ships ~33 rules today; the list below is where
we'd love help.

## Why contributing a rule is a great first PR

Every rule is small and self-contained. Adding one is a tight, well-scoped loop:

1. One `Rule` subclass in the matching module under `src/autonomyproof/rules/`.
2. A **positive** test (it fires) and a **negative** test (it doesn't).
3. A positive + negative case in `benchmark/corpus.yaml`.
4. Run `python benchmark/run.py` — your rule must add **zero false positives** on 41 real repos.

That last step is the whole game: **a detection that can't stay clean on real code doesn't
ship.** The benchmark tells you objectively whether your rule is good — no bikeshedding.
Full walkthrough in [CONTRIBUTING.md](CONTRIBUTING.md#adding-a-security-rule).

## Wanted rules (`help wanted` / `good first issue`)

Each of these is a bite-sized, zero-FP-friendly detection. Pick one, open an issue with the
[rule proposal form](.github/ISSUE_TEMPLATE/propose-a-rule.yml), and go.

| Idea | Pattern to detect | Why it stays zero-FP |
|---|---|---|
| **Cloud resource destruction** | An agent tool calling `boto3` / GCP / Azure delete/terminate (`delete_bucket`, `terminate_instances`, `delete_*`) | Match specific unambiguous SDK method names, scoped to tool functions (the cloud analog of AG033) |
| **Kubernetes destruction** | `delete_namespaced_*`, `delete_collection_*` from the k8s client inside a tool | Method names are specific; tool-scoped |
| **Money movement without approval** | Stripe/PayPal `Refund.create`, `Transfer.create`, `Payout.create` in a tool with no approval gate | Named SDK calls; reuse the AG007 approval-marker suppression |
| **Repo mutation by code agents** | `git push --force`, GitPython `repo.push()`, force-push via subprocess in a tool | Specific verbs; tool-scoped |
| **Persistence via dotfiles** | Writing to `~/.ssh/authorized_keys`, crontab, `.bashrc`, systemd units | Specific target paths only |
| **Supply-chain RCE** | Download → deserialize: a URL fetched then passed to `pickle`/`torch.load`/`joblib.load` | Requires both a network source and a deser sink in one flow |
| **Runtime package install** | `pip install` / `npm install` of a model-controlled package via subprocess | shell/subprocess + install verb + non-constant arg |
| **Full-environment passthrough** | `subprocess(..., env=os.environ)` feeding a shell/interpreter tool | Exact kwarg shape |
| **Secret read-and-return** | A tool that reads `.env`/keyring/credential files and returns the value to the model | Credential-path read (AG004) whose value reaches a `return` |
| **World-writable permissions** | `os.chmod(path, 0o777)` / overly-permissive modes | Literal mode check |
| **Model-controlled file write** | `open(path, "w")` / `Path(path).write_*` on a model-controlled path inside a tool | The write analog of AG003; tool-scoped + taint-classified |

## Bigger pieces (discussion first)

- **Cross-function taint** — today source-tracking is single-function; whole-program taint
  would close the AG005/AG012 config-vs-model gap noted in the benchmark. Start a
  [discussion](https://github.com/autonomyproof/autonomyproof-cli/discussions) before diving in.
- **More version-validated CVEs** — extend `cve.py`'s registry with new agent-framework
  advisories (version ranges verified). Each is a small, high-signal addition.
- **JavaScript/TypeScript agents** — the rule model generalizes; a TS front-end is a large
  but high-impact effort.

Not sure where to start? Open a [discussion](https://github.com/autonomyproof/autonomyproof-cli/discussions)
and we'll help you scope something.
