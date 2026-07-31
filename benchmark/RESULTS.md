# AutonomyProof real-world benchmark

**Scanner version:** 0.12.0 · **Snapshot date:** 2026-07-28 · **Reproduce:** `python benchmark/run.py`

This measures how the scanner behaves on **real, unmodified open-source code** — **41 public
agent / MCP / framework repositories (~35,000 Python files)**, shallow-cloned and scanned in
full (including their tests, scripts, and examples). It is deliberately published
warts-and-all: a static-analysis tool that hides its false-positive rate isn't trustworthy.

## Corpus

41 repositories, **34,722 Python files**, **9,148 findings** — full per-repo breakdown in
`benchmark/results.json`. Repos include the MCP python-sdk + servers, crewAI, langgraph,
openai-agents, pydantic-ai, smolagents, autogen, agno, haystack, litellm, guardrails, letta,
livekit agents, browser-use, gpt-researcher, semantic-kernel, promptflow, langflow, dspy,
mem0, marvin, and more. The list is trivially extensible (edit `benchmark/repos.txt`; any repo
that fails to clone is skipped).

### Version-validated CVEs found in the wild (AG026)
The version-gated CVE check found **real vulnerable dependency pins** in popular repos — a
zero-FP, high-signal result:
- **letta** pins `langchain-core==0.3.75` → CVE-2025-68664 **and** CVE-2026-44843
- **dspy** pins `langchain-core==1.0.4` → CVE-2025-68664 **and** CVE-2026-44843
- **anthropic-cookbook** pins `langchain-core==1.1.0` → CVE-2025-68664 **and** CVE-2026-44843
- **camel** pins `gradio==3.18.0` → CVE-2025-48889 (arbitrary file read)

Both versions are provably inside the published vulnerable ranges. This is what AG026 is for:
it only fires when the pinned version is known-vulnerable, so a hit is a fact, not a guess.

## Findings per rule (whole repo, incl. tests/scripts)

| Rule | Count | Precision read (author-labeled sample) |
|---|---:|---|
| AG002 dynamic code (eval/exec) | 94 | **High** — real `eval`/`exec` calls |
| AG021 insecure deserialization | 37 | **High** — real `pickle.loads` / `yaml.load` |
| AG022 disabled TLS verify | 22 | **High** — real `verify=False` |
| AG023 template injection | 88 | **High** — real jinja Template/render_template_string |
| AG007 dangerous-op-without-approval | 46 | **High** — real tools with no approval |
| AG024 dangerous framework flag | 8 | **High** — literal `trust_remote_code=True` |
| AG025 interpreter tool exposed | 115 | **High** — real `ShellTool` / `ComputerTool` (approval-gated suppressed) |
| AG026 known-vulnerable dependency | 7 | **High** — real vulnerable pins: langchain-core (letta, dspy, anthropic-cookbook), gradio (camel) |
| AG027 sandbox disabled | 0 | **N/A** — no `use_docker=False` in these repos |
| AG028 code-executing agent/chain | 4 | **High** — real `create_csv_agent` / `LLMMathChain` / `create_sql_agent` (langflow) |
| AG029 unrestricted HTTP request tool | 1 | **High** — real `TextRequestsWrapper` (langflow) |
| AG030 public share tunnel | 0 | **N/A** — no `.launch(share=True)` in these repos |
| AG031 CORS wildcard + credentials | 5 | **High** — real FastAPI misconfigs (autogen-core, litellm, llama-deploy) |
| AG032 disabled safety filter | 1 | **High** — real `HarmBlockThreshold.BLOCK_NONE` (pipecat) |
| AG018 missing timeout | 1067 | **High** — factual (no `timeout=`) |
| AG005 unrestricted HTTP | 752 | **Medium** — dynamic URLs are TP; config/`self.x` URLs are FP |
| AG012 model-controlled SQL | 786 | **Medium** — f-string/var queries TP |
| AG003 filesystem | 2035 | **Low–Medium** — flags build scripts, tests, config loads |
| AG019 destructive command | 300 | **Low** — matches ordinary `DELETE FROM` / `DROP` SQL |

### A rule the benchmark rejected (AG030)
A proposed **AG030 (dynamic import of a model-controlled module)** was implemented, then
**dropped** when this benchmark showed it firing **224 times** — almost all benign plugin
loading like `importlib.import_module(f"stories.{name}")`, where the name comes from a registry
or f-string, not model input. It could not meet the zero-false-positive bar, so it did not ship.
The benchmark is the gate: a rule that can't stay zero-FP on real code is removed, not shipped.

### Precision sampling method
Author-adjudicated, ~5–8 findings per rule read against their actual source line. This is a
**small, single-reviewer sample on whole repositories** (tests and scripts included), so treat
it as directional, not a certified precision number. Recall is **not** measured here — that
needs labeled ground truth; see the recall note below.

## False-positive classes this benchmark found — and the fixes shipped

The run exposed concrete FP classes. Each was fixed and re-measured on the identical corpus:

| Fix | Before | After | What it was |
|---|---:|---:|---|
| **AG007** scoped to detected tool functions only | 2,443 | **27** | fired on every ordinary function named execute/delete/send, not agent tools |
| **AG023** scoped `from_string` to jinja `Environment` | 33 | **2** | `RunState.from_string(...)` (a deserializer) matched as template injection |
| **AG012** suppress parameterized `execute(q, params)` + unwrap `text("const")` | 569 | **332** | bound-parameter queries and hardcoded SQL flagged as model-controlled |

Total findings dropped **4,750 → 2,068** across these fixes (−56%), with no loss on the
true-positive samples. AG007 alone went from the dominant noise source to 27 genuine
tool-level findings.

## Known-noisy rules (not yet fixed — honestly flagged)

- **AG019** matches destructive *SQL* (`DELETE FROM`, `DROP`) as if it were a destructive shell
  command. It should distinguish SQL context from shell strings.
- **AG003** is accurate by its own definition (a non-constant path reaches a file op) but has no
  reachability tiering, so build scripts and tests dominate its volume on library repos.
- **AG005/AG012** still surface some config-sourced URLs and dynamic-but-safe queries; the
  single-function taint helps but cross-function taint would close the rest.

## Recall (separate, ground-truth)

Recall is measured on the bundled labeled example `examples/vulnerable-langgraph-agent`, where
the injected issues are known. The scanner detects the intended classes (shell, SSRF via
metadata, unrestricted HTTP, missing limits, etc.). Recall on arbitrary real repos is **not**
claimed, because those repos have no vulnerability labels to measure against.

## Caveats

1. Author-labeled, small sample, single snapshot date — repos are live and drift.
2. Whole-repo scan includes tests/scripts/examples, which inflates volume vs. production paths.
3. Precision only; no real-repo recall.
4. "High/Medium/Low" are directional reads, not certified metrics.

The point of publishing this is to keep the accuracy work honest and to make the fix backlog
concrete and measurable. Re-run `python benchmark/run.py` after any rule change to see the delta.
