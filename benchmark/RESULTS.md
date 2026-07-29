# AutonomyProof real-world benchmark

**Scanner version:** 0.8.0 · **Snapshot date:** 2026-07-28 · **Reproduce:** `python benchmark/run.py`

This measures how the scanner behaves on **real, unmodified open-source code** — 10 public
agent / MCP / framework repositories, shallow-cloned and scanned in full (including their
tests, scripts, and examples). It is deliberately published warts-and-all: a static-analysis
tool that hides its false-positive rate isn't trustworthy.

## Corpus

| Repo | Python files | Findings |
|---|---:|---:|
| modelcontextprotocol/python-sdk | 823 | 50 |
| crewAIInc/crewAI | 1278 | 358 |
| langchain-ai/langgraph | 447 | 309 |
| openai/openai-agents-python | 840 | 183 |
| pydantic/pydantic-ai | 599 | 81 |
| huggingface/smolagents | 73 | 91 |
| run-llama/llama_deploy | 108 | 52 |
| microsoft/autogen | 546 | 129 |
| modelcontextprotocol/servers | 14 | 13 |
| agno-agi/agno | 4286 | 802 |
| **Total** | **~9,000** | **2,180** |

## Findings per rule (whole repo, incl. tests/scripts)

| Rule | Count | Precision read (author-labeled sample) |
|---|---:|---|
| AG002 dynamic code (eval/exec) | 35 | **High** — real `eval`/`exec` calls |
| AG018 missing timeout | 292 | **High** — factual (no `timeout=`) |
| AG021 insecure deserialization | 12 | **High** — real `pickle.loads` / `yaml.load` |
| AG022 disabled TLS verify | 8 | **High** — real `verify=False` |
| AG023 template injection | 2 | **High** *(after fix; was 33)* |
| AG007 dangerous-op-without-approval | 27 | **High** *(after fix; was 2,443)* — real tools: `execute_code`, `send_email`, `refund_order`, `delete_file` |
| AG024 dangerous framework flag | 5 | **High** — all literal `trust_remote_code=True` |
| AG025 interpreter tool exposed | 105 | **High** — real `ShellTool` / `ComputerTool` / `CodeInterpreterTool` (approval-gated ones suppressed) |
| AG005 unrestricted HTTP | 150 | **Medium** — dynamic URLs are TP; config/`self.x` URLs are FP |
| AG012 model-controlled SQL | 332 | **Medium** *(after fix; was 569)* — f-string/var queries TP |
| AG003 filesystem | 597 | **Low–Medium** — flags build scripts, tests, config loads |
| AG019 destructive command | 192 | **Low** — matches ordinary `DELETE FROM` / `DROP` SQL |

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
