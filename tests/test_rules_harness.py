"""Tests for harness-layer rules (AG024, AG025)."""

from __future__ import annotations

from autonomyproof.astutils import FileAnalysis
from autonomyproof.config import Config
from autonomyproof.models import Severity
from autonomyproof.rules.base import ProjectContext
from autonomyproof.rules.harness import (
    CodeExecutingAgentRule,
    CorsWildcardCredentialsRule,
    DangerousFrameworkFlagRule,
    DisabledSafetyFilterRule,
    InterpreterToolExposedRule,
    KnownVulnerableDependencyRule,
    PublicShareRule,
    SandboxDisabledRule,
    UnrestrictedRequestToolRule,
)
from helpers import run_rule


def _pctx(versions: dict[str, str]) -> ProjectContext:
    analysis = FileAnalysis.build("agent.py", "x = 1\n")
    return ProjectContext(
        analyses=[analysis], config=Config(), frameworks=[], dependency_versions=versions
    )


# --- AG024 dangerous framework flags ------------------------------------------
def test_ag024_allow_dangerous_deserialization_critical() -> None:
    code = "FAISS.load_local(path, emb, allow_dangerous_deserialization=True)\n"
    findings = run_rule(DangerousFrameworkFlagRule(), code)
    assert findings[0].ruleId == "AG024"
    assert findings[0].severity is Severity.CRITICAL
    assert "AML.T0010" in findings[0].mappings.mitre
    # No static CVE on the pattern rule — CVEs are version-validated by AG026.
    assert findings[0].mappings.cve == []


def test_ag024_allow_dangerous_code_critical() -> None:
    findings = run_rule(DangerousFrameworkFlagRule(), "make_agent(allow_dangerous_code=True)\n")
    assert findings[0].severity is Severity.CRITICAL


def test_ag024_trust_remote_code_critical() -> None:
    code = "AutoModel.from_pretrained(name, trust_remote_code=True)\n"
    assert run_rule(DangerousFrameworkFlagRule(), code)[0].severity is Severity.CRITICAL


def test_ag024_allow_dangerous_requests_high() -> None:
    findings = run_rule(DangerousFrameworkFlagRule(), "Chain(allow_dangerous_requests=True)\n")
    assert findings[0].severity is Severity.HIGH


def test_ag024_secrets_from_env_high() -> None:
    assert run_rule(DangerousFrameworkFlagRule(), "dumps(obj, secrets_from_env=True)\n")


def test_ag024_allowed_objects_all_high() -> None:
    findings = run_rule(DangerousFrameworkFlagRule(), "load(data, allowed_objects='all')\n")
    assert findings[0].severity is Severity.HIGH


def test_ag024_flag_false_is_clean() -> None:
    code = "FAISS.load_local(path, emb, allow_dangerous_deserialization=False)\n"
    assert run_rule(DangerousFrameworkFlagRule(), code) == []


def test_ag024_flag_non_literal_is_clean() -> None:
    assert run_rule(DangerousFrameworkFlagRule(), "make_agent(allow_dangerous_code=flag)\n") == []


def test_ag024_allowed_objects_core_is_clean() -> None:
    assert run_rule(DangerousFrameworkFlagRule(), "load(data, allowed_objects='core')\n") == []


def test_ag024_unrelated_kwarg_clean() -> None:
    assert run_rule(DangerousFrameworkFlagRule(), "f(verbose=True)\n") == []


# --- AG025 interpreter tools ---------------------------------------------------
def test_ag025_python_repl_tool() -> None:
    findings = run_rule(InterpreterToolExposedRule(), "tool = PythonREPLTool()\n")
    assert findings[0].ruleId == "AG025"
    assert findings[0].severity is Severity.CRITICAL


def test_ag025_shell_tool_dotted() -> None:
    code = "from langchain_community.tools import ShellTool\nt = ShellTool()\n"
    assert run_rule(InterpreterToolExposedRule(), code)


def test_ag025_code_interpreter_tool() -> None:
    assert run_rule(InterpreterToolExposedRule(), "CodeInterpreterTool()\n")


def test_ag025_load_tools_with_dangerous_entry() -> None:
    code = "tools = load_tools(['python_repl', 'llm-math'])\n"
    findings = run_rule(InterpreterToolExposedRule(), code)
    assert findings and "python_repl" in findings[0].evidence


def test_ag025_load_tools_safe_only_clean() -> None:
    assert run_rule(InterpreterToolExposedRule(), "load_tools(['llm-math', 'serpapi'])\n") == []


def test_ag025_load_tools_non_list_clean() -> None:
    assert run_rule(InterpreterToolExposedRule(), "load_tools(tool_names)\n") == []


def test_ag025_load_tools_no_args_clean() -> None:
    assert run_rule(InterpreterToolExposedRule(), "load_tools()\n") == []


def test_ag025_unrelated_call_clean() -> None:
    assert run_rule(InterpreterToolExposedRule(), "SummarizerTool()\n") == []


def test_ag025_interpreter_with_approval_clean() -> None:
    # A shell tool gated behind human approval is the recommended pattern, not a finding.
    code = "ShellTool(executor=run, needs_approval=True)\n"
    assert run_rule(InterpreterToolExposedRule(), code) == []


# --- AG026 version-validated CVE ----------------------------------------------
def test_ag026_vulnerable_version_flagged_with_cve() -> None:
    findings = list(
        KnownVulnerableDependencyRule().check_project(_pctx({"langchain-core": "0.3.80"}))
    )
    cves = {c for f in findings for c in f.mappings.cve}
    assert "CVE-2025-68664" in cves
    assert "CVE-2026-44843" in cves
    assert all(f.ruleId == "AG026" for f in findings)


def test_ag026_vulnerable_1x_version_flagged() -> None:
    findings = list(
        KnownVulnerableDependencyRule().check_project(_pctx({"langchain_core": "1.2.4"}))
    )
    assert findings and "CVE-2025-68664" in {c for f in findings for c in f.mappings.cve}


def test_ag026_patched_version_clean() -> None:
    assert (
        list(KnownVulnerableDependencyRule().check_project(_pctx({"langchain-core": "0.3.85"})))
        == []
    )


def test_ag026_no_dependency_clean() -> None:
    assert list(KnownVulnerableDependencyRule().check_project(_pctx({}))) == []


def test_ag026_langflow_rce_flagged() -> None:
    findings = list(KnownVulnerableDependencyRule().check_project(_pctx({"langflow": "1.2.0"})))
    assert findings and "CVE-2025-3248" in {c for f in findings for c in f.mappings.cve}


# --- AG027 sandbox disabled ---------------------------------------------------
def test_ag027_use_docker_false_kwarg() -> None:
    assert run_rule(SandboxDisabledRule(), "LocalExecutor(use_docker=False)\n")


def test_ag027_use_docker_false_in_dict() -> None:
    code = "agent = UserProxyAgent(code_execution_config={'use_docker': False})\n"
    findings = run_rule(SandboxDisabledRule(), code)
    assert findings and findings[0].ruleId == "AG027"


def test_ag027_use_docker_true_clean() -> None:
    assert run_rule(SandboxDisabledRule(), "LocalExecutor(use_docker=True)\n") == []


def test_ag027_dict_true_value_clean() -> None:
    assert run_rule(SandboxDisabledRule(), "cfg = {'use_docker': True}\n") == []


def test_ag027_dict_without_use_docker_clean() -> None:
    assert run_rule(SandboxDisabledRule(), "cfg = {'work_dir': 'coding'}\n") == []


# --- AG028 code-executing agent ------------------------------------------------
def test_ag028_pandas_agent() -> None:
    findings = run_rule(
        CodeExecutingAgentRule(), "agent = create_pandas_dataframe_agent(llm, df)\n"
    )
    assert findings[0].ruleId == "AG028"


def test_ag028_palchain_dotted() -> None:
    assert run_rule(CodeExecutingAgentRule(), "chain = PALChain.from_math_prompt(llm)\n")


def test_ag028_safe_agent_clean() -> None:
    assert run_rule(CodeExecutingAgentRule(), "agent = create_react_agent(llm, tools)\n") == []


# --- AG029 unrestricted request tool -------------------------------------------
def test_ag029_requests_tool() -> None:
    findings = run_rule(UnrestrictedRequestToolRule(), "t = RequestsGetTool()\n")
    assert findings[0].ruleId == "AG029"


def test_ag029_safe_tool_clean() -> None:
    assert run_rule(UnrestrictedRequestToolRule(), "t = CalculatorTool()\n") == []


# --- AG030 public share tunnel -------------------------------------------------
def test_ag030_share_true() -> None:
    findings = run_rule(PublicShareRule(), "demo.launch(share=True)\n")
    assert findings[0].ruleId == "AG030"


def test_ag030_share_false_clean() -> None:
    assert run_rule(PublicShareRule(), "demo.launch(share=False)\n") == []


def test_ag030_no_share_clean() -> None:
    assert run_rule(PublicShareRule(), "demo.launch(server_port=7860)\n") == []


def test_ag030_non_launch_clean() -> None:
    assert run_rule(PublicShareRule(), "config.set(share=True)\n") == []


# --- AG026 additional CVEs -----------------------------------------------------
def test_ag026_langflow_34291_flagged() -> None:
    findings = list(KnownVulnerableDependencyRule().check_project(_pctx({"langflow": "1.6.9"})))
    assert "CVE-2025-34291" in {c for f in findings for c in f.mappings.cve}


def test_ag026_llama_index_pickle_flagged() -> None:
    findings = list(
        KnownVulnerableDependencyRule().check_project(_pctx({"llama-index-core": "0.12.40"}))
    )
    assert "CVE-2025-3108" in {c for f in findings for c in f.mappings.cve}


# --- AG031 CORS wildcard + credentials ----------------------------------------
def test_ag031_fastapi_cors_wildcard_creds() -> None:
    code = "app.add_middleware(CORSMiddleware, allow_origins=['*'], allow_credentials=True)\n"
    findings = run_rule(CorsWildcardCredentialsRule(), code)
    assert findings[0].ruleId == "AG031"


def test_ag031_flask_cors_wildcard_creds() -> None:
    assert run_rule(
        CorsWildcardCredentialsRule(), "CORS(app, origins='*', supports_credentials=True)\n"
    )


def test_ag031_wildcard_without_credentials_clean() -> None:
    code = "app.add_middleware(CORSMiddleware, allow_origins=['*'])\n"
    assert run_rule(CorsWildcardCredentialsRule(), code) == []


def test_ag031_credentials_with_specific_origin_clean() -> None:
    code = "app.add_middleware(CORSMiddleware, allow_origins=['https://app.example.com'], allow_credentials=True)\n"
    assert run_rule(CorsWildcardCredentialsRule(), code) == []


# --- AG032 disabled safety filter ---------------------------------------------
def test_ag032_block_none() -> None:
    code = "cfg = {cat: HarmBlockThreshold.BLOCK_NONE}\n"
    findings = run_rule(DisabledSafetyFilterRule(), code)
    assert findings[0].ruleId == "AG032"


def test_ag032_block_threshold_clean() -> None:
    assert (
        run_rule(
            DisabledSafetyFilterRule(), "cfg = {cat: HarmBlockThreshold.BLOCK_MEDIUM_AND_ABOVE}\n"
        )
        == []
    )
