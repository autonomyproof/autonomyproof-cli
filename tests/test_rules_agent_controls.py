"""Tests for agent-control rules (AG007, AG009, AG013, AG015, AG016)."""

from __future__ import annotations

from autonomyproof.rules.agent_controls import (
    DangerousOperationRule,
    ExcessiveLimitRule,
    GuardrailSelfModificationRule,
    McpArgumentValidationRule,
    SubAgentCreationRule,
)
from helpers import run_rule


# --- AG007 --------------------------------------------------------------------
def test_ag007_dangerous_without_approval() -> None:
    findings = run_rule(
        DangerousOperationRule(), "def delete_user(uid):\n    return db.remove(uid)\n"
    )
    assert findings[0].ruleId == "AG007"
    assert findings[0].toolName == "delete_user"


def test_ag007_with_approval_clean() -> None:
    code = (
        "def deploy(env):\n    if not approved:\n        raise Exception()\n    return run(env)\n"
    )
    assert run_rule(DangerousOperationRule(), code) == []


def test_ag007_async_with_human_in_the_loop_kwarg_clean() -> None:
    code = "async def refund(order):\n    return gate(order, human_in_the_loop=True)\n"
    assert run_rule(DangerousOperationRule(), code) == []


def test_ag007_non_dangerous_clean() -> None:
    assert run_rule(DangerousOperationRule(), "def summarize(text):\n    return text\n") == []


# --- AG009 --------------------------------------------------------------------
def test_ag009_high_retries() -> None:
    assert run_rule(ExcessiveLimitRule(), "Agent(max_retries=50)\n")


def test_ag009_high_recursion_limit_kwarg() -> None:
    assert run_rule(ExcessiveLimitRule(), "build(recursion_limit=5000)\n")


def test_ag009_low_values_clean() -> None:
    assert run_rule(ExcessiveLimitRule(), "Agent(max_retries=3, max_iterations=10)\n") == []


def test_ag009_setrecursionlimit_high() -> None:
    assert run_rule(ExcessiveLimitRule(), "import sys\nsys.setrecursionlimit(5000)\n")


def test_ag009_setrecursionlimit_low_clean() -> None:
    assert run_rule(ExcessiveLimitRule(), "import sys\nsys.setrecursionlimit(100)\n") == []


def test_ag009_unbounded_while_true() -> None:
    assert run_rule(ExcessiveLimitRule(), "while True:\n    step()\n")


def test_ag009_while_true_with_break_clean() -> None:
    assert run_rule(ExcessiveLimitRule(), "while True:\n    if done:\n        break\n") == []


def test_ag009_non_int_kwarg_clean() -> None:
    assert run_rule(ExcessiveLimitRule(), "Agent(max_retries=value)\n") == []


# --- AG013 --------------------------------------------------------------------
_MCP_TOOL = (
    "from mcp.server.fastmcp import FastMCP\n"
    "mcp = FastMCP('x')\n"
    "@mcp.tool()\n"
    "def read_path(path):\n    return path\n"
)


def test_ag013_unvalidated_tool_arg() -> None:
    findings = run_rule(McpArgumentValidationRule(), _MCP_TOOL, frameworks=["MCP"])
    assert findings[0].ruleId == "AG013"


def test_ag013_with_validation_clean() -> None:
    code = (
        "from mcp.server.fastmcp import FastMCP\n"
        "mcp = FastMCP('x')\n"
        "@mcp.tool()\n"
        "def read_path(path):\n    if not path:\n        raise ValueError()\n    return path\n"
    )
    assert run_rule(McpArgumentValidationRule(), code, frameworks=["MCP"]) == []


def test_ag013_validation_via_call_clean() -> None:
    code = (
        "from mcp.server.fastmcp import FastMCP\n"
        "mcp = FastMCP('x')\n"
        "@mcp.tool()\n"
        "def fetch(url):\n    return validate_url(url)\n"
    )
    assert run_rule(McpArgumentValidationRule(), code, frameworks=["MCP"]) == []


def test_ag013_non_risky_param_clean() -> None:
    code = (
        "from mcp.server.fastmcp import FastMCP\n"
        "mcp = FastMCP('x')\n"
        "@mcp.tool()\n"
        "def greet(name):\n    return name\n"
    )
    assert run_rule(McpArgumentValidationRule(), code, frameworks=["MCP"]) == []


def test_ag013_without_mcp_framework_clean() -> None:
    assert run_rule(McpArgumentValidationRule(), _MCP_TOOL, frameworks=["LangChain"]) == []


def test_ag013_non_tool_function_clean() -> None:
    code = "def read_path(path):\n    return path\n"
    assert run_rule(McpArgumentValidationRule(), code, frameworks=["MCP"]) == []


# --- AG015 --------------------------------------------------------------------
def test_ag015_attribute_assignment() -> None:
    findings = run_rule(GuardrailSelfModificationRule(), "self.system_prompt = new\n")
    assert findings[0].ruleId == "AG015"


def test_ag015_aug_assignment() -> None:
    assert run_rule(GuardrailSelfModificationRule(), "agent.policy += extra\n")


def test_ag015_normal_attribute_clean() -> None:
    assert run_rule(GuardrailSelfModificationRule(), "self.counter = 1\n") == []


def test_ag015_name_target_clean() -> None:
    assert run_rule(GuardrailSelfModificationRule(), "counter = 1\n") == []


def test_ag015_config_file_write() -> None:
    assert run_rule(
        GuardrailSelfModificationRule(), "open('.github/workflows/ci.yml', 'w').write(x)\n"
    )


def test_ag015_path_write_text_config() -> None:
    code = "from pathlib import Path\nPath('autonomyproof.yaml').write_text(data)\n"
    assert run_rule(GuardrailSelfModificationRule(), code)


def test_ag015_write_without_marker_clean() -> None:
    assert run_rule(GuardrailSelfModificationRule(), "open('notes.txt', 'w').write(x)\n") == []


def test_ag015_read_open_clean() -> None:
    assert run_rule(GuardrailSelfModificationRule(), "open('policy.yaml').read()\n") == []


def test_ag015_non_write_call_clean() -> None:
    assert run_rule(GuardrailSelfModificationRule(), "compute('policy')\n") == []


# --- AG016 --------------------------------------------------------------------
def test_ag016_agent_in_loop_without_limit() -> None:
    code = "for x in items:\n    create_agent(x)\n"
    findings = run_rule(SubAgentCreationRule(), code)
    assert findings[0].ruleId == "AG016"


def test_ag016_agent_in_tool_without_limit() -> None:
    code = (
        "from mcp.server.fastmcp import FastMCP\n"
        "mcp = FastMCP('x')\n"
        "@mcp.tool()\n"
        "def spawn():\n    return Agent()\n"
    )
    assert run_rule(SubAgentCreationRule(), code)


def test_ag016_with_limit_clean() -> None:
    code = "for x in items:\n    create_agent(x, max_agents=3)\n"
    assert run_rule(SubAgentCreationRule(), code) == []


def test_ag016_top_level_clean() -> None:
    assert run_rule(SubAgentCreationRule(), "Agent()\n") == []


def test_ag016_non_agent_clean() -> None:
    assert run_rule(SubAgentCreationRule(), "for x in items:\n    process(x)\n") == []


def test_ag016_unresolvable_call_clean() -> None:
    assert run_rule(SubAgentCreationRule(), "for x in items:\n    registry[0]()\n") == []
