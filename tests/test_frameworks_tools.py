"""Tests for framework detection and tool detection."""

from __future__ import annotations

from autonomyproof.astutils import FileAnalysis
from autonomyproof.frameworks import detect_frameworks, primary_framework
from autonomyproof.tools import detect_tools


def _a(code: str) -> FileAnalysis:
    return FileAnalysis.build("m.py", code)


def test_detect_frameworks_from_imports() -> None:
    analyses = [_a("import os\nimport langgraph\nfrom os import path\nfrom crewai import Crew\n")]
    assert detect_frameworks(analyses, []) == ["CrewAI", "LangGraph"]


def test_detect_frameworks_from_dependencies() -> None:
    assert detect_frameworks([_a("x = 1\n")], ["pydantic_ai"]) == ["PydanticAI"]


def test_detect_frameworks_ignores_unknown() -> None:
    assert detect_frameworks([_a("import os\n")], ["numpy"]) == []


def test_primary_framework_priority() -> None:
    assert primary_framework(["LangChain", "LangGraph"]) == "LangGraph"


def test_primary_framework_none() -> None:
    assert primary_framework([]) is None


def test_detect_tools_various_decorators() -> None:
    code = (
        "import mcp\n"
        "@tool\n"
        "def a():\n    pass\n"
        "@mcp.tool()\n"
        "def b():\n    pass\n"
        "@function_tool\n"
        "def c():\n    pass\n"
        "def d():\n    pass\n"
    )
    tools = detect_tools(_a(code))
    assert set(tools) == {"a", "b", "c"}


def test_detect_tools_ignores_unrelated_decorator() -> None:
    code = "@staticmethod\ndef a():\n    pass\n@obj[0]\ndef b():\n    pass\n"
    assert detect_tools(_a(code)) == {}


def test_detect_tools_from_tools_list() -> None:
    code = (
        "def move_money():\n    pass\n"
        "def read_file():\n    pass\n"
        "agent = create_agent(tools=[move_money, read_file])\n"
    )
    assert set(detect_tools(_a(code))) == {"move_money", "read_file"}


def test_detect_tools_from_tool_object() -> None:
    code = "from langchain.tools import Tool\ndef run():\n    pass\nt = Tool(func=run)\n"
    assert set(detect_tools(_a(code))) == {"run"}


def test_detect_tools_from_structured_tool_from_function() -> None:
    code = (
        "from langchain.tools import StructuredTool\n"
        "def wire():\n    pass\n"
        "t = StructuredTool.from_function(wire)\n"
    )
    assert set(detect_tools(_a(code))) == {"wire"}


def test_detect_tools_ignores_non_name_tools_list_entries() -> None:
    code = "agent = create_agent(tools=[SomeClass(), 'x'])\n"
    assert detect_tools(_a(code)) == {}
