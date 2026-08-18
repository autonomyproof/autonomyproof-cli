"""Tests for execution rules (AG001, AG002, AG019)."""

from __future__ import annotations

from autonomyproof.models import Severity
from autonomyproof.rules.execution import (
    DestructiveCommandRule,
    DynamicCodeExecutionRule,
    InsecureModelOutputRule,
    ShellExecutionRule,
)
from helpers import run_rule


def test_ag001_os_system() -> None:
    findings = run_rule(ShellExecutionRule(), "import os\nos.system(cmd)\n")
    assert findings[0].ruleId == "AG001"
    assert findings[0].severity is Severity.CRITICAL


def test_ag001_os_popen() -> None:
    assert run_rule(ShellExecutionRule(), "import os\nos.popen(cmd)\n")


def test_ag001_subprocess_shell_true() -> None:
    code = "import subprocess\nsubprocess.run(cmd, shell=True)\n"
    assert run_rule(ShellExecutionRule(), code)


def test_ag001_subprocess_without_shell_is_clean() -> None:
    code = "import subprocess\nsubprocess.run([cmd], shell=False)\n"
    assert run_rule(ShellExecutionRule(), code) == []


def test_ag001_unrelated_call_is_clean() -> None:
    assert run_rule(ShellExecutionRule(), "print(x)\n") == []


def test_ag002_eval_exec_compile() -> None:
    for builtin in ("eval", "exec", "compile"):
        assert run_rule(DynamicCodeExecutionRule(), f"{builtin}(src)\n")


def test_ag002_clean() -> None:
    assert run_rule(DynamicCodeExecutionRule(), "json.loads(src)\n") == []


def test_ag019_detects_destructive_string() -> None:
    findings = run_rule(DestructiveCommandRule(), "cmd = 'rm -rf /data'\n")
    assert findings[0].ruleId == "AG019"


def test_ag019_only_one_finding_per_string() -> None:
    findings = run_rule(DestructiveCommandRule(), "cmd = 'sudo rm -rf /'\n")
    assert len(findings) == 1


def test_ag019_ignores_non_string_and_clean_string() -> None:
    assert run_rule(DestructiveCommandRule(), "x = 5\ny = 'hello world'\n") == []


# --- AG040 (insecure model output → exec) ------------------------------------
def test_ag040_inline_eval_of_model_output() -> None:
    code = "@tool\ndef run(p):\n    return eval(llm.invoke(p))\n"
    findings = run_rule(InsecureModelOutputRule(), code)
    assert findings and findings[0].ruleId == "AG040"


def test_ag040_variable_exec() -> None:
    code = "def run(p):\n    code = llm.predict(p)\n    exec(code)\n"
    assert run_rule(InsecureModelOutputRule(), code)


def test_ag040_content_accessor() -> None:
    code = "def run(p):\n    exec(llm.invoke(p).content)\n"
    assert run_rule(InsecureModelOutputRule(), code)


def test_ag040_openai_choices_chain() -> None:
    code = (
        "def run(p):\n"
        "    resp = client.chat.completions.create(model='x', messages=p)\n"
        "    exec(resp.choices[0].message.content)\n"
    )
    assert run_rule(InsecureModelOutputRule(), code)


def test_ag040_os_system_of_model_output() -> None:
    code = "import os\ndef run(p):\n    os.system(agent.generate(p))\n"
    assert run_rule(InsecureModelOutputRule(), code)


def test_ag040_subprocess_of_model_output() -> None:
    code = "import subprocess\ndef run(p):\n    subprocess.run(llm.ainvoke(p))\n"
    assert run_rule(InsecureModelOutputRule(), code)


def test_ag040_await_model_call() -> None:
    code = "async def run(p):\n    exec(await llm.ainvoke(p))\n"
    assert run_rule(InsecureModelOutputRule(), code)


def test_ag040_user_input_not_model_clean() -> None:
    # exec of a parameter (not model output) is AG002's job, not AG040.
    assert run_rule(InsecureModelOutputRule(), "def run(user_input):\n    exec(user_input)\n") == []


def test_ag040_constant_clean() -> None:
    assert run_rule(InsecureModelOutputRule(), "exec('print(1)')\n") == []


def test_ag040_expression_clean() -> None:
    assert run_rule(InsecureModelOutputRule(), "exec('a' + 'b')\n") == []


def test_ag040_non_model_call_clean() -> None:
    code = "def run(u):\n    data = requests.get(u).text\n    exec(data)\n"
    assert run_rule(InsecureModelOutputRule(), code) == []


def test_ag040_plain_function_result_clean() -> None:
    code = "def run(p):\n    x = compute(p)\n    exec(x)\n"
    assert run_rule(InsecureModelOutputRule(), code) == []


def test_ag040_create_non_llm_receiver_clean() -> None:
    # `.create` only counts on a completions/messages receiver, not e.g. Customer.create.
    code = "def run(e):\n    exec(stripe.Customer.create(email=e))\n"
    assert run_rule(InsecureModelOutputRule(), code) == []


def test_ag040_create_name_receiver_clean() -> None:
    code = "def run():\n    exec(Payout.create())\n"
    assert run_rule(InsecureModelOutputRule(), code) == []


def test_ag040_subprocess_list_clean() -> None:
    code = "import subprocess\ndef run():\n    subprocess.run(['ls', '-la'])\n"
    assert run_rule(InsecureModelOutputRule(), code) == []


def test_ag040_no_args_clean() -> None:
    assert run_rule(InsecureModelOutputRule(), "def run():\n    eval()\n") == []


def test_ag040_not_a_sink_clean() -> None:
    assert run_rule(InsecureModelOutputRule(), "def run(p):\n    print(llm.invoke(p))\n") == []


def test_ag040_deep_alias_chain_not_tracked_clean() -> None:
    # Single-function tracking is intentionally shallow; a 5-deep alias chain is not followed.
    code = (
        "def run(p):\n    a = llm.invoke(p)\n    b = a\n    c = b\n"
        "    d = c\n    e = d\n    exec(e)\n"
    )
    assert run_rule(InsecureModelOutputRule(), code) == []
