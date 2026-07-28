"""Tests for data rules (AG011, AG012, AG017)."""

from __future__ import annotations

from autonomyproof.models import Severity
from autonomyproof.rules.data import (
    MemoryIsolationRule,
    ModelControlledSqlRule,
    SecretInContextRule,
)
from helpers import run_rule


def test_ag012_read_is_high() -> None:
    findings = run_rule(ModelControlledSqlRule(), "cursor.execute(query)\n")
    assert findings[0].severity is Severity.HIGH


def test_ag012_mutation_is_critical() -> None:
    code = "cursor.execute('DELETE FROM t WHERE id=' + user)\n"
    findings = run_rule(ModelControlledSqlRule(), code)
    assert findings[0].severity is Severity.CRITICAL


def test_ag012_nested_attribute_receiver() -> None:
    findings = run_rule(ModelControlledSqlRule(), "self.cursor.execute(query)\n")
    assert findings[0].ruleId == "AG012"


def test_ag012_text_wrapper_on_non_db_receiver() -> None:
    code = "get_session().execute(text(query))\n"
    findings = run_rule(ModelControlledSqlRule(), code)
    assert findings[0].ruleId == "AG012"


def test_ag012_constant_query_suppressed() -> None:
    # A hardcoded query assigned to a variable is not model-controlled.
    assert run_rule(ModelControlledSqlRule(), "q = 'SELECT 1'\ncursor.execute(q)\n") == []


def test_ag012_parameter_query_is_flagged() -> None:
    code = "def run(query):\n    cursor.execute(query)\n"
    assert run_rule(ModelControlledSqlRule(), code)


def test_ag012_mutation_detected_via_variable() -> None:
    code = "q = 'DELETE FROM t WHERE id='\ncursor.execute(q + user)\n"
    findings = run_rule(ModelControlledSqlRule(), code)
    assert findings and findings[0].severity is Severity.CRITICAL


def test_ag012_constant_query_clean() -> None:
    assert run_rule(ModelControlledSqlRule(), "cursor.execute('SELECT 1')\n") == []


def test_ag012_non_db_receiver_clean() -> None:
    assert run_rule(ModelControlledSqlRule(), "pool.execute(query)\n") == []


def test_ag012_non_execute_method_clean() -> None:
    assert run_rule(ModelControlledSqlRule(), "cursor.fetchall(query)\n") == []


def test_ag012_execute_no_args_clean() -> None:
    assert run_rule(ModelControlledSqlRule(), "cursor.execute()\n") == []


def test_ag011_memory_without_key() -> None:
    findings = run_rule(MemoryIsolationRule(), "from x import MemorySaver\nMemorySaver()\n")
    assert findings[0].ruleId == "AG011"


def test_ag011_memory_with_kwarg_key_clean() -> None:
    assert (
        run_rule(MemoryIsolationRule(), "from x import MemorySaver\nMemorySaver(namespace=u)\n")
        == []
    )


def test_ag011_memory_with_string_key_clean() -> None:
    assert run_rule(MemoryIsolationRule(), "from x import Chroma\nChroma('tenant_id')\n") == []


def test_ag011_non_matching_kwarg_then_isolation_clean() -> None:
    code = "from x import MemorySaver\nMemorySaver(ttl=60, user_id=u)\n"
    assert run_rule(MemoryIsolationRule(), code) == []


def test_ag011_non_matching_literal_then_isolation_clean() -> None:
    code = "from x import Chroma\nChroma('cache', 'user_id')\n"
    assert run_rule(MemoryIsolationRule(), code) == []


def test_ag011_non_memory_clean() -> None:
    assert run_rule(MemoryIsolationRule(), "Session()\n") == []


def test_ag011_unresolvable_call_clean() -> None:
    assert run_rule(MemoryIsolationRule(), "registry[0]()\n") == []


def test_ag017_secret_in_prompt() -> None:
    code = "p = f'You are an agent. Use {api_key} now.'\n"
    findings = run_rule(SecretInContextRule(), code)
    assert findings[0].ruleId == "AG017"


def test_ag017_env_secret_constant_key() -> None:
    code = "p = f'System prompt. token {os.environ[\"API_KEY\"]}'\n"
    assert run_rule(SecretInContextRule(), code)


def test_ag017_attribute_secret() -> None:
    code = "p = f'You are a bot; password is {config.password}'\n"
    assert run_rule(SecretInContextRule(), code)


def test_ag017_second_interpolation_is_secret() -> None:
    code = "p = f'You are a bot helping {name} with key {api_key}'\n"
    assert run_rule(SecretInContextRule(), code)


def test_ag017_prompt_without_secret_clean() -> None:
    assert run_rule(SecretInContextRule(), "p = f'You are an agent helping {name}'\n") == []


def test_ag017_secret_without_prompt_marker_clean() -> None:
    assert run_rule(SecretInContextRule(), "p = f'value {api_key}'\n") == []


def test_ag017_non_fstring_clean() -> None:
    assert run_rule(SecretInContextRule(), "p = 'you are an agent'\n") == []
