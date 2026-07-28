"""Tests for configuration loading and validation."""

from __future__ import annotations

from pathlib import Path

import pytest

from autonomyproof.config import (
    DEFAULT_EXCLUDE,
    DEFAULT_IGNORE_CONTENT,
    Config,
    ConfigError,
    default_config_yaml,
)


def test_from_mapping_full() -> None:
    config = Config.from_mapping(
        {
            "version": 1,
            "project": {"name": "demo"},
            "agent": {
                "name": "a",
                "owner": "o",
                "purpose": "p",
                "environment": "dev",
                "criticality": "high",
            },
            "scan": {"include": ["**/*.py"], "exclude": ["x/**"]},
            "privacy": {"redact_secrets": False},
            "policy": {"fail_on": "high", "ignored_rules": ["AG001"], "accepted_findings": ["fp"]},
            "network": {"allowed_domains": ["api.openai.com"]},
        }
    )
    assert config.project_name == "demo"
    assert config.agent_owner == "o"
    assert config.redact_secrets is False
    assert config.fail_on == "high"
    assert config.ignored_rules == ["AG001"]
    assert config.allowed_domains == ["api.openai.com"]


def test_from_mapping_defaults() -> None:
    config = Config.from_mapping({})
    assert config.project_name == "unnamed-project"
    assert config.agent_name is None
    assert config.exclude == DEFAULT_EXCLUDE
    assert config.redact_secrets is True
    assert config.max_iterations is None
    assert config.max_subagents is None


def test_from_mapping_parses_limits() -> None:
    config = Config.from_mapping(
        {
            "limits": {
                "maximum_iterations": 50,
                "maximum_runtime_seconds": 1800,
                "maximum_subagents": 5,
            }
        }
    )
    assert config.max_iterations == 50
    assert config.max_runtime_seconds == 1800
    assert config.max_subagents == 5


def test_from_mapping_rejects_non_int_limit() -> None:
    with pytest.raises(ConfigError):
        Config.from_mapping({"limits": {"maximum_iterations": "lots"}})


def test_from_mapping_rejects_bool_limit() -> None:
    with pytest.raises(ConfigError):
        Config.from_mapping({"limits": {"maximum_subagents": True}})


def test_from_mapping_null_section() -> None:
    config = Config.from_mapping({"agent": None})
    assert config.agent_name is None


def test_from_mapping_non_dict_root() -> None:
    with pytest.raises(ConfigError):
        Config.from_mapping([])  # type: ignore[arg-type]


def test_from_mapping_bad_section() -> None:
    with pytest.raises(ConfigError):
        Config.from_mapping({"project": "not-a-mapping"})


def test_from_mapping_bad_list() -> None:
    with pytest.raises(ConfigError):
        Config.from_mapping({"scan": {"include": "notalist"}})


def test_load_valid(tmp_path: Path) -> None:
    path = tmp_path / "autonomyproof.yaml"
    path.write_text("project:\n  name: x\n", encoding="utf-8")
    assert Config.load(path).project_name == "x"


def test_load_empty_file(tmp_path: Path) -> None:
    path = tmp_path / "autonomyproof.yaml"
    path.write_text("", encoding="utf-8")
    assert Config.load(path).project_name == "unnamed-project"


def test_load_invalid_yaml(tmp_path: Path) -> None:
    path = tmp_path / "autonomyproof.yaml"
    path.write_text("a: [unclosed\n", encoding="utf-8")
    with pytest.raises(ConfigError):
        Config.load(path)


def test_default_config_yaml_and_ignore() -> None:
    assert "name: myproj" in default_config_yaml("myproj")
    assert ".venv/" in DEFAULT_IGNORE_CONTENT
