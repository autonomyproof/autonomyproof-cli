"""Project configuration loading and validation (PRD §10)."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

CONFIG_FILENAME = "autonomyproof.yaml"
IGNORE_FILENAME = ".autonomyproofignore"

# Only Python is analyzed today; keep the default include honest so matched-but-
# unanalyzed YAML/JSON files aren't silently discovered and dropped. Non-Python
# manifest analysis (the authority graph) will re-add those globs when it lands.
DEFAULT_INCLUDE = ["**/*.py"]
DEFAULT_EXCLUDE = [
    ".git/**",
    ".venv/**",
    "venv/**",
    "node_modules/**",
    "dist/**",
    "build/**",
    "coverage/**",
    "__pycache__/**",
    "vendor/**",
    "tests/fixtures/**",
]


class ConfigError(ValueError):
    """Raised when a configuration file is structurally invalid."""


@dataclass
class Config:
    """Parsed, validated project configuration with defaults applied."""

    version: int = 1
    project_name: str = "unnamed-project"
    agent_name: str | None = None
    agent_owner: str | None = None
    agent_purpose: str | None = None
    environment: str | None = None
    criticality: str | None = None
    include: list[str] = field(default_factory=lambda: list(DEFAULT_INCLUDE))
    exclude: list[str] = field(default_factory=lambda: list(DEFAULT_EXCLUDE))
    redact_secrets: bool = True
    fail_on: str = "critical"
    ignored_rules: list[str] = field(default_factory=list)
    accepted_findings: list[str] = field(default_factory=list)
    allowed_domains: list[str] = field(default_factory=list)
    max_iterations: int | None = None
    max_runtime_seconds: int | None = None
    max_subagents: int | None = None

    @classmethod
    def from_mapping(cls, data: dict[str, Any]) -> Config:
        """Build a :class:`Config` from a parsed YAML mapping, applying defaults."""
        if not isinstance(data, dict):
            raise ConfigError("Configuration root must be a mapping.")

        project = _section(data, "project")
        agent = _section(data, "agent")
        scan = _section(data, "scan")
        privacy = _section(data, "privacy")
        policy = _section(data, "policy")
        network = _section(data, "network")
        limits = _section(data, "limits")

        return cls(
            version=int(data.get("version", 1)),
            project_name=str(project.get("name", "unnamed-project")),
            agent_name=_opt_str(agent.get("name")),
            agent_owner=_opt_str(agent.get("owner")),
            agent_purpose=_opt_str(agent.get("purpose")),
            environment=_opt_str(agent.get("environment")),
            criticality=_opt_str(agent.get("criticality")),
            include=_str_list(scan.get("include"), DEFAULT_INCLUDE),
            exclude=_str_list(scan.get("exclude"), DEFAULT_EXCLUDE),
            redact_secrets=bool(privacy.get("redact_secrets", True)),
            fail_on=str(policy.get("fail_on", "critical")),
            ignored_rules=_str_list(policy.get("ignored_rules"), []),
            accepted_findings=_str_list(policy.get("accepted_findings"), []),
            allowed_domains=_str_list(network.get("allowed_domains"), []),
            max_iterations=_opt_int(limits.get("maximum_iterations")),
            max_runtime_seconds=_opt_int(limits.get("maximum_runtime_seconds")),
            max_subagents=_opt_int(limits.get("maximum_subagents")),
        )

    @classmethod
    def load(cls, path: Path) -> Config:
        """Load and validate configuration from ``path``."""
        try:
            raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        except yaml.YAMLError as exc:
            raise ConfigError(f"Invalid YAML: {exc}") from exc
        if raw is None:
            raw = {}
        return cls.from_mapping(raw)


def _section(data: dict[str, Any], key: str) -> dict[str, Any]:
    value = data.get(key, {})
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ConfigError(f"Section '{key}' must be a mapping.")
    return value


def _opt_str(value: Any) -> str | None:
    return None if value is None else str(value)


def _opt_int(value: Any) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise ConfigError("Expected an integer.")
    return value


def _str_list(value: Any, default: list[str]) -> list[str]:
    if value is None:
        return list(default)
    if not isinstance(value, list):
        raise ConfigError("Expected a list of strings.")
    return [str(item) for item in value]


def default_config_yaml(project_name: str) -> str:
    """Return the contents written by ``autonomyproof init``."""
    return f"""version: 1

project:
  name: {project_name}

agent:
  name: {project_name}
  owner: engineering@example.com
  purpose: Describe the approved purpose of this agent
  environment: development
  criticality: high

scan:
  include:
    - "**/*.py"
  exclude:
    - ".venv/**"
    - "tests/fixtures/**"

privacy:
  upload_source: false
  upload_prompts: false
  upload_tool_output: false
  redact_secrets: true
  include_relative_paths: true

policy:
  fail_on: critical
  ignored_rules: []
  accepted_findings: []

limits:
  maximum_iterations: 50
  maximum_runtime_seconds: 1800
  maximum_subagents: 5

network:
  allowed_domains:
    - api.openai.com
    - github.com
"""


DEFAULT_IGNORE_CONTENT = """# Extra paths ignored by AutonomyProof (beyond scan.exclude)
.git/
.venv/
venv/
node_modules/
dist/
build/
__pycache__/
"""
