"""Tests for insecure-primitive rules (AG021, AG022, AG023)."""

from __future__ import annotations

from autonomyproof.rules.insecure import (
    DisabledCertVerificationRule,
    InsecureDeserializationRule,
    TemplateInjectionRule,
)
from helpers import run_rule


def test_ag021_pickle_loads() -> None:
    findings = run_rule(InsecureDeserializationRule(), "import pickle\npickle.loads(data)\n")
    assert findings and findings[0].ruleId == "AG021"


def test_ag021_torch_load() -> None:
    assert run_rule(InsecureDeserializationRule(), "import torch\ntorch.load(f)\n")


def test_ag021_yaml_load_without_loader() -> None:
    assert run_rule(InsecureDeserializationRule(), "import yaml\nyaml.load(data)\n")


def test_ag021_yaml_load_with_safe_loader_kwarg_clean() -> None:
    code = "import yaml\nyaml.load(data, Loader=yaml.SafeLoader)\n"
    assert run_rule(InsecureDeserializationRule(), code) == []


def test_ag021_yaml_load_with_positional_safe_loader_clean() -> None:
    code = "from yaml import SafeLoader\nimport yaml\nyaml.load(data, SafeLoader)\n"
    assert run_rule(InsecureDeserializationRule(), code) == []


def test_ag021_yaml_load_with_unsafe_loader() -> None:
    assert run_rule(
        InsecureDeserializationRule(), "import yaml\nyaml.load(data, Loader=yaml.Loader)\n"
    )


def test_ag021_yaml_safe_load_clean() -> None:
    assert run_rule(InsecureDeserializationRule(), "import yaml\nyaml.safe_load(data)\n") == []


def test_ag022_verify_false() -> None:
    findings = run_rule(
        DisabledCertVerificationRule(), "import requests\nrequests.get(u, verify=False)\n"
    )
    assert findings and findings[0].ruleId == "AG022"


def test_ag022_check_hostname_false() -> None:
    assert run_rule(DisabledCertVerificationRule(), "ctx.wrap(check_hostname=False)\n")


def test_ag022_unverified_ssl_context() -> None:
    code = "import ssl\nctx = ssl._create_unverified_context()\n"
    assert run_rule(DisabledCertVerificationRule(), code)


def test_ag022_verify_true_clean() -> None:
    assert (
        run_rule(DisabledCertVerificationRule(), "import requests\nrequests.get(u, verify=True)\n")
        == []
    )


def test_ag023_render_template_string_model_controlled() -> None:
    code = "from flask import render_template_string\nrender_template_string(user_input)\n"
    findings = run_rule(TemplateInjectionRule(), code)
    assert findings and findings[0].ruleId == "AG023"


def test_ag023_render_template_string_constant_clean() -> None:
    code = "from flask import render_template_string\nrender_template_string('<b>hi</b>')\n"
    assert run_rule(TemplateInjectionRule(), code) == []


def test_ag023_jinja_template_from_model() -> None:
    assert run_rule(TemplateInjectionRule(), "import jinja2\njinja2.Template(user_input)\n")


def test_ag023_environment_from_string() -> None:
    assert run_rule(TemplateInjectionRule(), "env.from_string(user_input)\n")


def test_ag023_environment_call_from_string() -> None:
    code = "import jinja2\njinja2.Environment().from_string(user_input)\n"
    assert run_rule(TemplateInjectionRule(), code)


def test_ag023_from_string_constant_clean() -> None:
    assert run_rule(TemplateInjectionRule(), "env.from_string('static')\n") == []


def test_ag023_unrelated_from_string_is_clean() -> None:
    # A deserializer like RunState.from_string is not template injection (benchmark FP fix).
    assert run_rule(TemplateInjectionRule(), "RunState.from_string(agent, blob)\n") == []


def test_ag023_from_string_on_non_name_receiver_clean() -> None:
    assert run_rule(TemplateInjectionRule(), "items[0].from_string(user_input)\n") == []


def test_ag021_joblib_load() -> None:
    assert run_rule(InsecureDeserializationRule(), "import joblib\njoblib.load(f)\n")


def test_ag021_pandas_read_pickle() -> None:
    assert run_rule(InsecureDeserializationRule(), "import pandas\npandas.read_pickle(f)\n")


def test_ag021_numpy_allow_pickle_true() -> None:
    code = "import numpy\nnumpy.load(f, allow_pickle=True)\n"
    findings = run_rule(InsecureDeserializationRule(), code)
    assert findings and findings[0].ruleId == "AG021"


def test_ag021_numpy_default_clean() -> None:
    assert run_rule(InsecureDeserializationRule(), "import numpy\nnumpy.load(f)\n") == []


def test_ag021_numpy_allow_pickle_false_clean() -> None:
    assert (
        run_rule(InsecureDeserializationRule(), "import numpy\nnumpy.load(f, allow_pickle=False)\n")
        == []
    )
