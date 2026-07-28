"""Tests for network rules (AG005, AG006, AG014, AG018)."""

from __future__ import annotations

from autonomyproof.config import Config
from autonomyproof.models import Severity
from autonomyproof.rules.network import (
    MissingTimeoutRule,
    SsrfRule,
    TokenPassthroughRule,
    UnrestrictedHttpRule,
)
from helpers import run_rule


def test_ag005_unbounded_is_critical() -> None:
    findings = run_rule(UnrestrictedHttpRule(), "import requests\nrequests.get(url)\n")
    assert findings[0].severity is Severity.CRITICAL


def test_ag005_with_allowlist_and_timeout_is_high() -> None:
    config = Config(allowed_domains=["api.openai.com"])
    findings = run_rule(
        UnrestrictedHttpRule(), "import requests\nrequests.get(url, timeout=5)\n", config=config
    )
    assert findings[0].severity is Severity.HIGH


def test_ag005_constant_url_clean() -> None:
    assert (
        run_rule(UnrestrictedHttpRule(), "import requests\nrequests.get('https://a.com')\n") == []
    )


def test_ag005_httpx_and_urllib_and_aiohttp() -> None:
    assert run_rule(UnrestrictedHttpRule(), "import httpx\nhttpx.get(url)\n")
    assert run_rule(UnrestrictedHttpRule(), "import urllib.request\nurllib.request.urlopen(url)\n")
    assert run_rule(UnrestrictedHttpRule(), "import aiohttp\naiohttp.ClientSession().get(url)\n")


def test_ag005_session_without_args_clean() -> None:
    assert run_rule(UnrestrictedHttpRule(), "import aiohttp\naiohttp.ClientSession().get()\n") == []


def test_ag005_session_method_on_plain_receiver_clean() -> None:
    # Undefined receiver with no assignment cannot be proven to be an HTTP session.
    assert run_rule(UnrestrictedHttpRule(), "session.get(url)\n") == []


def test_ag005_non_session_call_receiver_clean() -> None:
    assert run_rule(UnrestrictedHttpRule(), "import redis\nredis().get(url)\n") == []


def test_ag005_session_variable_is_tracked() -> None:
    # The common real-world pattern: a client assigned to a variable, then reused.
    code = "import httpx\nclient = httpx.Client()\nclient.get(url)\n"
    findings = run_rule(UnrestrictedHttpRule(), code)
    assert findings and findings[0].ruleId == "AG005"


def test_ag005_requests_session_variable_is_tracked() -> None:
    code = "import requests\ns = requests.Session()\ns.post(url)\n"
    assert run_rule(UnrestrictedHttpRule(), code)


def test_ag005_unknown_variable_receiver_clean() -> None:
    code = "import redis\nr = redis.Redis()\nr.get(url)\n"
    assert run_rule(UnrestrictedHttpRule(), code) == []


def test_ag005_attribute_receiver_not_proven_session_clean() -> None:
    # self.session.get(url): the receiver is neither an inline call nor a local variable.
    code = "def go(self, url):\n    return self.session.get(url)\n"
    assert run_rule(UnrestrictedHttpRule(), code) == []


def test_ag005_call_chain_source_is_kept() -> None:
    code = "import requests\nrequests.get(get_config().url, timeout=5)\n"
    assert run_rule(UnrestrictedHttpRule(), code)


def test_ag005_config_attribute_is_suppressed() -> None:
    # The canonical false positive: a URL read from trusted config, not model output.
    code = "import requests\nurl = settings.COMPANY_API_URL\nrequests.get(url, timeout=5)\n"
    assert run_rule(UnrestrictedHttpRule(), code) == []


def test_ag005_os_environ_is_suppressed() -> None:
    code = "import os\nimport requests\nrequests.get(os.environ['URL'], timeout=5)\n"
    assert run_rule(UnrestrictedHttpRule(), code) == []


def test_ag005_uppercase_constant_is_suppressed() -> None:
    code = "import requests\nrequests.get(API_ENDPOINT, timeout=5)\n"
    assert run_rule(UnrestrictedHttpRule(), code) == []


def test_ag005_chained_constant_is_suppressed() -> None:
    code = "import requests\na = 'https://api.example.com'\nb = a\nrequests.get(b)\n"
    assert run_rule(UnrestrictedHttpRule(), code) == []


def test_ag005_tool_parameter_is_tainted_and_critical() -> None:
    code = "import requests\ndef fetch(url):\n    return requests.get(url)\n"
    findings = run_rule(UnrestrictedHttpRule(), code)
    assert findings and findings[0].severity is Severity.CRITICAL


def test_ag005_unknown_source_is_kept() -> None:
    code = "import requests\ndef go():\n    return requests.get(build_url())\n"
    assert run_rule(UnrestrictedHttpRule(), code)


def test_ag006_private_10_8_range() -> None:
    # 10.8.0.1 is in 10.0.0.0/8 but the old string-marker "10.0." missed it.
    assert run_rule(SsrfRule(), "import requests\nrequests.get('http://10.8.0.1/')\n")


def test_ag006_private_172_20_range() -> None:
    assert run_rule(SsrfRule(), "import requests\nrequests.get('http://172.20.1.1/')\n")


def test_ag006_variable_indirection() -> None:
    # One assignment used to defeat the SSRF check entirely.
    code = "import requests\nu = 'http://169.254.169.254/latest/meta-data/'\nrequests.get(u)\n"
    findings = run_rule(SsrfRule(), code)
    assert findings and findings[0].ruleId == "AG006"


def test_ag006_ipv6_loopback() -> None:
    assert run_rule(SsrfRule(), "import requests\nrequests.get('http://[::1]:8000/')\n")


def test_ag006_dot_internal_host() -> None:
    assert run_rule(SsrfRule(), "import requests\nrequests.get('http://db.internal/health')\n")


def test_ag006_metadata_hostname() -> None:
    code = "import requests\nrequests.get('http://metadata.google.internal/token')\n"
    assert run_rule(SsrfRule(), code)


def test_ag006_public_ip_clean() -> None:
    assert run_rule(SsrfRule(), "import requests\nrequests.get('http://93.184.216.34/')\n") == []


def test_ag006_malformed_ipv6_url_is_handled() -> None:
    # Malformed IPv6 makes urlsplit raise; the scanner degrades gracefully, no crash.
    assert run_rule(SsrfRule(), "import requests\nrequests.get('http://[::1/')\n") == []


def test_ag006_metadata_host() -> None:
    findings = run_rule(
        SsrfRule(), "import requests\nrequests.get('http://169.254.169.254/latest')\n"
    )
    assert findings[0].ruleId == "AG006"


def test_ag006_localhost() -> None:
    assert run_rule(SsrfRule(), "import requests\nrequests.get('http://localhost:8080')\n")


def test_ag006_no_marker_clean() -> None:
    assert run_rule(SsrfRule(), "import requests\nrequests.get(url)\n") == []


def test_ag006_constant_safe_url_clean() -> None:
    assert (
        run_rule(SsrfRule(), "import requests\nrequests.get('https://safe.example.com/x')\n") == []
    )


def test_ag006_non_http_call_clean() -> None:
    assert run_rule(SsrfRule(), "log('http://localhost')\n") == []


def test_ag014_token_forwarded() -> None:
    code = "import requests\nrequests.post(url, headers={'Authorization': token})\n"
    findings = run_rule(TokenPassthroughRule(), code)
    assert findings[0].ruleId == "AG014"


def test_ag014_attribute_token() -> None:
    code = "import requests\nrequests.get(url, headers={'Authorization': request.access_token})\n"
    assert run_rule(TokenPassthroughRule(), code)


def test_ag014_constant_header_clean() -> None:
    code = "import requests\nrequests.get(url, headers={'Authorization': 'Bearer static'})\n"
    assert run_rule(TokenPassthroughRule(), code) == []


def test_ag014_non_token_variable_clean() -> None:
    code = "import requests\nrequests.get(url, headers={'Authorization': something})\n"
    assert run_rule(TokenPassthroughRule(), code) == []


def test_ag014_headers_not_dict_clean() -> None:
    code = "import requests\nrequests.get(url, headers=hdrs)\n"
    assert run_rule(TokenPassthroughRule(), code) == []


def test_ag014_non_http_clean() -> None:
    assert run_rule(TokenPassthroughRule(), "f(url, headers={'Authorization': token})\n") == []


def test_ag018_subprocess_without_timeout() -> None:
    findings = run_rule(MissingTimeoutRule(), "import subprocess\nsubprocess.run([cmd])\n")
    assert findings[0].ruleId == "AG018"


def test_ag018_subprocess_with_timeout_clean() -> None:
    assert (
        run_rule(MissingTimeoutRule(), "import subprocess\nsubprocess.run([cmd], timeout=5)\n")
        == []
    )


def test_ag018_http_without_timeout() -> None:
    assert run_rule(MissingTimeoutRule(), "import requests\nrequests.get(url)\n")


def test_ag018_http_with_timeout_clean() -> None:
    assert run_rule(MissingTimeoutRule(), "import requests\nrequests.get(url, timeout=5)\n") == []


def test_ag018_aiohttp_session_without_timeout() -> None:
    code = "import aiohttp\naiohttp.ClientSession().get(url)\n"
    assert run_rule(MissingTimeoutRule(), code)


def test_ag018_unrelated_clean() -> None:
    assert run_rule(MissingTimeoutRule(), "compute(x)\n") == []
