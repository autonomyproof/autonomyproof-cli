"""Tests for filesystem rules (AG003, AG004)."""

from __future__ import annotations

from autonomyproof.models import Severity
from autonomyproof.rules.filesystem import CredentialPathAccessRule, FilesystemAccessRule
from helpers import run_rule


def test_ag003_open_read_is_high() -> None:
    findings = run_rule(FilesystemAccessRule(), "open(path).read()\n")
    assert findings[0].severity is Severity.HIGH


def test_ag003_open_write_is_critical() -> None:
    findings = run_rule(FilesystemAccessRule(), "open(path, 'w').write(data)\n")
    assert findings[0].severity is Severity.CRITICAL


def test_ag003_open_constant_path_clean() -> None:
    assert run_rule(FilesystemAccessRule(), "open('config.txt').read()\n") == []


def test_ag003_open_no_args_clean() -> None:
    assert run_rule(FilesystemAccessRule(), "open()\n") == []


def test_ag003_constant_path_via_variable_suppressed() -> None:
    # A hardcoded path assigned to a variable is not model-controlled.
    assert run_rule(FilesystemAccessRule(), "p = 'out.txt'\nopen(p, 'w')\n") == []


def test_ag003_parameter_path_is_critical() -> None:
    code = "def w(path):\n    return open(path, 'w')\n"
    findings = run_rule(FilesystemAccessRule(), code)
    assert findings and findings[0].severity is Severity.CRITICAL


def test_ag003_os_remove_is_critical() -> None:
    findings = run_rule(FilesystemAccessRule(), "import os\nos.remove(path)\n")
    assert findings[0].severity is Severity.CRITICAL


def test_ag003_path_read_text_high() -> None:
    findings = run_rule(FilesystemAccessRule(), "from pathlib import Path\nPath(p).read_text()\n")
    assert findings[0].severity is Severity.HIGH


def test_ag003_path_write_text_critical() -> None:
    findings = run_rule(FilesystemAccessRule(), "from pathlib import Path\nPath(p).write_text(x)\n")
    assert findings[0].severity is Severity.CRITICAL


def test_ag003_path_unlink_critical() -> None:
    findings = run_rule(FilesystemAccessRule(), "from pathlib import Path\nPath(p).unlink()\n")
    assert findings[0].severity is Severity.CRITICAL


def test_ag003_path_method_constant_clean() -> None:
    assert (
        run_rule(FilesystemAccessRule(), "from pathlib import Path\nPath('a.txt').read_text()\n")
        == []
    )


def test_ag003_method_on_non_path_clean() -> None:
    assert run_rule(FilesystemAccessRule(), "obj.read_text()\n") == []


def test_ag003_unrelated_method_clean() -> None:
    assert run_rule(FilesystemAccessRule(), "from pathlib import Path\nPath(p).exists()\n") == []


def test_ag003_bare_function_call_clean() -> None:
    assert run_rule(FilesystemAccessRule(), "compute(path)\n") == []


def test_ag004_open_ssh_key() -> None:
    findings = run_rule(CredentialPathAccessRule(), "open('/home/u/.ssh/id_rsa').read()\n")
    assert findings[0].ruleId == "AG004"


def test_ag004_path_aws_credentials() -> None:
    assert run_rule(
        CredentialPathAccessRule(), "from pathlib import Path\nPath('.aws/credentials')\n"
    )


def test_ag004_read_text_env() -> None:
    assert run_rule(CredentialPathAccessRule(), "obj.read_text('.env')\n")


def test_ag004_clean_path() -> None:
    assert run_rule(CredentialPathAccessRule(), "open('report.txt').read()\n") == []


def test_ag004_credential_path_via_variable() -> None:
    # One-line indirection no longer hides the credential path.
    code = "def f():\n    p = '/home/u/.aws/credentials'\n    return open(p).read()\n"
    findings = run_rule(CredentialPathAccessRule(), code)
    assert findings and findings[0].ruleId == "AG004"


def test_ag004_non_fs_call_with_marker_is_clean() -> None:
    assert run_rule(CredentialPathAccessRule(), "print('.ssh/id_rsa')\n") == []
