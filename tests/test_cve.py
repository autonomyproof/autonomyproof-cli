"""Tests for version-validated CVE matching."""

from __future__ import annotations

from autonomyproof.cve import known_vulnerabilities


def test_matches_vulnerable_0_3_line() -> None:
    matches = known_vulnerabilities({"langchain-core": "0.3.80"})
    assert {m.cve for m in matches} == {"CVE-2025-68664", "CVE-2026-44843"}


def test_matches_vulnerable_1_x_line() -> None:
    assert {m.cve for m in known_vulnerabilities({"langchain-core": "1.2.4"})} == {
        "CVE-2025-68664",
        "CVE-2026-44843",
    }


def test_normalizes_package_name() -> None:
    assert known_vulnerabilities({"LangChain_Core": "0.3.80"})


def test_patched_version_is_clean() -> None:
    assert known_vulnerabilities({"langchain-core": "0.3.85"}) == []


def test_absent_package_is_clean() -> None:
    assert known_vulnerabilities({"requests": "2.31.0"}) == []


def test_unparseable_version_is_skipped() -> None:
    assert known_vulnerabilities({"langchain-core": "not-a-version"}) == []


def test_matches_langflow_rce() -> None:
    # langflow 1.2.0 is in range for both the code-exec RCE and the CORS/CSRF chain.
    assert {m.cve for m in known_vulnerabilities({"langflow": "1.2.0"})} == {
        "CVE-2025-3248",
        "CVE-2025-34291",
    }


def test_langflow_patched_is_clean() -> None:
    # 1.7.0 fixes both langflow CVEs in the registry.
    assert known_vulnerabilities({"langflow": "1.7.0"}) == []
