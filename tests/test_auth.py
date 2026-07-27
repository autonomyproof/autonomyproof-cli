"""Tests for local credential storage."""

from __future__ import annotations

from pathlib import Path

import pytest

from autonomyproof import auth


@pytest.fixture(autouse=True)
def _isolate(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("AUTONOMYPROOF_HOME", str(tmp_path))
    monkeypatch.delenv("AUTONOMYPROOF_TOKEN", raising=False)
    monkeypatch.delenv("AUTONOMYPROOF_API_URL", raising=False)


def test_load_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AUTONOMYPROOF_TOKEN", "ap_live_env")
    monkeypatch.setenv("AUTONOMYPROOF_API_URL", "https://custom.example")
    creds = auth.load_credentials()
    assert creds.token == "ap_live_env"
    assert creds.api_url == "https://custom.example"
    assert creds.source == "env"


def test_save_and_load_from_file() -> None:
    auth.save_token("ap_live_file", "https://api.example")
    creds = auth.load_credentials()
    assert creds.token == "ap_live_file"
    assert creds.api_url == "https://api.example"
    assert creds.source == "file"


def test_file_api_url_overridden_by_env(monkeypatch: pytest.MonkeyPatch) -> None:
    auth.save_token("ap_live_file", "https://api.example")
    monkeypatch.setenv("AUTONOMYPROOF_API_URL", "https://env.example")
    assert auth.load_credentials().api_url == "https://env.example"


def test_load_none() -> None:
    creds = auth.load_credentials()
    assert creds.token is None
    assert creds.source == "none"
    assert creds.api_url == auth.DEFAULT_API_URL


def test_clear_token() -> None:
    auth.save_token("ap_live_x")
    assert auth.clear_token() is True
    assert auth.clear_token() is False
