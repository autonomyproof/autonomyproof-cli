"""Tests for the cloud API client."""

from __future__ import annotations

import httpx
import pytest

from autonomyproof.api import ApiClient, ApiError, PushResult, idempotency_key
from autonomyproof.models import ProjectMetadata, ScanResult


def _result() -> ScanResult:
    return ScanResult(
        scan_id="scan-1",
        scanner_version="0.1.0",
        project=ProjectMetadata(name="p", commit="sha"),
        frameworks=[],
        tools=[],
        capabilities=[],
        findings=[],
        score=100,
        risk_level="Low",
        files_scanned=0,
        rules_executed=[],
        duration_ms=1,
    )


def _client(handler: httpx.MockTransport, **kwargs: object) -> ApiClient:
    http = httpx.Client(transport=handler)
    return ApiClient("ap_live_x", "https://api.example", client=http, **kwargs)  # type: ignore[arg-type]


def test_push_success() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["Authorization"] == "Bearer ap_live_x"
        assert "Idempotency-Key" in request.headers
        return httpx.Response(201, json={"scanId": "server-1", "reportUrl": "https://app/r/1"})

    client = _client(httpx.MockTransport(handler))
    result = client.push_scan(_result())
    assert result == PushResult(scan_id="server-1", report_url="https://app/r/1")
    client.close()


def test_push_client_error_raises() -> None:
    handler = httpx.MockTransport(lambda req: httpx.Response(400, text="bad payload"))
    with pytest.raises(ApiError, match="rejected"):
        _client(handler).push_scan(_result())


def test_push_server_error_retries_then_raises() -> None:
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(500, text="boom")

    with pytest.raises(ApiError, match="after 3 attempts"):
        _client(httpx.MockTransport(handler), max_retries=3).push_scan(_result())
    assert calls["n"] == 3


def test_push_network_error_then_success() -> None:
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] == 1:
            raise httpx.ConnectError("down")
        return httpx.Response(200, json={"reportUrl": "https://app/r/2"})

    result = _client(httpx.MockTransport(handler)).push_scan(_result())
    assert result.report_url == "https://app/r/2"
    assert result.scan_id == "scan-1"


def test_push_all_network_errors_raises() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("down")

    with pytest.raises(ApiError, match="after 2 attempts"):
        _client(httpx.MockTransport(handler), max_retries=2).push_scan(_result())


def test_idempotency_key_is_stable() -> None:
    assert idempotency_key(_result()) == idempotency_key(_result())
