"""HTTP client for pushing sanitized scans to AutonomyProof Cloud."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

import httpx

from autonomyproof import __version__
from autonomyproof.models import ScanResult
from autonomyproof.payload import assert_sanitized, build_scan_payload


class ApiError(RuntimeError):
    """Raised when the cloud API rejects a request after retries."""


@dataclass
class PushResult:
    """The outcome of a successful scan push."""

    scan_id: str
    report_url: str


def idempotency_key(result: ScanResult) -> str:
    """Derive a stable idempotency key from the scan identity."""
    material = f"{result.project.name}:{result.project.commit}:{result.scan_id}"
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


class ApiClient:
    """Thin, retrying client for the scan-ingestion endpoint."""

    def __init__(
        self,
        token: str,
        api_url: str,
        *,
        client: httpx.Client | None = None,
        max_retries: int = 3,
    ) -> None:
        self.token = token
        self.api_url = api_url.rstrip("/")
        self.max_retries = max_retries
        self._client = client or httpx.Client(timeout=30.0)

    def push_scan(self, result: ScanResult) -> PushResult:
        """Push a sanitized scan, retrying transient failures. Raises :class:`ApiError`."""
        payload = build_scan_payload(result)
        assert_sanitized(payload)
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Idempotency-Key": idempotency_key(result),
            "User-Agent": f"autonomyproof/{__version__}",
        }
        url = f"{self.api_url}/api/v1/scans"

        last_error = "unknown error"
        for attempt in range(1, self.max_retries + 1):
            try:
                response = self._client.post(url, json=payload, headers=headers)
            except httpx.HTTPError as exc:
                last_error = f"network error: {exc}"
                continue
            if response.status_code < 400:
                body = response.json()
                return PushResult(
                    scan_id=str(body.get("scanId", result.scan_id)),
                    report_url=str(body.get("reportUrl", "")),
                )
            if response.status_code < 500:
                raise ApiError(f"Cloud rejected the scan ({response.status_code}): {response.text}")
            last_error = f"server error {response.status_code}"
            if attempt == self.max_retries:
                break
        raise ApiError(f"Failed to push scan after {self.max_retries} attempts: {last_error}")

    def close(self) -> None:
        """Close the underlying HTTP client."""
        self._client.close()
