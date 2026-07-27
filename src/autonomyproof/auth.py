"""Local credential storage for the CLI (token + cloud API URL)."""

from __future__ import annotations

import json
import os
import stat
from dataclasses import dataclass
from pathlib import Path

TOKEN_ENV_VAR = "AUTONOMYPROOF_TOKEN"
API_URL_ENV_VAR = "AUTONOMYPROOF_API_URL"
DEFAULT_API_URL = "https://api.autonomyproof.io"


@dataclass
class Credentials:
    """A resolved token and API URL, plus where the token came from."""

    token: str | None
    api_url: str
    source: str  # "env", "file", or "none"


def _credentials_path() -> Path:
    override = os.environ.get("AUTONOMYPROOF_HOME")
    base = Path(override) if override else Path.home() / ".autonomyproof"
    return base / "credentials.json"


def load_credentials() -> Credentials:
    """Resolve credentials, preferring the environment over the stored file."""
    api_url = os.environ.get(API_URL_ENV_VAR, DEFAULT_API_URL)
    env_token = os.environ.get(TOKEN_ENV_VAR)
    if env_token:
        return Credentials(token=env_token, api_url=api_url, source="env")

    path = _credentials_path()
    if path.exists():
        data = json.loads(path.read_text(encoding="utf-8"))
        return Credentials(
            token=data.get("token"),
            api_url=os.environ.get(API_URL_ENV_VAR, data.get("api_url", api_url)),
            source="file",
        )
    return Credentials(token=None, api_url=api_url, source="none")


def save_token(token: str, api_url: str = DEFAULT_API_URL) -> Path:
    """Persist ``token`` and ``api_url`` with owner-only permissions."""
    path = _credentials_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"token": token, "api_url": api_url}), encoding="utf-8")
    path.chmod(stat.S_IRUSR | stat.S_IWUSR)
    return path


def clear_token() -> bool:
    """Delete stored credentials. Returns ``True`` if a file was removed."""
    path = _credentials_path()
    if path.exists():
        path.unlink()
        return True
    return False
