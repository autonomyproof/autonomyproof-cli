"""Repository and file discovery."""

from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass
from pathlib import Path

_PRUNED_DIRS = {
    ".git",
    ".venv",
    "venv",
    "env",
    "node_modules",
    "dist",
    "build",
    "coverage",
    "__pycache__",
    "vendor",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
}
_DEP_NAME = re.compile(r"^[A-Za-z0-9._-]+")


@dataclass
class RepoMetadata:
    """Best-effort git identity read from the ``.git`` directory (no subprocess)."""

    branch: str | None = None
    commit: str | None = None


def _glob_to_regex(pattern: str) -> re.Pattern[str]:
    """Translate a git-style glob (with ``**``) into an anchored regex."""
    out = ["(?s:"]
    i = 0
    while i < len(pattern):
        char = pattern[i]
        if pattern[i : i + 3] == "**/":
            out.append("(?:.*/)?")
            i += 3
        elif pattern[i : i + 2] == "**":
            out.append(".*")
            i += 2
        elif char == "*":
            out.append("[^/]*")
            i += 1
        elif char == "?":
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(char))
            i += 1
    out.append(")\\Z")
    return re.compile("".join(out))


def _matches_any(rel_path: str, patterns: list[str]) -> bool:
    return any(_glob_to_regex(pattern).match(rel_path) for pattern in patterns)


def read_ignore_patterns(root: Path) -> list[str]:
    """Read ``.autonomyproofignore`` glob lines, ignoring blanks and comments."""
    ignore_file = root / ".autonomyproofignore"
    if not ignore_file.exists():
        return []
    patterns: list[str] = []
    for line in ignore_file.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            normalized = stripped + "**" if stripped.endswith("/") else stripped
            patterns.append(normalized)
    return patterns


def discover_files(root: Path, include: list[str], exclude: list[str]) -> list[Path]:
    """Return matched files under ``root`` honoring include/exclude and pruned dirs."""
    matched: list[Path] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        rel_parts = path.relative_to(root).parts
        if any(part in _PRUNED_DIRS for part in rel_parts):
            continue
        rel = path.relative_to(root).as_posix()
        if _matches_any(rel, include) and not _matches_any(rel, exclude):
            matched.append(path)
    return matched


def dependency_names(root: Path) -> list[str]:
    """Extract dependency package names from common Python manifests (best effort)."""
    names: set[str] = set()

    requirements = root / "requirements.txt"
    if requirements.exists():
        for line in requirements.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if stripped and not stripped.startswith("#"):
                match = _DEP_NAME.match(stripped)
                if match:
                    names.add(match.group(0))

    for manifest in ("pyproject.toml", "Pipfile"):
        path = root / manifest
        if not path.exists():
            continue
        try:
            data = tomllib.loads(path.read_text(encoding="utf-8"))
        except tomllib.TOMLDecodeError:
            continue
        names.update(_names_from_toml(data))

    return sorted(names)


def _names_from_toml(data: dict[str, object]) -> set[str]:
    names: set[str] = set()
    project = data.get("project")
    if isinstance(project, dict):
        deps = project.get("dependencies")
        if isinstance(deps, list):
            for dep in deps:
                match = _DEP_NAME.match(str(dep))
                if match:
                    names.add(match.group(0))
    packages = data.get("packages")
    if isinstance(packages, dict):
        names.update(str(key) for key in packages)
    return names


def read_repo_metadata(root: Path) -> RepoMetadata:
    """Read branch and commit from ``.git`` without invoking git."""
    head_file = root / ".git" / "HEAD"
    if not head_file.exists():
        return RepoMetadata()
    head = head_file.read_text(encoding="utf-8").strip()
    if head.startswith("ref: "):
        ref = head[5:]
        branch = ref.rsplit("/", 1)[-1]
        commit = _resolve_ref(root, ref)
        return RepoMetadata(branch=branch, commit=commit)
    return RepoMetadata(branch=None, commit=head)


def _resolve_ref(root: Path, ref: str) -> str | None:
    ref_file = root / ".git" / ref
    if ref_file.exists():
        return ref_file.read_text(encoding="utf-8").strip()
    packed = root / ".git" / "packed-refs"
    if packed.exists():
        for line in packed.read_text(encoding="utf-8").splitlines():
            if line.endswith(ref):
                return line.split(" ", 1)[0]
    return None
