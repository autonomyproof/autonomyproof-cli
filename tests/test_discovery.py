"""Tests for repository and file discovery."""

from __future__ import annotations

from pathlib import Path

from autonomyproof.discovery import (
    dependency_names,
    discover_files,
    read_ignore_patterns,
    read_repo_metadata,
)


def _rel(root: Path, paths: list[Path]) -> set[str]:
    return {p.relative_to(root).as_posix() for p in paths}


def test_discover_include_exclude_and_prune(tmp_path: Path) -> None:
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg" / "a.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / "top.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / "skip.txt").write_text("no\n", encoding="utf-8")
    (tmp_path / ".venv").mkdir()
    (tmp_path / ".venv" / "lib.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / "vendored").mkdir()
    (tmp_path / "vendored" / "v.py").write_text("x = 1\n", encoding="utf-8")

    found = discover_files(tmp_path, include=["**/*.py"], exclude=["vendored/**"])
    assert _rel(tmp_path, found) == {"pkg/a.py", "top.py"}


def test_glob_special_forms(tmp_path: Path) -> None:
    (tmp_path / "a").mkdir()
    (tmp_path / "a" / "b.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / "c.py").write_text("x = 1\n", encoding="utf-8")

    assert _rel(tmp_path, discover_files(tmp_path, ["**"], [])) == {"a/b.py", "c.py"}
    assert _rel(tmp_path, discover_files(tmp_path, ["*.py"], [])) == {"c.py"}
    assert _rel(tmp_path, discover_files(tmp_path, ["?.py"], [])) == {"c.py"}
    assert _rel(tmp_path, discover_files(tmp_path, ["**/*.py"], [])) == {"a/b.py", "c.py"}


def test_read_ignore_patterns(tmp_path: Path) -> None:
    (tmp_path / ".autonomyproofignore").write_text("# comment\n\nbuild/\n*.tmp\n", encoding="utf-8")
    assert read_ignore_patterns(tmp_path) == ["build/**", "*.tmp"]


def test_read_ignore_patterns_missing(tmp_path: Path) -> None:
    assert read_ignore_patterns(tmp_path) == []


def test_dependency_names_requirements(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text(
        "# deps\nlanggraph>=0.2\nrequests==2.31\n@@@ not-a-package\n\n", encoding="utf-8"
    )
    assert set(dependency_names(tmp_path)) == {"langgraph", "requests"}


def test_dependency_names_pyproject(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        '[project]\ndependencies = ["crewai>=0.1", "httpx"]\n', encoding="utf-8"
    )
    assert set(dependency_names(tmp_path)) == {"crewai", "httpx"}


def test_dependency_names_pipfile(tmp_path: Path) -> None:
    (tmp_path / "Pipfile").write_text('[packages]\nautogen = "*"\n', encoding="utf-8")
    assert dependency_names(tmp_path) == ["autogen"]


def test_dependency_names_invalid_toml(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text("not = = valid\n", encoding="utf-8")
    assert dependency_names(tmp_path) == []


def test_dependency_names_toml_without_project(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text("[tool.ruff]\nline-length = 100\n", encoding="utf-8")
    assert dependency_names(tmp_path) == []


def test_dependency_names_toml_deps_not_list(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text('[project]\ndependencies = "oops"\n', encoding="utf-8")
    assert dependency_names(tmp_path) == []


def test_dependency_names_toml_skips_unparsable_entry(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        '[project]\ndependencies = ["valid", "@@@"]\n', encoding="utf-8"
    )
    assert dependency_names(tmp_path) == ["valid"]


def test_repo_metadata_branch_ref(tmp_path: Path) -> None:
    git = tmp_path / ".git"
    (git / "refs" / "heads").mkdir(parents=True)
    (git / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
    (git / "refs" / "heads" / "main").write_text("abc123\n", encoding="utf-8")
    meta = read_repo_metadata(tmp_path)
    assert meta.branch == "main"
    assert meta.commit == "abc123"


def test_repo_metadata_packed_refs(tmp_path: Path) -> None:
    git = tmp_path / ".git"
    git.mkdir()
    (git / "HEAD").write_text("ref: refs/heads/dev\n", encoding="utf-8")
    (git / "packed-refs").write_text("deadbeef refs/heads/dev\n", encoding="utf-8")
    meta = read_repo_metadata(tmp_path)
    assert meta.commit == "deadbeef"


def test_repo_metadata_packed_refs_no_match(tmp_path: Path) -> None:
    git = tmp_path / ".git"
    git.mkdir()
    (git / "HEAD").write_text("ref: refs/heads/dev\n", encoding="utf-8")
    (git / "packed-refs").write_text("aaa refs/heads/other\nbbb refs/tags/v1\n", encoding="utf-8")
    assert read_repo_metadata(tmp_path).commit is None


def test_repo_metadata_detached_head(tmp_path: Path) -> None:
    git = tmp_path / ".git"
    git.mkdir()
    (git / "HEAD").write_text("cafebabe\n", encoding="utf-8")
    meta = read_repo_metadata(tmp_path)
    assert meta.branch is None
    assert meta.commit == "cafebabe"


def test_repo_metadata_unresolvable_ref(tmp_path: Path) -> None:
    git = tmp_path / ".git"
    git.mkdir()
    (git / "HEAD").write_text("ref: refs/heads/ghost\n", encoding="utf-8")
    meta = read_repo_metadata(tmp_path)
    assert meta.branch == "ghost"
    assert meta.commit is None


def test_repo_metadata_no_git(tmp_path: Path) -> None:
    assert read_repo_metadata(tmp_path).commit is None
