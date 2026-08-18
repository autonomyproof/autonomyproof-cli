"""Command-line interface (PRD §9)."""

from __future__ import annotations

import webbrowser
from pathlib import Path

import click

from autonomyproof import __version__
from autonomyproof.api import ApiClient, ApiError
from autonomyproof.auth import (
    DEFAULT_API_URL,
    clear_token,
    load_credentials,
    save_token,
)
from autonomyproof.baseline import (
    BASELINE_FILENAME,
    BaselineError,
    load_baseline_fingerprints,
    new_findings,
    write_baseline,
)
from autonomyproof.config import (
    CONFIG_FILENAME,
    DEFAULT_IGNORE_CONTENT,
    IGNORE_FILENAME,
    Config,
    ConfigError,
    default_config_yaml,
)
from autonomyproof.models import Finding, ScanResult, Severity
from autonomyproof.reporters import write_html, write_json, write_sarif
from autonomyproof.rules.base import Rule
from autonomyproof.rules.categories import CATEGORY_ORDER
from autonomyproof.rules.registry import all_rules, get_rule
from autonomyproof.scanner import Scanner
from autonomyproof.scoring import SCORE_DISCLAIMER

_FAIL_RANKS = {
    "critical": Severity.CRITICAL.rank,
    "high": Severity.HIGH.rank,
    "medium": Severity.MEDIUM.rank,
    "low": Severity.LOW.rank,
    "none": None,
}
_REPORT_STEM = "autonomyproof-report"


def _load_config(config_path: Path | None, root: Path) -> Config:
    target = config_path or (root / CONFIG_FILENAME)
    if target.exists():
        return Config.load(target)
    return Config()


def _resolve_root(target: Path) -> Path:
    return target if target.is_dir() else target.parent


def _configure(
    config_path: Path | None,
    root: Path,
    include: tuple[str, ...],
    exclude: tuple[str, ...],
) -> Config:
    config = _load_config(config_path, root)
    if include:
        config.include = list(include)
    if exclude:
        config.exclude = [*config.exclude, *exclude]
    return config


def _write_reports(result: ScanResult, fmt: str, out_dir: Path) -> list[Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    if fmt in {"json", "all"}:
        written.append(write_json(result, out_dir / f"{_REPORT_STEM}.json"))
    if fmt in {"html", "all"}:
        written.append(write_html(result, out_dir / f"{_REPORT_STEM}.html"))
    if fmt in {"sarif", "all"}:
        written.append(write_sarif(result, out_dir / f"{_REPORT_STEM}.sarif"))
    return written


def _should_fail(findings: list[Finding], fail_on: str) -> bool:
    threshold = _FAIL_RANKS[fail_on]
    if threshold is None:
        return False
    return any(f.severity.rank >= threshold for f in findings)


@click.group()
@click.version_option(__version__, prog_name="autonomyproof")
def main() -> None:
    """AutonomyProof — find unsafe capabilities and missing guardrails in AI agents."""


@main.command()
@click.option("--path", "root", type=click.Path(file_okay=False, path_type=Path), default=".")
def init(root: Path) -> None:
    """Create autonomyproof.yaml and .autonomyproofignore."""
    root.mkdir(parents=True, exist_ok=True)
    config_path = root / CONFIG_FILENAME
    ignore_path = root / IGNORE_FILENAME
    if config_path.exists():
        click.echo(f"{CONFIG_FILENAME} already exists; leaving it unchanged.")
    else:
        config_path.write_text(default_config_yaml(root.resolve().name), encoding="utf-8")
        click.echo(f"Wrote {config_path}")
    if not ignore_path.exists():
        ignore_path.write_text(DEFAULT_IGNORE_CONTENT, encoding="utf-8")
        click.echo(f"Wrote {ignore_path}")


@main.command()
@click.argument("target", type=click.Path(exists=True, path_type=Path), default=".")
@click.option("--local-only", is_flag=True, help="Never contact the cloud.")
@click.option("--push/--no-push", default=True, help="Push sanitized findings when logged in.")
@click.option("--fail-on", type=click.Choice(list(_FAIL_RANKS)), default=None)
@click.option(
    "--baseline",
    "baseline_path",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
    help="Gate only on findings absent from this baseline (authority-regression gate).",
)
@click.option("--format", "fmt", type=click.Choice(["html", "json", "sarif", "all"]), default="all")
@click.option("--output", type=click.Path(file_okay=False, path_type=Path), default=".")
@click.option("--project", "project_name", default=None)
@click.option("--api-url", default=None)
@click.option("--config", "config_path", type=click.Path(path_type=Path), default=None)
@click.option("--include", multiple=True, help="Override include glob(s).")
@click.option("--exclude", multiple=True, help="Additional exclude glob(s).")
@click.option("--verbose", is_flag=True)
@click.option("--no-cache", is_flag=True, help="Reserved: disable caching (no cache yet).")
@click.pass_context
def scan(
    ctx: click.Context,
    target: Path,
    local_only: bool,
    push: bool,
    fail_on: str | None,
    baseline_path: Path | None,
    fmt: str,
    output: Path,
    project_name: str | None,
    api_url: str | None,
    config_path: Path | None,
    include: tuple[str, ...],
    exclude: tuple[str, ...],
    verbose: bool,
    no_cache: bool,
) -> None:
    """Scan TARGET (default: current directory)."""
    root = _resolve_root(target)
    config = _configure(config_path, root, include, exclude)
    effective_fail_on = fail_on or config.fail_on

    result = Scanner(config).scan(root, project_name=project_name)
    written = _write_reports(result, fmt, output)

    click.echo(f"Score {result.score}/100 — {result.risk_level} risk")
    counts = result.severity_counts()
    click.echo(
        f"Findings: {len(result.findings)} "
        f"(critical {counts['critical']}, high {counts['high']}, "
        f"medium {counts['medium']}, low {counts['low']})"
    )

    gated = result.findings
    if baseline_path is not None:
        try:
            known = load_baseline_fingerprints(baseline_path)
        except BaselineError as exc:
            raise click.ClickException(str(exc)) from exc
        gated = new_findings(result.findings, known)
        click.echo(f"Baseline: {len(result.findings) - len(gated)} known, {len(gated)} new")

    if verbose:
        for finding in gated:
            click.echo(
                f"  {finding.severity.value:8} {finding.ruleId} {finding.file}:{finding.line}"
            )
    for path in written:
        click.echo(f"Report: {path}")

    _maybe_push(result, local_only=local_only, push=push, api_url=api_url)
    click.echo(SCORE_DISCLAIMER)

    if _should_fail(gated, effective_fail_on):
        ctx.exit(1)


def _maybe_push(result: ScanResult, *, local_only: bool, push: bool, api_url: str | None) -> None:
    if local_only or not push:
        return
    creds = load_credentials()
    if not creds.token:
        click.echo("Not logged in — sign up at https://app.autonomyproof.io to push results.")
        return
    client = ApiClient(creds.token, api_url or creds.api_url)
    try:
        pushed = client.push_scan(result)
        click.echo(f"Pushed to cloud. Hosted report: {pushed.report_url}")
    except ApiError as exc:
        click.echo(f"Cloud push failed ({exc}). Local report preserved.")
    finally:
        client.close()


@main.command("baseline")
@click.argument("target", type=click.Path(exists=True, path_type=Path), default=".")
@click.option(
    "--output",
    type=click.Path(dir_okay=False, path_type=Path),
    default=BASELINE_FILENAME,
    help="Where to write the baseline file.",
)
@click.option("--project", "project_name", default=None)
@click.option("--config", "config_path", type=click.Path(path_type=Path), default=None)
@click.option("--include", multiple=True, help="Override include glob(s).")
@click.option("--exclude", multiple=True, help="Additional exclude glob(s).")
def baseline(
    target: Path,
    output: Path,
    project_name: str | None,
    config_path: Path | None,
    include: tuple[str, ...],
    exclude: tuple[str, ...],
) -> None:
    """Record TARGET's current findings as an authority baseline.

    Commit the baseline, then gate future scans with
    ``autonomyproof scan --baseline <file> --fail-on <level>`` so a pull request
    fails only when it introduces new unsafe authority.
    """
    root = _resolve_root(target)
    config = _configure(config_path, root, include, exclude)
    result = Scanner(config).scan(root, project_name=project_name)
    path = write_baseline(result, Path(output))
    click.echo(f"Wrote baseline with {len(result.findings)} findings to {path}")


@main.command()
@click.option("--api-url", default=DEFAULT_API_URL)
@click.option("--token", default=None, help="Paste a token non-interactively.")
def login(api_url: str, token: str | None) -> None:
    """Authenticate the CLI with AutonomyProof Cloud."""
    click.echo(f"Open browser: {api_url.replace('api.', 'app.')}/cli-login")
    resolved = token or click.prompt("Paste your API token", hide_input=True)
    if not resolved.startswith("ap_live_"):
        raise click.ClickException("Token must start with 'ap_live_'.")
    path = save_token(resolved, api_url)
    click.echo(f"Saved credentials to {path}")


@main.command()
def logout() -> None:
    """Remove stored cloud credentials."""
    if clear_token():
        click.echo("Logged out.")
    else:
        click.echo("No stored credentials.")


@main.group()
def report() -> None:
    """Work with local reports."""


@report.command("open")
@click.option("--output", type=click.Path(file_okay=False, path_type=Path), default=".")
def report_open(output: Path) -> None:
    """Open the latest HTML report in a browser."""
    html = output / f"{_REPORT_STEM}.html"
    if not html.exists():
        raise click.ClickException(f"No report found at {html}. Run a scan first.")
    webbrowser.open(html.resolve().as_uri())
    click.echo(f"Opened {html}")


@main.group()
def config() -> None:
    """Configuration helpers."""


@config.command("validate")
@click.option("--config", "config_path", type=click.Path(path_type=Path), default=CONFIG_FILENAME)
def config_validate(config_path: Path) -> None:
    """Validate an autonomyproof.yaml file."""
    path = Path(config_path)
    if not path.exists():
        raise click.ClickException(f"{path} not found.")
    try:
        Config.load(path)
    except ConfigError as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo(f"{path} is valid.")


@main.group()
def rules() -> None:
    """Inspect the rule catalogue."""


@rules.command("list")
def rules_list() -> None:
    """List every rule, grouped by assessment lens."""
    rules_by_category: dict[str, list[Rule]] = {}
    for rule in all_rules():
        rules_by_category.setdefault(rule.category, []).append(rule)
    for category in CATEGORY_ORDER:
        group = rules_by_category.get(category, [])
        click.echo(f"\n{category} ({len(group)})")
        for rule in group:
            click.echo(f"  {rule.id}  {rule.default_severity.value:8}  {rule.name}")


@rules.command("explain")
@click.argument("rule_id")
def rules_explain(rule_id: str) -> None:
    """Explain a single rule, e.g. 'AG001'."""
    try:
        rule = get_rule(rule_id)
    except KeyError as exc:
        raise click.ClickException(f"Unknown rule: {rule_id}") from exc
    click.echo(f"{rule.id} — {rule.name}")
    click.echo(f"Category: {rule.category}")
    click.echo(f"Severity: {rule.default_severity.value}")
    click.echo(f"Description: {rule.description}")
    click.echo(f"Risk: {rule.risk}")
    click.echo("Remediation:")
    for step in rule.remediation:
        click.echo(f"  - {step}")
    if rule.mappings.mitre:
        click.echo(f"MITRE: {', '.join(rule.mappings.mitre)}")
