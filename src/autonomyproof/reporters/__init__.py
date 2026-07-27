"""Report generation: JSON, HTML, and SARIF."""

from __future__ import annotations

from autonomyproof.reporters.html_reporter import render_html, write_html
from autonomyproof.reporters.json_reporter import build_report_dict, write_json
from autonomyproof.reporters.sarif_reporter import build_sarif, write_sarif

__all__ = [
    "build_report_dict",
    "build_sarif",
    "render_html",
    "write_html",
    "write_json",
    "write_sarif",
]
