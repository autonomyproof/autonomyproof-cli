"""Standalone HTML report (PRD §14.2). No external CDN dependency."""

from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, select_autoescape

from autonomyproof.models import ScanResult
from autonomyproof.scoring import SCORE_DISCLAIMER

_TEMPLATE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>AutonomyProof Report — {{ project.name }}</title>
<style>
  :root { color-scheme: light dark; --crit:#b3261e; --high:#c05600; --med:#8a6d00; --low:#3a6ea5; }
  * { box-sizing: border-box; }
  body { font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; margin:0;
         line-height:1.5; color:#1a1a1a; background:#f6f7f9; }
  main { max-width: 960px; margin: 0 auto; padding: 24px; }
  header { background:#0b1f3a; color:#fff; padding:24px; }
  h1 { margin:0 0 4px; font-size:1.5rem; } h2 { margin-top:2rem; border-bottom:1px solid #dce0e6; padding-bottom:4px; }
  .score { font-size:3rem; font-weight:700; } .muted { color:#5b6570; }
  table { border-collapse: collapse; width:100%; margin-top:8px; }
  th, td { text-align:left; padding:8px 10px; border-bottom:1px solid #e2e6ec; vertical-align:top; font-size:.94rem; }
  .sev { font-weight:700; text-transform:uppercase; font-size:.72rem; padding:2px 8px; border-radius:10px; color:#fff; }
  .sev-critical { background:var(--crit); } .sev-high { background:var(--high); }
  .sev-medium { background:var(--med); } .sev-low { background:var(--low); }
  code { background:#eef1f5; padding:1px 5px; border-radius:4px; font-size:.85rem; }
  ul { margin:4px 0 4px 18px; } .card { background:#fff; border:1px solid #e2e6ec; border-radius:8px; padding:16px; margin-top:12px; }
  .disclaimer { font-size:.82rem; color:#5b6570; margin-top:24px; }
  @media (prefers-color-scheme: dark) {
    body { background:#12151a; color:#e6e8eb; } .card, table { background:#1b1f26; }
    th, td { border-color:#2a2f37; } code { background:#2a2f37; } .muted,.disclaimer { color:#9aa4b0; }
  }
</style>
</head>
<body>
<header>
  <h1>AutonomyProof Readiness Report</h1>
  <div>{{ project.name }} · scan <code>{{ scan_id }}</code> · scanner {{ scanner_version }}</div>
</header>
<main>
  <section id="summary">
    <h2>1. Executive summary</h2>
    <div class="card">
      <span class="score">{{ score }}</span> / 100 &nbsp;
      <span class="sev sev-{{ risk_level|lower }}">{{ risk_level }} risk</span>
      <p class="muted">{{ files_scanned }} Python file(s) scanned ·
        {{ findings|length }} finding(s) · {{ frameworks|length }} framework(s) ·
        {{ tools|length }} tool(s){% if project.branch %} · branch {{ project.branch }}{% endif %}</p>
      <p>Critical: {{ counts.critical }} · High: {{ counts.high }} ·
         Medium: {{ counts.medium }} · Low: {{ counts.low }}</p>
    </div>
  </section>

  <section id="frameworks">
    <h2>2. Agent frameworks</h2>
    {% if frameworks %}<ul>{% for f in frameworks %}<li>{{ f }}</li>{% endfor %}</ul>
    {% else %}<p class="muted">No recognized agent framework detected.</p>{% endif %}
  </section>

  <section id="inventory">
    <h2>3. Tool and capability inventory</h2>
    {% if capabilities %}<ul>{% for c in capabilities %}<li><strong>{{ c.name }}:</strong> {{ c.detail }}</li>{% endfor %}</ul>
    {% else %}<p class="muted">No tools or capabilities inventoried.</p>{% endif %}
  </section>

  <section id="critical">
    <h2>4. Critical findings</h2>
    {% set crit = findings|selectattr('severity','equalto','critical')|list %}
    {% if crit %}<ul>{% for f in crit %}<li><strong>{{ f.ruleId }}</strong> — {{ f.title }}
      (<code>{{ f.file }}:{{ f.line }}</code>)</li>{% endfor %}</ul>
    {% else %}<p class="muted">No critical findings.</p>{% endif %}
  </section>

  <section id="findings">
    <h2>5. Findings by severity</h2>
    {% if findings %}
    <table>
      <thead><tr><th>Severity</th><th>Rule</th><th>Title</th><th>Location</th></tr></thead>
      <tbody>
      {% for f in findings %}
        <tr>
          <td><span class="sev sev-{{ f.severity }}">{{ f.severity }}</span></td>
          <td>{{ f.ruleId }}</td><td>{{ f.title }}</td>
          <td><code>{{ f.file }}:{{ f.line }}</code></td>
        </tr>
      {% endfor %}
      </tbody>
    </table>
    {% else %}<p class="muted">No findings.</p>{% endif %}
  </section>

  <section id="evidence">
    <h2>6. Detailed evidence &amp; remediation</h2>
    {% for f in findings %}
    <div class="card">
      <span class="sev sev-{{ f.severity }}">{{ f.severity }}</span>
      <strong>{{ f.ruleId }} — {{ f.title }}</strong>
      <p>{{ f.description }}</p>
      <p><strong>Location:</strong> <code>{{ f.file }}:{{ f.line }}</code>
         {% if f.toolName %} · <strong>Tool:</strong> {{ f.toolName }}{% endif %}
         {% if f.framework %} · <strong>Framework:</strong> {{ f.framework }}{% endif %}</p>
      <p><strong>Evidence:</strong> <code>{{ f.evidence }}</code></p>
      <p><strong>Risk:</strong> {{ f.risk }}</p>
      <p><strong>Remediation:</strong></p>
      <ul>{% for step in f.remediation %}<li>{{ step }}</li>{% endfor %}</ul>
      <p class="muted"><strong>Mappings:</strong>
        OWASP: {{ f.mappings.owaspAgentic|join(', ') }} ·
        NIST: {{ f.mappings.nistAiRmf|join(', ') }} ·
        ISO 42001: {{ f.mappings.iso42001Alignment|join(', ') }}</p>
      <p class="muted">Fingerprint: <code>{{ f.fingerprint }}</code></p>
    </div>
    {% endfor %}
  </section>

  <section id="limits">
    <h2>7. Scan limitations</h2>
    <p class="muted">Static analysis of Python source only. It cannot observe runtime behavior,
    and clean results do not guarantee security. {{ errors|length }} file(s) were skipped.</p>
  </section>

  <section id="privacy">
    <h2>8. Privacy statement</h2>
    <p class="muted">Scanning is local. No source code, secrets, prompts, or tool output leave
    your machine unless you explicitly push sanitized findings to AutonomyProof Cloud.</p>
  </section>

  <p class="disclaimer">{{ disclaimer }}</p>
</main>
</body>
</html>
"""


def render_html(result: ScanResult) -> str:
    """Render a fully self-contained HTML report string for ``result``."""
    env = Environment(autoescape=select_autoescape(["html", "xml"]))
    template = env.from_string(_TEMPLATE)
    return template.render(
        project=result.project,
        scan_id=result.scan_id,
        scanner_version=result.scanner_version,
        score=result.score,
        risk_level=result.risk_level,
        files_scanned=result.files_scanned,
        frameworks=result.frameworks,
        tools=result.tools,
        capabilities=result.capabilities,
        findings=[f.to_dict() for f in result.findings],
        counts=result.severity_counts(),
        errors=result.errors,
        disclaimer=SCORE_DISCLAIMER,
    )


def write_html(result: ScanResult, path: Path) -> Path:
    """Write the HTML report to ``path`` and return it."""
    path.write_text(render_html(result), encoding="utf-8")
    return path
