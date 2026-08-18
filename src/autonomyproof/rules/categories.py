"""Assessment lens each rule belongs to.

AutonomyProof is a security *assessment* across three lenses, not a flat rule list:

- **Harness gaps** — missing or weak runtime controls in the agent framework/config
  (no limits, no timeout, no sandbox, no tracing).
- **Guardrail gaps** — safety controls that are absent, disabled, or bypassable
  (no approval, disabled safety filter, agent can edit its own guardrails).
- **Attack vectors** — concrete exploitable capability or data-flow paths
  (shell/RCE, SSRF, injection, destructive/escalation authority, supply-chain).
"""

from __future__ import annotations

HARNESS = "Harness gap"
GUARDRAIL = "Guardrail gap"
ATTACK_VECTOR = "Attack vector"

# Fixed display order for reports and the CLI.
CATEGORY_ORDER = (HARNESS, GUARDRAIL, ATTACK_VECTOR)

# Every registered rule id -> its assessment lens. Kept central so the whole assessment
# structure is reviewable in one place. `tests/` asserts this covers every rule exactly.
RULE_CATEGORY: dict[str, str] = {
    # --- Harness gaps: missing/weak controls ---
    "AG008": HARNESS,  # missing execution limits
    "AG009": HARNESS,  # excessive/unbounded limits
    "AG010": HARNESS,  # missing action tracing
    "AG016": HARNESS,  # unrestricted sub-agent creation
    "AG018": HARNESS,  # external operation without a timeout
    "AG020": HARNESS,  # missing accountable-agent metadata
    "AG027": HARNESS,  # code-execution sandbox disabled
    # --- Guardrail gaps: safety controls absent/disabled/bypassable ---
    "AG007": GUARDRAIL,  # dangerous operation without human approval
    "AG011": GUARDRAIL,  # persistent memory without tenant isolation
    "AG013": GUARDRAIL,  # MCP tool accepts unvalidated arguments
    "AG015": GUARDRAIL,  # agent can modify its own guardrails
    "AG017": GUARDRAIL,  # secret interpolated into model context
    "AG032": GUARDRAIL,  # model safety filter disabled
    # --- Attack vectors: exploitable capability / data-flow paths ---
    "AG001": ATTACK_VECTOR,  # unrestricted shell execution
    "AG002": ATTACK_VECTOR,  # dynamic code execution
    "AG003": ATTACK_VECTOR,  # arbitrary filesystem access
    "AG004": ATTACK_VECTOR,  # sensitive credential-path access
    "AG005": ATTACK_VECTOR,  # unrestricted outbound HTTP
    "AG006": ATTACK_VECTOR,  # server-side request forgery
    "AG012": ATTACK_VECTOR,  # model-controlled SQL
    "AG014": ATTACK_VECTOR,  # bearer token forwarded without audience separation
    "AG019": ATTACK_VECTOR,  # destructive command exposure
    "AG021": ATTACK_VECTOR,  # insecure deserialization
    "AG022": ATTACK_VECTOR,  # disabled TLS verification
    "AG023": ATTACK_VECTOR,  # server-side template injection
    "AG024": ATTACK_VECTOR,  # dangerous framework capability flag
    "AG025": ATTACK_VECTOR,  # code/shell interpreter tool exposed
    "AG026": ATTACK_VECTOR,  # known-vulnerable dependency (supply chain)
    "AG028": ATTACK_VECTOR,  # code-executing agent or chain
    "AG029": ATTACK_VECTOR,  # unrestricted HTTP request tool
    "AG030": ATTACK_VECTOR,  # agent UI exposed via public tunnel
    "AG031": ATTACK_VECTOR,  # CORS wildcard origin with credentials
    "AG033": ATTACK_VECTOR,  # irreversible data destruction
    "AG034": ATTACK_VECTOR,  # cloud/infrastructure destruction
    "AG035": ATTACK_VECTOR,  # money movement without approval
    "AG036": ATTACK_VECTOR,  # persistence-sensitive file write
    "AG037": ATTACK_VECTOR,  # runtime package installation
    "AG038": ATTACK_VECTOR,  # IAM/privilege escalation
    "AG039": ATTACK_VECTOR,  # world-writable permission grant
    "AG040": ATTACK_VECTOR,  # insecure model-output handling
}


def category_for(rule_id: str) -> str:
    """Return the assessment lens for ``rule_id`` (defaults to Attack vector)."""
    return RULE_CATEGORY.get(rule_id, ATTACK_VECTOR)
