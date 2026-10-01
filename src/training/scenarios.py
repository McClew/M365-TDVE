# Attack-chain scenarios + timeline generation.
#
# A single alert rarely tells the whole story; SOC engineers need to recognise
# how events CHAIN together. Each scenario is a documented narrative that walks a
# realistic compromise step by step, mapping every step to the audit signal it
# produces and the detection that should fire. Rendered as reference material and
# as a timeline for tabletop / purple-team exercises - it describes the chain, it
# does not execute it.

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .reference import REFERENCE_LIBRARY


@dataclass
class ScenarioStep:
    technique_key: str          # -> REFERENCE_LIBRARY
    narrative: str              # what the attacker does at this step
    offset_minutes: int = 0     # relative time from the start of the chain


@dataclass
class Scenario:
    key: str
    title: str
    description: str
    steps: list[ScenarioStep] = field(default_factory=list)


_BEC = Scenario(
    key="bec_takeover",
    title="Business Email Compromise - full account takeover",
    description=(
        "A classic BEC chain: credential access, session establishment, then "
        "persistence and collection inside the mailbox. The value for a SOC is "
        "seeing how the later, quieter events tie back to the noisy first one."
    ),
    steps=[
        ScenarioStep("auth_failure", "Attacker password-sprays the tenant and finds a valid credential.", 0),
        ScenarioStep("mfa_prompt", "With the password, they bomb the user with MFA prompts until one is approved.", 8),
        ScenarioStep("inbox_rule", "Inside the mailbox, they create a rule to auto-read/hide replies to their phishing.", 15),
        ScenarioStep("mail_forwarding", "They add an external forwarding rule to keep receiving mail after they're kicked out.", 18),
        ScenarioStep("anonymous_sharing", "They create anonymous links on finance documents to exfiltrate them.", 25),
    ],
)

_CONSENT_PERSIST = Scenario(
    key="consent_persistence",
    title="Illicit consent grant with token persistence",
    description=(
        "A token-theft chain that never needs the password again. Highlights why "
        "'reset the password' is not sufficient response for consent/token attacks."
    ),
    steps=[
        ScenarioStep("device_code", "Attacker phishes the user with a device code and captures a token.", 0),
        ScenarioStep("consent_url", "Using the session, they lure/authorise a malicious OAuth app with Mail.ReadWrite + offline_access.", 10),
        ScenarioStep("mfa_registration", "They register their own MFA method to keep interactive access too.", 20),
        ScenarioStep("mail_forwarding", "They set forwarding so collection continues even if the app grant is caught.", 30),
    ],
)

_PRIV_ESC = Scenario(
    key="privilege_escalation",
    title="User-to-admin privilege escalation",
    description=(
        "A chain that starts as a normal user and reaches toward tenant control. "
        "Shows the pivot from a single-mailbox compromise to directory-wide risk."
    ),
    steps=[
        ScenarioStep("mfa_prompt", "Attacker gets in via MFA fatigue on a standard user.", 0),
        ScenarioStep("password_change", "They change the password to lock the owner out and hold the account.", 5),
        ScenarioStep("role_assignment", "They assign a privileged directory role to a controlled account.", 12),
        ScenarioStep("consent_url", "As an admin, they grant admin consent to a broad app for durable access.", 20),
    ],
)


SCENARIO_LIBRARY: dict[str, Scenario] = {
    s.key: s for s in [_BEC, _CONSENT_PERSIST, _PRIV_ESC]
}


def build_timeline(scenario: Scenario) -> dict[str, Any]:
    """Return a structured timeline: each step with its expected detection."""
    events = []
    for i, step in enumerate(scenario.steps, start=1):
        ref = REFERENCE_LIBRARY.get(step.technique_key)
        events.append({
            "step": i,
            "offset_minutes": step.offset_minutes,
            "technique_key": step.technique_key,
            "technique": ref.title if ref else step.technique_key,
            "mitre": ref.mitre_technique if ref else None,
            "narrative": step.narrative,
            "audit_operations": ref.audit_operations if ref else [],
            "expected_detection": ref.saas_alerts_event if ref else None,
            "remediation": ref.remediation if ref else None,
        })
    return {
        "scenario": scenario.key,
        "title": scenario.title,
        "description": scenario.description,
        "events": events,
    }


def render_scenario(scenario: Scenario) -> str:
    tl = build_timeline(scenario)
    lines = [f"# Scenario: {scenario.title}", "", scenario.description, "",
             "## Timeline", "",
             "| T+ (min) | Step | Technique (MITRE) | Expected detection | Remediation |",
             "| --- | --- | --- | --- | --- |"]
    for e in tl["events"]:
        lines.append(
            f"| {e['offset_minutes']} | {e['step']}. {e['narrative']} | "
            f"{e['technique']} ({e['mitre']}) | {e['expected_detection'] or '-'} | "
            f"{e['remediation'] or '-'} |"
        )
    lines += ["", "## Audit signals, in order", ""]
    for e in tl["events"]:
        ops = ", ".join(f"`{o}`" for o in e["audit_operations"]) or "_n/a_"
        lines.append(f"- **T+{e['offset_minutes']}m - {e['technique']}:** {ops}")
    lines.append("")
    lines.append("_Tabletop use: reveal one row at a time and have engineers name "
                 "the detection and the response before moving on._")
    lines.append("")
    return "\n".join(lines)
