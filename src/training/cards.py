# Renders the reference library into markdown "attack cards" for SOC engineers.
#
# Output: one card per technique plus an index, written to a directory. These are
# the reference sheets an on-call engineer keeps open - "what does this attack
# look like, and what do I do about it".

from __future__ import annotations

from pathlib import Path

from .reference import REFERENCE_LIBRARY, TechniqueReference


def _bullets(items) -> str:
    return "\n".join(f"- {i}" for i in items) if items else "_none recorded_"


def render_card(ref: TechniqueReference) -> str:
    lines: list[str] = []
    a = lines.append

    a(f"# {ref.title}")
    a("")
    a(f"> **Phase:** {ref.phase}  |  **Tactic:** {ref.tactic}  |  "
      f"**MITRE:** [{ref.mitre_technique} - {ref.mitre_name}]"
      f"({ref.references[0] if ref.references else 'https://attack.mitre.org'})")
    a("")
    a(f"**What it is.** {ref.summary}")
    a("")
    a(f"**Attacker's goal.** {ref.attacker_goal}")
    a("")

    a("## Where it shows up")
    a("")
    a(f"**Log sources:** {', '.join(ref.log_sources) or 'n/a'}")
    a("")
    a("**Audit operations to search for:**")
    a("")
    a(_bullets(f"`{op}`" for op in ref.audit_operations))
    a("")
    if ref.key_fields:
        a("**Key fields:**")
        a("")
        a("| Field | What to check |")
        a("| --- | --- |")
        for kf in ref.key_fields:
            a(f"| `{kf.get('field','')}` | {kf.get('check','')} |")
        a("")

    a("## How to spot it")
    a("")
    a(_bullets(ref.what_to_look_for))
    a("")
    a("**Common false positives:**")
    a("")
    a(_bullets(ref.false_positives))
    a("")

    if ref.detections:
        a("## Hunting queries")
        a("")
        for q in ref.detections:
            a(f"**{q.platform}**")
            if q.note:
                a("")
                a(f"_{q.note}_")
            a("")
            fence = "kql" if "KQL" in q.platform.upper() else "text"
            a(f"```{fence}")
            a(q.query)
            a("```")
            a("")

    a("## Response runbook")
    a("")
    a(_bullets(ref.response_steps))
    a("")
    a(f"- **CDR event this maps to:** {ref.saas_alerts_event or 'n/a'}")
    a(f"- **Remediation to validate:** {ref.remediation or 'n/a'}")
    a("")

    if ref.references:
        a("## References")
        a("")
        a(_bullets(ref.references))
        a("")

    return "\n".join(lines)


def render_index(library=REFERENCE_LIBRARY) -> str:
    lines = ["# Attack Reference Library", "",
             "SOC / on-call reference cards for the identity & M365 attacks this "
             "engine models. Each card covers what the technique is, the audit "
             "signal it leaves, how to hunt it, and how to respond.", ""]
    for phase in ("Initial Access", "Post-Breach"):
        entries = [r for r in library.values() if r.phase == phase]
        if not entries:
            continue
        lines.append(f"## {phase}")
        lines.append("")
        lines.append("| Technique | MITRE | Detects into (CDR) | Remediation |")
        lines.append("| --- | --- | --- | --- |")
        for r in entries:
            lines.append(
                f"| [{r.title}]({r.key}.md) | {r.mitre_technique} | "
                f"{r.saas_alerts_event or '-'} | {r.remediation or '-'} |"
            )
        lines.append("")
    return "\n".join(lines)


def write_all_cards(out_dir: str | Path, library=REFERENCE_LIBRARY) -> list[Path]:
    """Write one card per technique + an index. Returns the paths written."""
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []

    for ref in library.values():
        p = out / f"{ref.key}.md"
        p.write_text(render_card(ref), encoding="utf-8")
        written.append(p)

    idx = out / "README.md"
    idx.write_text(render_index(library), encoding="utf-8")
    written.append(idx)
    return written
