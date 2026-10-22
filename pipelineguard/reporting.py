"""Render a combined Markdown report."""
from __future__ import annotations

from datetime import datetime, timezone

from .blast import BlastRadius, to_mermaid
from .models import Alert, Finding


def render_report(findings: list[Finding], blast: list[BlastRadius], alerts: list[Alert]) -> str:
    out = ["# PipelineGuard report", "",
           f"Generated {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}", ""]

    out += ["## Static findings", ""]
    if findings:
        out += ["| Severity | Rule | Location | Issue |", "|---|---|---|---|"]
        for f in findings:
            out.append(f"| {f.severity.name} | {f.rule_id} | `{f.location}` | {f.title} |")
        out += ["", "### Remediation", ""]
        seen = set()
        for f in findings:
            if (f.rule_id, f.remediation) not in seen:
                seen.add((f.rule_id, f.remediation))
                out.append(f"- **{f.rule_id}**: {f.remediation}")
    else:
        out.append("No findings.")

    out += ["", "## Identity blast radius", ""]
    if blast:
        out += ["| Priority | Identity | Score | CI reachable | Trust | Key capabilities |", "|---|---|---|---|---|---|"]
        for b in blast:
            caps = ", ".join((b.privesc + b.data)[:4]) or "none"
            out.append(f"| {b.priority} | {b.name} | {b.score} ({b.tier.name}) | "
                       f"{'yes' if b.ci_reachable else 'no'} | {b.trust_note if b.ci_reachable else '-'} | {caps} |")
        out += ["", "```mermaid", to_mermaid(blast), "```",
                "", "_Deny statements, boundaries, SCPs and conditions are not evaluated, so scores are an upper bound._"]
    else:
        out.append("No cloud inventory collected.")

    out += ["", "## Runtime detections", ""]
    if alerts:
        out += ["| Severity | Rule | ATT&CK | Actor | Detail |", "|---|---|---|---|---|"]
        for a in alerts:
            out.append(f"| {a.severity.name} | {a.rule_id} | {a.technique} | `{a.actor}` | {a.details} |")
    else:
        out.append("No alerts.")
    return "\n".join(out) + "\n"
