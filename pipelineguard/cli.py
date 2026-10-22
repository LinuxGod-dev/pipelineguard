"""Command line interface: python -m pipelineguard <command>."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import blast, inventory, remediate
from .aws_client import make_client
from .detections.engine import DetectionConfig, load_events, run_detections
from .models import Alert, Finding, Severity
from .reporting import render_report
from .rules.identity_rules import audit_identities, audit_trust_policy
from .rules.workflow_rules import scan_path
from .simulate import attack, scenario


def _print_findings(findings: list[Finding], as_json: bool) -> None:
    if as_json:
        print(json.dumps([f.to_dict() for f in findings], indent=2))
        return
    for f in findings:
        print(f"[{f.severity.name}] {f.rule_id}  {f.location}")
        print(f"  {f.title}")
        print(f"  Fix: {f.remediation}")
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity.name] = counts.get(f.severity.name, 0) + 1
    summary = ", ".join(f"{n} {k}" for k, n in sorted(counts.items(), key=lambda kv: -Severity[kv[0]]))
    print(f"\n{len(findings)} finding(s)" + (f": {summary}" if summary else ""))


def _print_alerts(alerts: list[Alert], as_json: bool) -> None:
    if as_json:
        print(json.dumps([a.to_dict() for a in alerts], indent=2))
        return
    for a in alerts:
        print(f"[{a.severity.name}] {a.rule_id}  {a.technique}  {a.title}")
        print(f"  actor: {a.actor}")
        print(f"  {a.details}")
    print(f"\n{len(alerts)} alert(s)")


def _clients(args, *services: str):
    return [make_client(s, local=args.local, endpoint=args.endpoint) for s in services]


def cmd_scan_workflows(args) -> int:
    findings = scan_path(args.path)
    _print_findings(findings, args.json)
    threshold = Severity.parse(args.fail_on)
    return 1 if any(f.severity >= threshold for f in findings) else 0


def cmd_audit_trust(args) -> int:
    policy = json.loads(Path(args.policy).read_text(encoding="utf-8"))
    findings = audit_trust_policy(args.role, policy)
    _print_findings(findings, args.json)
    return 1 if findings else 0


def cmd_audit_cloud(args) -> int:
    (iam,) = _clients(args, "iam")
    findings = audit_identities(inventory.collect_identities(iam))
    _print_findings(findings, args.json)
    return 0


def cmd_blast(args) -> int:
    (iam,) = _clients(args, "iam")
    results = blast.analyze(inventory.collect_identities(iam))
    print(f"{'PRIORITY':<9}{'IDENTITY':<22}{'SCORE':<12}{'CI':<5}{'TRUST':<18}CAPABILITIES")
    for r in results:
        caps = ", ".join((r.privesc + r.data)[:3]) or "-"
        print(f"{r.priority:<9}{r.name:<22}{str(r.score) + ' ' + r.tier.name:<12}"
              f"{'yes' if r.ci_reachable else 'no':<5}{(r.trust_note if r.ci_reachable else '-'):<18}{caps}")
    if args.mermaid:
        Path(args.mermaid).write_text("```mermaid\n" + blast.to_mermaid(results) + "\n```\n", encoding="utf-8")
        print(f"\nMermaid graph written to {args.mermaid}")
    return 0


def cmd_sim(args) -> int:
    if args.action == "setup":
        iam, s3, sm, sts = _clients(args, "iam", "s3", "secretsmanager", "sts")
        info = scenario.setup(iam, s3, sm, sts)
        print(f"Lab ready in account {info['account']}: roles {scenario.VULN_ROLE} (vulnerable) "
              f"and {scenario.SAFE_ROLE} (scoped), user {scenario.LEGACY_USER}, 4 secrets, 1 bucket.")
    else:
        rec = attack.run_attack(lambda svc, creds=None: make_client(svc, args.local, args.endpoint, creds), args.out)
        print(f"Attack replayed. {len(rec.events)} CloudTrail-format events written to {args.out}")
    return 0


def cmd_detect(args) -> int:
    alerts = run_detections(load_events(args.events), DetectionConfig.load(args.config))
    _print_alerts(alerts, args.json)
    return 0


def cmd_remediate(args) -> int:
    if args.what == "pin":
        for wf in ([Path(args.path)] if Path(args.path).is_file() else sorted(Path(args.path).rglob("*.y*ml"))):
            new, log = remediate.pin_actions(wf.read_text(encoding="utf-8"))
            for line in log:
                print(f"{wf}: {line}")
            if args.write and new != wf.read_text(encoding="utf-8"):
                wf.write_text(new, encoding="utf-8")
                print(f"{wf}: written")
        if not args.write:
            print("\n(dry run; add --write to modify files)")
    elif args.what == "trust":
        policy = json.loads(Path(args.policy).read_text(encoding="utf-8"))
        fixed = remediate.harden_trust_policy(policy, args.repo, args.ref, args.environment)
        print(json.dumps(fixed, indent=2))
        if args.role:
            (iam,) = _clients(args, "iam")
            print(remediate.apply_trust_policy(iam, args.role, fixed, args.apply))
    elif args.what == "quarantine":
        (iam,) = _clients(args, "iam")
        print(remediate.quarantine_role(iam, args.role, args.apply))
    return 0


def cmd_report(args) -> int:
    findings = scan_path(args.workflows) if args.workflows else []
    blasts = []
    if args.cloud:
        (iam,) = _clients(args, "iam")
        idents = inventory.collect_identities(iam)
        findings += audit_identities(idents)
        blasts = blast.analyze(idents)
    alerts = run_detections(load_events(args.events), DetectionConfig.load(args.config)) if args.events else []
    findings.sort(key=lambda f: (-f.severity, f.target, f.line or 0))
    Path(args.out).write_text(render_report(findings, blasts, alerts), encoding="utf-8")
    print(f"Report written to {args.out}")
    return 0


def _add_cloud_flags(p: argparse.ArgumentParser) -> None:
    p.add_argument("--local", action="store_true", help="use LocalStack at http://localhost:4566")
    p.add_argument("--endpoint", help="custom AWS endpoint URL")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="pipelineguard", description=__doc__)
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("scan-workflows", help="audit GitHub Actions workflow files")
    s.add_argument("path")
    s.add_argument("--json", action="store_true")
    s.add_argument("--fail-on", default="high", help="exit 1 at or above this severity (default: high)")
    s.set_defaults(fn=cmd_scan_workflows)

    s = sub.add_parser("audit-trust", help="audit an IAM trust policy JSON file offline")
    s.add_argument("--policy", required=True)
    s.add_argument("--role", default="example-role")
    s.add_argument("--json", action="store_true")
    s.set_defaults(fn=cmd_audit_trust)

    s = sub.add_parser("audit-cloud", help="audit live IAM roles and keys")
    _add_cloud_flags(s)
    s.add_argument("--json", action="store_true")
    s.set_defaults(fn=cmd_audit_cloud)

    s = sub.add_parser("blast", help="score identity blast radius")
    _add_cloud_flags(s)
    s.add_argument("--mermaid", help="write a Mermaid diagram to this file")
    s.set_defaults(fn=cmd_blast)

    s = sub.add_parser("sim", help="build the vulnerable lab / replay the attack")
    s.add_argument("action", choices=["setup", "attack"])
    _add_cloud_flags(s)
    s.add_argument("--out", default="samples/cloudtrail/attack_events.jsonl")
    s.set_defaults(fn=cmd_sim)

    s = sub.add_parser("detect", help="run detections over CloudTrail-format events")
    s.add_argument("--events", required=True)
    s.add_argument("--config")
    s.add_argument("--json", action="store_true")
    s.set_defaults(fn=cmd_detect)

    s = sub.add_parser("remediate", help="fix findings (dry-run by default)")
    rs = s.add_subparsers(dest="what", required=True)
    r = rs.add_parser("pin", help="pin actions to commit SHAs")
    r.add_argument("path")
    r.add_argument("--write", action="store_true")
    r = rs.add_parser("trust", help="harden a GitHub OIDC trust policy")
    r.add_argument("--policy", required=True)
    r.add_argument("--repo", required=True, help="OWNER/REPO")
    r.add_argument("--ref", help="e.g. refs/heads/main")
    r.add_argument("--environment")
    r.add_argument("--role", help="also update this role in AWS")
    r.add_argument("--apply", action="store_true")
    _add_cloud_flags(r)
    r = rs.add_parser("quarantine", help="revoke a compromised role's existing sessions")
    r.add_argument("--role", required=True)
    r.add_argument("--apply", action="store_true")
    _add_cloud_flags(r)
    s.set_defaults(fn=cmd_remediate)

    s = sub.add_parser("report", help="write a combined Markdown report")
    s.add_argument("--workflows")
    s.add_argument("--events")
    s.add_argument("--config")
    s.add_argument("--cloud", action="store_true")
    s.add_argument("--out", default="report.md")
    _add_cloud_flags(s)
    s.set_defaults(fn=cmd_report)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.fn(args)
    except (FileNotFoundError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:  # most often: LocalStack not running
        print(f"error: {type(exc).__name__}: {exc}", file=sys.stderr)
        if "Could not connect" in str(exc) or "Connection" in type(exc).__name__:
            print("Is LocalStack running? Try: docker compose up -d", file=sys.stderr)
        return 2
