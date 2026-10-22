"""Blast-radius scoring: what could an attacker do if this identity were stolen?

Limitations (state these in your write-up): Deny statements, permission boundaries,
SCPs and Condition blocks are not evaluated, so scores are an upper bound.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from fnmatch import fnmatchcase
from typing import Any

from .inventory import Identity
from .models import Severity
from .rules.identity_rules import GH_HOST, audit_trust_policy

# action -> weight. Privilege-escalation and persistence primitives weigh most.
PRIVESC_ACTIONS: dict[str, int] = {
    "iam:PassRole": 25,
    "iam:CreateAccessKey": 30,
    "iam:CreateLoginProfile": 25,
    "iam:AttachRolePolicy": 35,
    "iam:PutRolePolicy": 35,
    "iam:AttachUserPolicy": 35,
    "iam:PutUserPolicy": 35,
    "iam:CreatePolicyVersion": 35,
    "iam:UpdateAssumeRolePolicy": 35,
    "sts:AssumeRole": 15,
    "lambda:UpdateFunctionCode": 20,
    "lambda:CreateFunction": 15,
    "ec2:RunInstances": 10,
}
DATA_ACTIONS: dict[str, int] = {
    "secretsmanager:GetSecretValue": 15,
    "ssm:GetParameter": 10,
    "kms:Decrypt": 10,
    "s3:GetObject": 10,
    "s3:PutObject": 10,
    "s3:DeleteObject": 10,
}

TRUST_NOTES = {
    "PG-OIDC-001": "ANY GitHub repo",
    "PG-OIDC-002": "any repo in org",
    "PG-OIDC-003": "any ref / PR",
}


@dataclass
class BlastRadius:
    name: str
    arn: str
    kind: str
    score: int
    tier: Severity
    admin: bool
    privesc: list[str] = field(default_factory=list)
    data: list[str] = field(default_factory=list)
    ci_reachable: bool = False
    trust_worst: Severity | None = None
    trust_note: str = "scoped"
    priority: int = 0


def _statements(policies: list[dict[str, Any]]) -> list[tuple[list[str], list[str]]]:
    out = []
    for doc in policies:
        stmts = doc.get("Statement", [])
        stmts = [stmts] if isinstance(stmts, dict) else stmts
        for s in stmts:
            if s.get("Effect") != "Allow":
                continue
            actions = s.get("Action")
            if actions is None and "NotAction" in s:
                actions = ["*"]  # conservative: Allow + NotAction is near-admin
            actions = [actions] if isinstance(actions, str) else (actions or [])
            res = s.get("Resource", ["*"])
            res = [res] if isinstance(res, str) else res
            out.append((actions, res))
    return out


def _tier(score: int) -> Severity:
    if score >= 80:
        return Severity.CRITICAL
    if score >= 50:
        return Severity.HIGH
    if score >= 20:
        return Severity.MEDIUM
    return Severity.LOW


def score_identity(ident: Identity) -> BlastRadius:
    stmts = _statements(ident.policies)
    admin = any(a in ("*", "*:*") and any(r == "*" for r in res) for acts, res in stmts for a in acts)

    privesc: dict[str, int] = {}
    data: dict[str, int] = {}
    for catalog, bucket in ((PRIVESC_ACTIONS, privesc), (DATA_ACTIONS, data)):
        for action, weight in catalog.items():
            for acts, res in stmts:
                if any(fnmatchcase(action.lower(), a.lower()) for a in acts):
                    wide = any("*" in r for r in res)
                    bucket[action] = max(bucket.get(action, 0), weight if wide else weight // 2)

    score = 100 if admin else min(99, sum(privesc.values()) + sum(data.values()))

    br = BlastRadius(
        name=ident.name, arn=ident.arn, kind=ident.kind, score=score, tier=_tier(score), admin=admin,
        privesc=sorted(privesc, key=privesc.get, reverse=True),  # type: ignore[arg-type]
        data=sorted(data, key=data.get, reverse=True),  # type: ignore[arg-type]
    )

    if ident.trust_policy:
        raw = str(ident.trust_policy)
        br.ci_reachable = GH_HOST in raw
        if br.ci_reachable:
            findings = [f for f in audit_trust_policy(ident.arn, ident.trust_policy)
                        if f.rule_id in TRUST_NOTES]
            if findings:
                worst = max(findings, key=lambda f: f.severity)
                br.trust_worst = worst.severity
                br.trust_note = TRUST_NOTES[worst.rule_id]
    boost = 0
    if br.ci_reachable:
        boost = 20 if (br.trust_worst or 0) >= Severity.HIGH else 10
    br.priority = min(100, score + boost) if score else 0
    return br


def analyze(identities: list[Identity]) -> list[BlastRadius]:
    results = [score_identity(i) for i in identities]
    return sorted(results, key=lambda r: (-r.priority, r.name))


def to_mermaid(results: list[BlastRadius], top: int = 8) -> str:
    lines = ["flowchart LR", '  gh(["GitHub Actions OIDC"])']
    for i, r in enumerate(results[:top]):
        rid = f"r{i}"
        lines.append(f'  {rid}["{r.name}<br/>score {r.score} ({r.tier.name})"]')
        if r.ci_reachable:
            lines.append(f'  gh -->|"{r.trust_note}"| {rid}')
        if r.admin:
            lines.append(f'  {rid} --> {rid}x["FULL ADMIN"]')
        for j, action in enumerate((r.privesc + r.data)[:6]):
            lines.append(f'  {rid} --> {rid}a{j}["{action}"]')
    return "\n".join(lines)
