"""Rules for AWS trust policies and IAM identities (OIDC federation focus)."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from ..models import Finding, Severity

GH_HOST = "token.actions.githubusercontent.com"


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _flatten_conditions(condition: dict[str, Any] | None) -> list[tuple[str, str, list[str]]]:
    """Return (operator, key, values) tuples with lowercase operator and key."""
    out = []
    for op, body in (condition or {}).items():
        if not isinstance(body, dict):
            continue
        for key, vals in body.items():
            out.append((op.lower(), key.lower(), [str(v) for v in _as_list(vals)]))
    return out


def _is_github_federated(principal: Any) -> bool:
    if not isinstance(principal, dict):
        return False
    return any(GH_HOST in str(p) for p in _as_list(principal.get("Federated")))


def audit_trust_policy(role: str, policy: dict[str, Any]) -> list[Finding]:
    """Audit one role's AssumeRole policy document."""
    findings: list[Finding] = []
    for stmt in _as_list(policy.get("Statement")):
        if stmt.get("Effect") != "Allow":
            continue
        principal = stmt.get("Principal")
        actions = [str(a).lower() for a in _as_list(stmt.get("Action"))]
        conds = _flatten_conditions(stmt.get("Condition"))

        # Anyone-can-assume: wildcard principal with no condition.
        wildcard = principal == "*" or (isinstance(principal, dict) and "*" in _as_list(principal.get("AWS")))
        if wildcard and not conds:
            findings.append(Finding(
                "PG-TRUST-001", "Role can be assumed by any AWS principal", Severity.CRITICAL, role,
                "The trust policy has a wildcard principal and no conditions.",
                "Name specific principals or add an aws:PrincipalOrgID condition.",
                technique="T1078.004"))

        if not _is_github_federated(principal):
            continue
        if not any(a in ("sts:assumerolewithwebidentity", "sts:*", "*") for a in actions):
            continue

        sub_key = f"{GH_HOST}:sub"
        aud_key = f"{GH_HOST}:aud"
        subs = [(op, vals) for op, key, vals in conds if key == sub_key]
        has_aud = any(key == aud_key for _, key, _ in conds)

        if not subs:
            findings.append(Finding(
                "PG-OIDC-001", "GitHub OIDC role has no `sub` condition", Severity.CRITICAL, role,
                "Any repository on GitHub can request a token and assume this role. A single "
                "hijacked workflow, anywhere, is enough.",
                "Add a StringEquals condition on token.actions.githubusercontent.com:sub, for example "
                "repo:ORG/REPO:ref:refs/heads/main or repo:ORG/REPO:environment:production.",
                technique="T1078.004"))
        for op, vals in subs:
            for v in vals:
                body = v.split(":", 1)[1] if v.startswith("repo:") else v
                if v == "*" or v.startswith("repo:*") or body.startswith("*"):
                    findings.append(Finding(
                        "PG-OIDC-001", f"GitHub OIDC `sub` matches any repository ({v})",
                        Severity.CRITICAL, role,
                        "The wildcard sits before the organization, so any repo can assume the role.",
                        "Pin the full owner/repo and a ref or environment.", technique="T1078.004"))
                elif "*" in v:
                    org_only = v.endswith("/*") or v.count(":") == 1
                    if org_only:
                        findings.append(Finding(
                            "PG-OIDC-002", f"GitHub OIDC `sub` matches every repo in an org ({v})",
                            Severity.HIGH, role,
                            "Any repository in the organization, including a freshly created or "
                            "compromised one, can assume the role.",
                            "Pin the exact repository.", technique="T1078.004"))
                    else:
                        findings.append(Finding(
                            "PG-OIDC-003", f"GitHub OIDC `sub` allows any ref or event ({v})",
                            Severity.MEDIUM, role,
                            "Pull request runs, feature branches and tags can all assume the role.",
                            "Restrict to refs/heads/main or a protected GitHub environment.",
                            technique="T1078.004"))
        if not has_aud:
            findings.append(Finding(
                "PG-OIDC-004", "GitHub OIDC role does not pin the `aud` claim", Severity.MEDIUM, role,
                "Without an audience check, tokens minted for other consumers may be accepted.",
                f"Add StringEquals {aud_key}: sts.amazonaws.com.", technique="T1528"))
    return findings


def audit_access_keys(identities: list[Any], now: datetime | None = None,
                      max_age_days: int = 90) -> list[Finding]:
    """PG-KEY-001: active long-lived IAM user keys past the age limit."""
    now = now or datetime.now(timezone.utc)
    out: list[Finding] = []
    for ident in identities:
        for key in getattr(ident, "access_keys", []):
            if key["status"] != "Active":
                continue
            created = key["created"]
            if created.tzinfo is None:
                created = created.replace(tzinfo=timezone.utc)
            age = (now - created).days
            if age > max_age_days:
                out.append(Finding(
                    "PG-KEY-001", f"Active access key is {age} days old", Severity.MEDIUM, ident.arn,
                    f"Key {key['id']} exceeds the {max_age_days}-day rotation limit. Long-lived keys "
                    "stolen from a runner stay valid until rotated.",
                    "Replace with OIDC federation or an IAM role, then delete the key.",
                    technique="T1552.001"))
    return out


def audit_identities(identities: list[Any], now: datetime | None = None) -> list[Finding]:
    findings: list[Finding] = []
    for ident in identities:
        if ident.kind == "role" and ident.trust_policy:
            findings.extend(audit_trust_policy(ident.arn, ident.trust_policy))
    findings.extend(audit_access_keys(identities, now))
    return sorted(findings, key=lambda f: (-f.severity, f.target))
