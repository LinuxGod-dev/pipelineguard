"""Remediation helpers. Everything that touches AWS is dry-run unless apply=True."""
from __future__ import annotations

import copy
import json
import os
import re
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from typing import Any, Callable

from .rules.identity_rules import GH_HOST, _is_github_federated

SHA_RE = re.compile(r"^[0-9a-f]{40}$")
USES_RE = re.compile(r"^(?P<prefix>\s*(?:-\s*)?uses:\s*)(?P<ref>[^\s#]+)(?P<rest>.*)$")
Resolver = Callable[[str, str], str]


def github_resolver(repo: str, ref: str) -> str:
    """Resolve a tag or branch to a commit SHA using the GitHub API (set GITHUB_TOKEN to avoid rate limits)."""
    url = f"https://api.github.com/repos/{repo}/commits/{urllib.parse.quote(ref, safe='')}"
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "pipelineguard"}
    if os.environ.get("GITHUB_TOKEN"):
        headers["Authorization"] = f"Bearer {os.environ['GITHUB_TOKEN']}"
    with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=15) as resp:
        return json.load(resp)["sha"]


def pin_actions(text: str, resolver: Resolver = github_resolver) -> tuple[str, list[str]]:
    """Rewrite `uses: owner/repo@tag` to `uses: owner/repo@<sha> # tag`. Returns (new_text, change log)."""
    log: list[str] = []
    out_lines = []
    for line in text.split("\n"):
        m = USES_RE.match(line)
        if not m:
            out_lines.append(line)
            continue
        ref = m.group("ref")
        if ref.startswith(("./", "docker://")) or "@" not in ref:
            out_lines.append(line)
            continue
        name, version = ref.rsplit("@", 1)
        parts = name.split("/")
        if SHA_RE.match(version) or len(parts) < 2:
            out_lines.append(line)
            continue
        repo = "/".join(parts[:2])
        try:
            sha = resolver(repo, version)
        except Exception as exc:  # network, rate limit, unknown ref
            log.append(f"SKIPPED {ref}: {exc}")
            out_lines.append(line)
            continue
        rest = m.group("rest").strip()
        comment = f" # {version}" + (f" {rest}" if rest else "")
        out_lines.append(f"{m.group('prefix')}{name}@{sha}{comment}")
        log.append(f"PINNED  {ref} -> {sha}")
    return "\n".join(out_lines), log


def harden_trust_policy(policy: dict[str, Any], repo: str, ref: str | None = None,
                        environment: str | None = None) -> dict[str, Any]:
    """Return a copy of the trust policy with GitHub OIDC statements pinned to one repo + ref/environment."""
    if not ref and not environment:
        raise ValueError("provide a ref (e.g. refs/heads/main) or an environment; repo-wide trust is too broad")
    sub = f"repo:{repo}:environment:{environment}" if environment else f"repo:{repo}:ref:{ref}"
    new = copy.deepcopy(policy)
    stmts = new.get("Statement", [])
    for stmt in [stmts] if isinstance(stmts, dict) else stmts:
        if stmt.get("Effect") == "Allow" and _is_github_federated(stmt.get("Principal")):
            stmt["Condition"] = {"StringEquals": {f"{GH_HOST}:aud": "sts.amazonaws.com", f"{GH_HOST}:sub": sub}}
    return new


def apply_trust_policy(iam: Any, role: str, policy: dict[str, Any], apply: bool = False) -> str:
    if not apply:
        return f"[dry-run] would update trust policy of {role}"
    iam.update_assume_role_policy(RoleName=role, PolicyDocument=json.dumps(policy))
    return f"updated trust policy of {role}"


def quarantine_policy(now: datetime | None = None) -> dict[str, Any]:
    """Deny-all that only affects sessions issued before `now`, which revokes stolen sessions
    while letting a fresh, legitimate assumption work after the trust policy is fixed."""
    now = now or datetime.now(timezone.utc)
    return {"Version": "2012-10-17", "Statement": [{
        "Effect": "Deny", "Action": "*", "Resource": "*",
        "Condition": {"DateLessThan": {"aws:TokenIssueTime": now.strftime("%Y-%m-%dT%H:%M:%SZ")}}}]}


def quarantine_role(iam: Any, role: str, apply: bool = False) -> str:
    doc = quarantine_policy()
    if not apply:
        return f"[dry-run] would attach PipelineGuardQuarantine to {role}:\n{json.dumps(doc, indent=2)}"
    iam.put_role_policy(RoleName=role, PolicyName="PipelineGuardQuarantine", PolicyDocument=json.dumps(doc))
    return f"quarantined {role}: all sessions issued before now are denied"


def deactivate_access_key(iam: Any, user: str, key_id: str, apply: bool = False) -> str:
    if not apply:
        return f"[dry-run] would deactivate key {key_id} for {user}"
    iam.update_access_key(UserName=user, AccessKeyId=key_id, Status="Inactive")
    return f"deactivated key {key_id} for {user}"
