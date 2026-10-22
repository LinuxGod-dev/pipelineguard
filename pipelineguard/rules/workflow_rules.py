"""Static rules for GitHub Actions workflows.

Each rule maps to a pattern seen in the 2026 CI/CD supply chain campaigns
(Trivy/Checkmarx, Megalodon, Miasma): pull_request_target abuse, mutable action
tags, long-lived cloud keys, over-broad tokens, and script injection.
"""
from __future__ import annotations

import re
from typing import Callable

from ..models import Finding, Severity
from ..workflow_loader import Workflow, load_workflows

SHA_RE = re.compile(r"^[0-9a-f]{40}$")
EXPR_RE = re.compile(r"\$\{\{\s*(?P<expr>[^}]*?)\s*\}\}")
CLOUD_SECRET_RE = re.compile(
    r"secrets\.(AWS_SECRET_ACCESS_KEY|AWS_ACCESS_KEY_ID|AZURE_CREDENTIALS|AZURE_CLIENT_SECRET|"
    r"GCP_SA_KEY|GOOGLE_CREDENTIALS|GCP_CREDENTIALS|GOOGLE_APPLICATION_CREDENTIALS)",
    re.IGNORECASE,
)

UNTRUSTED_REF_PARTS = (
    "github.event.pull_request.head",
    "github.head_ref",
    "github.event.workflow_run.head",
)
UNTRUSTED_CONTEXTS = (
    "github.event.issue.title",
    "github.event.issue.body",
    "github.event.pull_request.title",
    "github.event.pull_request.body",
    "github.event.pull_request.head.ref",
    "github.event.pull_request.head.label",
    "github.event.pull_request.head.repo.default_branch",
    "github.event.comment.body",
    "github.event.review.body",
    "github.event.review_comment.body",
    "github.event.pages",
    "github.event.commits",
    "github.event.head_commit.message",
    "github.event.head_commit.author.email",
    "github.event.head_commit.author.name",
    "github.event.workflow_run.head_branch",
    "github.event.workflow_run.head_commit.message",
    "github.head_ref",
)


def _f(wf: Workflow, rule_id: str, title: str, sev: Severity, desc: str, fix: str,
       line: int | None = None, technique: str | None = None) -> Finding:
    return Finding(rule_id, title, sev, wf.path, desc, fix, line, technique)


def rule_prt_untrusted_checkout(wf: Workflow) -> list[Finding]:
    """PG-GHA-001: pull_request_target + checkout of attacker-controlled code."""
    if "pull_request_target" not in wf.triggers():
        return []
    out: list[Finding] = []
    track = wf.tracker()
    for job, _, step in wf.iter_steps():
        uses = str(step.get("uses", ""))
        if not uses.startswith("actions/checkout"):
            continue
        ref = str((step.get("with") or {}).get("ref", ""))
        line = track.find("actions/checkout")
        if any(part in ref for part in UNTRUSTED_REF_PARTS):
            out.append(_f(
                wf, "PG-GHA-001",
                "pull_request_target checks out untrusted pull request code",
                Severity.CRITICAL,
                f"Job '{job}' runs with a privileged token and secrets, yet checks out code from "
                "the pull request. A malicious PR can execute in that context and steal credentials "
                "(the entry point of the Trivy compromise).",
                "Use the pull_request trigger, or split into an unprivileged build and a privileged "
                "workflow_run that never executes PR code. Never check out the PR head under "
                "pull_request_target.",
                line, "T1195.002",
            ))
    return out


def rule_unpinned_actions(wf: Workflow) -> list[Finding]:
    """PG-GHA-002: actions referenced by mutable tag/branch instead of a commit SHA."""
    out: list[Finding] = []
    track = wf.tracker()
    refs: list[str] = []
    for _, job in wf.jobs().items():
        if isinstance(job.get("uses"), str):
            refs.append(job["uses"])
        for step in job.get("steps") or []:
            if isinstance(step, dict) and isinstance(step.get("uses"), str):
                refs.append(step["uses"])
    for uses in refs:
        if uses.startswith("./"):
            continue
        line = track.find(uses)
        if uses.startswith("docker://"):
            if "@sha256:" not in uses:
                out.append(_f(wf, "PG-GHA-002", f"Docker image not pinned by digest: {uses}",
                              Severity.MEDIUM, "Image tags can be repointed by an attacker.",
                              "Pin to an @sha256 digest.", line, "T1195.002"))
            continue
        if "@" not in uses:
            continue
        name, ref = uses.rsplit("@", 1)
        if SHA_RE.match(ref):
            continue
        first_party = name.split("/")[0].lower() in {"actions", "github"}
        out.append(_f(
            wf, "PG-GHA-002", f"Action not pinned to a commit SHA: {uses}",
            Severity.MEDIUM if first_party else Severity.HIGH,
            "Tags and branches are mutable. In March 2026, attackers hijacked release tags on "
            "popular actions so every pipeline referencing the tag ran credential-stealing code.",
            "Pin to the full 40-character commit SHA and keep the tag in a trailing comment. "
            "Run `python -m pipelineguard remediate pin` to do this automatically.",
            line, "T1195.002",
        ))
    return out


def rule_static_cloud_credentials(wf: Workflow) -> list[Finding]:
    """PG-GHA-003: long-lived cloud keys stored as repository secrets."""
    for i, raw in enumerate(wf.lines, start=1):
        if raw.strip().startswith("#"):
            continue
        m = CLOUD_SECRET_RE.search(raw)
        if m:
            return [_f(
                wf, "PG-GHA-003", f"Long-lived cloud credential in workflow ({m.group(1).upper()})",
                Severity.HIGH,
                "Static keys in CI secrets are exactly what runner-memory and environment scrapers "
                "harvest, and they stay valid until someone rotates them.",
                "Use OIDC federation with a short-lived role: configure-aws-credentials with "
                "role-to-assume and `permissions: id-token: write` on that job only.",
                i, "T1552.001",
            )]
    return []


def rule_permissions(wf: Workflow) -> list[Finding]:
    """PG-GHA-004: over-broad GITHUB_TOKEN permissions."""
    out: list[Finding] = []
    data = wf.data or {}
    top = data.get("permissions")
    if top == "write-all":
        out.append(_f(wf, "PG-GHA-004", "Workflow grants write-all token permissions", Severity.HIGH,
                      "Every job gets a token that can write to the repo, packages and more.",
                      "Set `permissions: contents: read` at the top and grant extra scopes per job.",
                      wf.line_of("write-all"), "T1078.004"))
    elif top is None:
        missing = [n for n, j in wf.jobs().items() if "permissions" not in j]
        if missing:
            out.append(_f(wf, "PG-GHA-004", "No explicit token permissions",
                          Severity.MEDIUM,
                          f"Jobs without a permissions block inherit the repository default: {', '.join(missing)}.",
                          "Add a top-level `permissions: contents: read` block.",
                          wf.line_of("jobs:"), "T1078.004"))
    if isinstance(top, dict) and str(top.get("id-token")) == "write":
        out.append(_f(wf, "PG-GHA-004", "id-token: write granted at workflow level", Severity.LOW,
                      "Every job, including ones that run third-party actions, can mint OIDC tokens "
                      "for your cloud roles.",
                      "Grant id-token: write only on the job that actually deploys.",
                      wf.line_of("id-token"), "T1528"))
    for name, job in wf.jobs().items():
        if job.get("permissions") == "write-all":
            out.append(_f(wf, "PG-GHA-004", f"Job '{name}' grants write-all token permissions",
                          Severity.HIGH, "Job token can write everywhere.",
                          "List only the scopes the job needs.", wf.line_of("write-all"), "T1078.004"))
    return out


def rule_script_injection(wf: Workflow) -> list[Finding]:
    """PG-GHA-005: untrusted event data interpolated into shell or script steps."""
    out: list[Finding] = []
    track = wf.tracker()
    for job, _, step in wf.iter_steps():
        bodies = [str(step.get("run", ""))]
        if isinstance(step.get("with"), dict) and "script" in step["with"]:
            bodies.append(str(step["with"]["script"]))
        for body in bodies:
            for m in EXPR_RE.finditer(body):
                expr = m.group("expr")
                if any(ctx in expr for ctx in UNTRUSTED_CONTEXTS):
                    out.append(_f(
                        wf, "PG-GHA-005", f"Script injection via ${{{{ {expr} }}}}",
                        Severity.HIGH,
                        f"Job '{job}' interpolates attacker-controlled text straight into a script, "
                        "so a crafted PR title, branch name or comment becomes code execution.",
                        "Pass the value through an environment variable and reference it as "
                        '"$VAR" in the script instead of using ${{ }} inside run:.',
                        track.find(m.group(0)), "T1059",
                    ))
    return out


def rule_self_hosted_on_prs(wf: Workflow) -> list[Finding]:
    """PG-GHA-006: self-hosted runners reachable from pull requests."""
    if not ({"pull_request", "pull_request_target"} & wf.triggers()):
        return []
    out: list[Finding] = []
    for name, job in wf.jobs().items():
        runs_on = job.get("runs-on")
        labels = runs_on if isinstance(runs_on, list) else [runs_on]
        if isinstance(runs_on, dict):
            labels = runs_on.get("labels", [])
        if any("self-hosted" in str(lbl) for lbl in labels):
            out.append(_f(
                wf, "PG-GHA-006", f"Self-hosted runner used on pull request trigger (job '{name}')",
                Severity.HIGH,
                "Untrusted PR code runs on persistent infrastructure inside your network, where it "
                "can read cloud metadata and other jobs' leftovers.",
                "Use ephemeral, isolated runners for PR workflows, or restrict to trusted authors.",
                wf.line_of("self-hosted"), "T1610",
            ))
    return out


RULES: list[Callable[[Workflow], list[Finding]]] = [
    rule_prt_untrusted_checkout,
    rule_unpinned_actions,
    rule_static_cloud_credentials,
    rule_permissions,
    rule_script_injection,
    rule_self_hosted_on_prs,
]


def scan_workflow(wf: Workflow) -> list[Finding]:
    if wf.error:
        return [Finding("PG-GHA-000", "Workflow could not be parsed", Severity.LOW, wf.path,
                        wf.error, "Fix the YAML so it can be analyzed.")]
    findings: list[Finding] = []
    for rule in RULES:
        findings.extend(rule(wf))
    return findings


def scan_path(path: str) -> list[Finding]:
    findings: list[Finding] = []
    for wf in load_workflows(path):
        findings.extend(scan_workflow(wf))
    return sorted(findings, key=lambda f: (-f.severity, f.target, f.line or 0))
