"""Full chain on moto: lab setup -> audit -> blast radius -> attack -> detect -> remediate."""
import json

import pytest

moto = pytest.importorskip("moto")
from moto import mock_aws  # noqa: E402

from pipelineguard import blast, inventory, remediate  # noqa: E402
from pipelineguard.aws_client import make_client  # noqa: E402
from pipelineguard.detections.engine import DetectionConfig, load_events, run_detections  # noqa: E402
from pipelineguard.rules.identity_rules import audit_identities  # noqa: E402
from pipelineguard.simulate import attack, scenario  # noqa: E402


@pytest.fixture
def lab():
    with mock_aws():
        scenario.setup(*[make_client(s) for s in ("iam", "s3", "secretsmanager", "sts")])
        yield


def test_audit_finds_vulnerable_role_only(lab):
    findings = audit_identities(inventory.collect_identities(make_client("iam")))
    flagged = {f.target.rsplit("/", 1)[-1] for f in findings if f.rule_id.startswith("PG-OIDC")}
    assert flagged == {scenario.VULN_ROLE}


def test_blast_ranks_vulnerable_role_first(lab):
    results = blast.analyze(inventory.collect_identities(make_client("iam")))
    top = results[0]
    assert top.name == scenario.VULN_ROLE and top.ci_reachable and top.trust_note == "ANY GitHub repo"
    assert top.score >= 80
    safe = next(r for r in results if r.name == scenario.SAFE_ROLE)
    assert safe.score < 30 and safe.trust_note == "scoped"
    assert "flowchart LR" in blast.to_mermaid(results)


def test_attack_is_detected(lab, tmp_path):
    out = tmp_path / "events.jsonl"
    attack.run_attack(lambda svc, creds=None: make_client(svc, creds=creds), out)
    cfg = DetectionConfig.load("detection.yml")
    alerts = run_detections(load_events(out), cfg)
    rules = {a.rule_id for a in alerts}
    assert {"PG-DET-001", "PG-DET-002", "PG-DET-003", "PG-DET-004", "PG-DET-005"} <= rules
    # No false positive on the legitimate baseline session.
    assert all("github-actions-legit" not in a.actor for a in alerts)


def test_remediation_closes_the_hole(lab):
    iam = make_client("iam")
    role = iam.get_role(RoleName=scenario.VULN_ROLE)["Role"]
    fixed = remediate.harden_trust_policy(role["AssumeRolePolicyDocument"], "acme/app", ref="refs/heads/main")
    assert "would update" in remediate.apply_trust_policy(iam, scenario.VULN_ROLE, fixed, apply=False)
    remediate.apply_trust_policy(iam, scenario.VULN_ROLE, fixed, apply=True)
    findings = audit_identities(inventory.collect_identities(iam))
    assert not [f for f in findings if f.rule_id.startswith("PG-OIDC")]
    remediate.quarantine_role(iam, scenario.VULN_ROLE, apply=True)
    assert "PipelineGuardQuarantine" in iam.list_role_policies(RoleName=scenario.VULN_ROLE)["PolicyNames"]
