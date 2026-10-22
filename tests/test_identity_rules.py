import json
from pathlib import Path

from pipelineguard.rules.identity_rules import audit_trust_policy


def load(name):
    return json.loads(Path(f"samples/trust/{name}").read_text())


def ids(findings):
    return {f.rule_id for f in findings}


def test_missing_sub_is_critical():
    f = audit_trust_policy("r", load("bad_trust.json"))
    assert "PG-OIDC-001" in ids(f)
    assert max(x.severity for x in f).name == "CRITICAL"


def test_org_wildcard_is_high():
    assert "PG-OIDC-002" in ids(audit_trust_policy("r", load("org_wide_trust.json")))


def test_any_ref_is_medium():
    p = load("good_trust.json")
    cond = p["Statement"][0]["Condition"]
    cond["StringLike"] = {"token.actions.githubusercontent.com:sub": "repo:acme/app:*"}
    del cond["StringEquals"]["token.actions.githubusercontent.com:sub"]
    assert "PG-OIDC-003" in ids(audit_trust_policy("r", p))


def test_repo_wildcard_is_critical():
    p = load("good_trust.json")
    p["Statement"][0]["Condition"]["StringEquals"]["token.actions.githubusercontent.com:sub"] = "repo:*"
    assert "PG-OIDC-001" in ids(audit_trust_policy("r", p))


def test_missing_aud_flagged():
    p = load("good_trust.json")
    del p["Statement"][0]["Condition"]["StringEquals"]["token.actions.githubusercontent.com:aud"]
    assert ids(audit_trust_policy("r", p)) == {"PG-OIDC-004"}


def test_good_policy_is_clean():
    assert audit_trust_policy("r", load("good_trust.json")) == []


def test_wildcard_principal_critical():
    p = {"Statement": [{"Effect": "Allow", "Principal": "*", "Action": "sts:AssumeRole"}]}
    assert "PG-TRUST-001" in ids(audit_trust_policy("r", p))
