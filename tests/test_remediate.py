import json
from pathlib import Path

import pytest

from pipelineguard.remediate import harden_trust_policy, pin_actions, quarantine_policy
from pipelineguard.rules.identity_rules import audit_trust_policy


def test_pin_actions_with_fake_resolver():
    text = Path("samples/workflows/vulnerable.yml").read_text()
    fake = lambda repo, ref: "f" * 40
    new, log = pin_actions(text, fake)
    assert "actions/checkout@" + "f" * 40 + " # v4" in new
    assert "aws-actions/configure-aws-credentials@" + "f" * 40 + " # v4" in new
    assert len([l for l in log if l.startswith("PINNED")]) == 3


def test_pin_skips_failures_and_keeps_line():
    def boom(repo, ref):
        raise RuntimeError("rate limited")
    new, log = pin_actions("      - uses: actions/checkout@v4\n", boom)
    assert new == "      - uses: actions/checkout@v4\n" and log[0].startswith("SKIPPED")


def test_pin_is_idempotent():
    text = "      - uses: actions/checkout@" + "a" * 40 + " # v4\n"
    assert pin_actions(text, lambda r, v: "b" * 40)[0] == text


def test_hardened_policy_passes_audit():
    bad = json.loads(Path("samples/trust/bad_trust.json").read_text())
    fixed = harden_trust_policy(bad, "acme/app", ref="refs/heads/main")
    assert audit_trust_policy("r", fixed) == []
    assert bad != fixed  # original untouched


def test_hardening_requires_ref_or_environment():
    with pytest.raises(ValueError):
        harden_trust_policy({"Statement": []}, "acme/app")


def test_quarantine_policy_uses_token_issue_time():
    stmt = quarantine_policy()["Statement"][0]
    assert stmt["Effect"] == "Deny" and "aws:TokenIssueTime" in stmt["Condition"]["DateLessThan"]
