from pipelineguard.detections.engine import DetectionConfig, run_detections


def ev(i, t, name, source, identity, ip="203.0.113.9", **extra):
    e = {"eventID": str(i), "eventTime": f"2026-10-21T10:00:{t:02d}Z", "eventName": name,
         "eventSource": source, "sourceIPAddress": ip, "userIdentity": identity,
         "requestParameters": {}}
    e.update(extra)
    return e


SESSION = {"type": "AssumedRole", "arn": "arn:aws:sts::1:assumed-role/gh-deploy-role/s"}


def test_secret_burst_threshold():
    events = [ev(i, i, "GetSecretValue", "secretsmanager.amazonaws.com", SESSION) for i in range(3)]
    assert any(a.rule_id == "PG-DET-003" for a in run_detections(events, DetectionConfig()))
    assert not any(a.rule_id == "PG-DET-003" for a in run_detections(events[:2], DetectionConfig()))


def test_slow_reads_do_not_trigger_burst():
    events = [ev(i, i * 30, "GetSecretValue", "secretsmanager.amazonaws.com", SESSION) for i in range(2)]
    events.append(ev(9, 59, "GetSecretValue", "secretsmanager.amazonaws.com", SESSION))
    # 0s, 30s, 59s -> all three inside a 60s window
    assert any(a.rule_id == "PG-DET-003" for a in run_detections(events, DetectionConfig()))


def test_allowed_sub_not_alerted():
    e = ev(1, 0, "AssumeRoleWithWebIdentity", "sts.amazonaws.com",
           {"type": "WebIdentityUser", "userName": "repo:acme/app:ref:refs/heads/main",
            "identityProvider": "token.actions.githubusercontent.com"},
           requestParameters={"roleArn": "arn:aws:iam::1:role/gh-deploy-role"})
    assert run_detections([e], DetectionConfig(allowed_subs=["repo:acme/app:*"])) == []


def test_assume_event_names_the_role():
    e = ev(1, 0, "AssumeRoleWithWebIdentity", "sts.amazonaws.com",
           {"type": "WebIdentityUser", "userName": "repo:evil/x:ref:refs/heads/main",
            "identityProvider": "token.actions.githubusercontent.com"},
           requestParameters={"roleArn": "arn:aws:iam::1:role/gh-deploy-role"})
    alert = run_detections([e], DetectionConfig(allowed_subs=["repo:acme/*"]))[0]
    assert "'gh-deploy-role'" in alert.details
