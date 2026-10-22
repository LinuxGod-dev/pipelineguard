"""Build a deliberately vulnerable AWS lab (LocalStack or a throwaway account)."""
from __future__ import annotations

import json
from typing import Any

from botocore.exceptions import ClientError

GH_HOST = "token.actions.githubusercontent.com"
BUCKET = "acme-prod-artifacts"
SECRETS = {
    "prod/db-password": "hunter2-prod",
    "prod/payments-api-key": "sk_live_demo_0001",
    "prod/mpesa-consumer-secret": "demo-consumer-secret",
    "prod/signing-key": "demo-signing-key",
}
VULN_ROLE = "gh-deploy-role"
SAFE_ROLE = "gh-readonly-role"
LEGACY_USER = "ci-legacy"
LEGIT_SUB = "repo:acme/app:ref:refs/heads/main"


def _try(label: str, fn, *args, **kwargs):
    try:
        return fn(*args, **kwargs)
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        print(f"  (skipped {label}: {code})")
        return None


def _trust(provider_arn: str, sub: str | None) -> str:
    cond: dict[str, Any] = {f"{GH_HOST}:aud": "sts.amazonaws.com"}
    body: dict[str, Any] = {"StringEquals": cond}
    if sub:
        cond[f"{GH_HOST}:sub"] = sub
    return json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Federated": provider_arn},
            "Action": "sts:AssumeRoleWithWebIdentity",
            "Condition": body,
        }],
    })


def setup(iam: Any, s3: Any, sm: Any, sts: Any) -> dict[str, str]:
    account = sts.get_caller_identity()["Account"]
    provider = f"arn:aws:iam::{account}:oidc-provider/{GH_HOST}"
    _try("oidc provider", iam.create_open_id_connect_provider,
         Url=f"https://{GH_HOST}", ClientIDList=["sts.amazonaws.com"],
         ThumbprintList=["6938fd4d98bab03faadb97b34396831e3780aea1"])

    # Vulnerable role: no `sub` condition, wide permissions.
    _try("vuln role", iam.create_role, RoleName=VULN_ROLE, AssumeRolePolicyDocument=_trust(provider, None))
    _try("vuln policy", iam.put_role_policy, RoleName=VULN_ROLE, PolicyName="deploy-too-much",
         PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [
             {"Effect": "Allow", "Action": ["s3:*", "secretsmanager:GetSecretValue",
                                            "secretsmanager:ListSecrets", "iam:PassRole",
                                            "iam:CreateAccessKey", "iam:List*"], "Resource": "*"}]}))

    # Well-scoped role: exact repo+branch, one bucket, read only.
    _try("safe role", iam.create_role, RoleName=SAFE_ROLE, AssumeRolePolicyDocument=_trust(provider, LEGIT_SUB))
    _try("safe policy", iam.put_role_policy, RoleName=SAFE_ROLE, PolicyName="read-artifacts",
         PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [
             {"Effect": "Allow", "Action": ["s3:GetObject", "s3:ListBucket"],
              "Resource": [f"arn:aws:s3:::{BUCKET}", f"arn:aws:s3:::{BUCKET}/*"]}]}))

    _try("bucket", s3.create_bucket, Bucket=BUCKET)
    for name, value in SECRETS.items():
        _try(f"secret {name}", sm.create_secret, Name=name, SecretString=value)

    # Legacy static key, the kind that gets scraped from CI environments.
    _try("legacy user", iam.create_user, UserName=LEGACY_USER)
    if not iam.list_access_keys(UserName=LEGACY_USER)["AccessKeyMetadata"]:
        iam.create_access_key(UserName=LEGACY_USER)
    return {"account": account, "provider": provider}
