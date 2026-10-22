"""Collect IAM roles/users with their trust policies, permission policies and keys."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass
class Identity:
    arn: str
    name: str
    kind: str  # "role" or "user"
    trust_policy: dict[str, Any] | None = None
    policies: list[dict[str, Any]] = field(default_factory=list)
    access_keys: list[dict[str, Any]] = field(default_factory=list)


def _doc(value: Any) -> dict[str, Any]:
    return json.loads(value) if isinstance(value, str) else value


def _managed_docs(iam: Any, attached: list[dict[str, Any]]) -> list[dict[str, Any]]:
    docs = []
    for pol in attached:
        meta = iam.get_policy(PolicyArn=pol["PolicyArn"])["Policy"]
        ver = iam.get_policy_version(PolicyArn=pol["PolicyArn"], VersionId=meta["DefaultVersionId"])
        docs.append(_doc(ver["PolicyVersion"]["Document"]))
    return docs


def _role_policies(iam: Any, name: str) -> list[dict[str, Any]]:
    docs = _managed_docs(iam, iam.list_attached_role_policies(RoleName=name)["AttachedPolicies"])
    for pname in iam.list_role_policies(RoleName=name)["PolicyNames"]:
        docs.append(_doc(iam.get_role_policy(RoleName=name, PolicyName=pname)["PolicyDocument"]))
    return docs


def _user_policies(iam: Any, name: str) -> list[dict[str, Any]]:
    docs = _managed_docs(iam, iam.list_attached_user_policies(UserName=name)["AttachedPolicies"])
    for pname in iam.list_user_policies(UserName=name)["PolicyNames"]:
        docs.append(_doc(iam.get_user_policy(UserName=name, PolicyName=pname)["PolicyDocument"]))
    return docs


def collect_identities(iam: Any) -> list[Identity]:
    out: list[Identity] = []
    for page in iam.get_paginator("list_roles").paginate():
        for role in page["Roles"]:
            if role.get("Path", "/").startswith("/aws-service-role/"):
                continue
            out.append(Identity(
                arn=role["Arn"], name=role["RoleName"], kind="role",
                trust_policy=_doc(role["AssumeRolePolicyDocument"]),
                policies=_role_policies(iam, role["RoleName"]),
            ))
    for page in iam.get_paginator("list_users").paginate():
        for user in page["Users"]:
            keys = []
            for k in iam.list_access_keys(UserName=user["UserName"])["AccessKeyMetadata"]:
                created: datetime = k["CreateDate"]
                keys.append({"id": k["AccessKeyId"], "status": k["Status"], "created": created})
            out.append(Identity(
                arn=user["Arn"], name=user["UserName"], kind="user",
                policies=_user_policies(iam, user["UserName"]), access_keys=keys,
            ))
    return out
