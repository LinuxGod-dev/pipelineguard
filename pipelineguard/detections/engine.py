"""Detection rules over CloudTrail-format events, mapped to MITRE ATT&CK."""
from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass, field
from datetime import datetime
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Any

import yaml

from ..models import Alert, Severity

IAM_PERSISTENCE = {"CreateAccessKey", "CreateLoginProfile", "UpdateLoginProfile"}
IAM_PRIVESC = {"AttachRolePolicy", "PutRolePolicy", "AttachUserPolicy", "PutUserPolicy",
               "CreatePolicyVersion", "UpdateAssumeRolePolicy", "CreateUser", "CreateRole"}


@dataclass
class DetectionConfig:
    allowed_subs: list[str] = field(default_factory=list)
    allowed_cidrs: list[str] = field(default_factory=list)
    ci_roles: list[str] = field(default_factory=lambda: ["gh-*", "github-*", "*-ci-*", "*pipeline*"])
    secret_read_threshold: int = 3
    discovery_threshold: int = 4
    window_seconds: int = 60

    @classmethod
    def load(cls, path: str | Path | None) -> "DetectionConfig":
        if not path:
            return cls()
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


def load_events(path: str | Path) -> list[dict[str, Any]]:
    events = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        if line.strip():
            events.append(json.loads(line))
    return sorted(events, key=lambda e: e["eventTime"])


def _t(event: dict[str, Any]) -> datetime:
    return datetime.fromisoformat(event["eventTime"].replace("Z", "+00:00"))


def _role_of(event: dict[str, Any]) -> str | None:
    arn = event.get("userIdentity", {}).get("arn", "")
    if ":assumed-role/" in arn:
        return arn.split(":assumed-role/", 1)[1].split("/")[0]
    role_arn = (event.get("requestParameters") or {}).get("roleArn", "")
    if event.get("eventName") == "AssumeRoleWithWebIdentity" and ":role/" in role_arn:
        return role_arn.rsplit("/", 1)[1]
    return None


def _actor(event: dict[str, Any]) -> str:
    ui = event.get("userIdentity", {})
    return ui.get("arn") or ui.get("userName") or ui.get("principalId", "unknown")


def _is_ci(role: str | None, cfg: DetectionConfig) -> bool:
    return bool(role) and any(fnmatchcase(role, p) for p in cfg.ci_roles)  # type: ignore[arg-type]


def _in_cidrs(ip: str, cidrs: list[str]) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in ipaddress.ip_network(c, strict=False) for c in cidrs)


def det_rogue_oidc_assume(events, cfg) -> list[Alert]:
    """PG-DET-001: a GitHub OIDC subject outside the allow-list assumed (or tried to assume) a role."""
    out = []
    for e in events:
        if e["eventName"] != "AssumeRoleWithWebIdentity":
            continue
        ui = e.get("userIdentity", {})
        sub = ui.get("userName", "")
        if "githubusercontent" not in str(ui.get("identityProvider", "")):
            continue
        if any(fnmatchcase(sub, p) for p in cfg.allowed_subs):
            continue
        denied = "errorCode" in e
        out.append(Alert(
            "PG-DET-001",
            "Denied OIDC role assumption from unknown repository" if denied
            else "Role assumed via GitHub OIDC by an unexpected repository",
            Severity.MEDIUM if denied else Severity.CRITICAL, "T1078.004", sub, e["eventTime"],
            f"Subject '{sub}' {'was denied' if denied else 'succeeded'} assuming role "
            f"'{_role_of(e)}' from {e['sourceIPAddress']}. Not in the allowed subject list.",
            [e["eventID"]]))
    return out


def det_ci_role_foreign_ip(events, cfg) -> list[Alert]:
    """PG-DET-002: CI role activity from outside the expected egress ranges."""
    if not cfg.allowed_cidrs:
        return []
    grouped: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for e in events:
        if not _is_ci(_role_of(e), cfg):
            continue
        ip = e.get("sourceIPAddress", "")
        if not _in_cidrs(ip, cfg.allowed_cidrs):
            grouped.setdefault((_actor(e), ip), []).append(e)
    return [Alert(
        "PG-DET-002", "CI role used from an unexpected network", Severity.HIGH, "T1078.004",
        actor, evs[0]["eventTime"],
        f"{len(evs)} call(s) from {ip}, outside the allowed CI egress ranges.",
        [e["eventID"] for e in evs]) for (actor, ip), evs in grouped.items()]


def _burst(events, names: set[str], threshold: int, window: int) -> list[tuple[str, list[dict[str, Any]]]]:
    by_actor: dict[str, list[dict[str, Any]]] = {}
    for e in events:
        if e["eventName"] in names and "errorCode" not in e:
            by_actor.setdefault(_actor(e), []).append(e)
    hits = []
    for actor, evs in by_actor.items():
        for i in range(len(evs)):
            span = [x for x in evs[i:] if (_t(x) - _t(evs[i])).total_seconds() <= window]
            if len(span) >= threshold:
                hits.append((actor, span))
                break
    return hits


def det_secret_read_burst(events, cfg) -> list[Alert]:
    """PG-DET-003: many secrets read by one identity in a short window."""
    return [Alert(
        "PG-DET-003", "Burst of Secrets Manager reads", Severity.HIGH, "T1555.006", actor,
        span[0]["eventTime"],
        f"{len(span)} GetSecretValue calls within {cfg.window_seconds}s.",
        [e["eventID"] for e in span])
        for actor, span in _burst(events, {"GetSecretValue"}, cfg.secret_read_threshold, cfg.window_seconds)]


def det_iam_mutation_by_ci(events, cfg) -> list[Alert]:
    """PG-DET-004: a CI role creates credentials or changes IAM (persistence/privilege escalation)."""
    out = []
    for e in events:
        if e["eventSource"] != "iam.amazonaws.com" or not _is_ci(_role_of(e), cfg):
            continue
        name = e["eventName"]
        if name in IAM_PERSISTENCE:
            out.append(Alert("PG-DET-004", f"CI role created credentials ({name})", Severity.CRITICAL,
                             "T1098.001", _actor(e), e["eventTime"],
                             f"{name} issued by a CI session, a classic persistence step.", [e["eventID"]]))
        elif name in IAM_PRIVESC:
            out.append(Alert("PG-DET-004", f"CI role modified IAM ({name})", Severity.CRITICAL,
                             "T1098", _actor(e), e["eventTime"],
                             f"{name} issued by a CI session.", [e["eventID"]]))
    return out


def det_discovery_burst(events, cfg) -> list[Alert]:
    """PG-DET-005: enumeration of the account right after role assumption."""
    names = {e["eventName"] for e in events if e["eventName"].startswith(("List", "Describe"))
             and e["eventSource"] in {"iam.amazonaws.com", "s3.amazonaws.com", "secretsmanager.amazonaws.com"}}
    return [Alert(
        "PG-DET-005", "Account enumeration burst", Severity.MEDIUM, "T1580", actor, span[0]["eventTime"],
        f"{len(span)} List/Describe calls within {cfg.window_seconds}s.", [e["eventID"] for e in span])
        for actor, span in _burst(events, names, cfg.discovery_threshold, cfg.window_seconds)]


DETECTIONS = [det_rogue_oidc_assume, det_ci_role_foreign_ip, det_secret_read_burst,
              det_iam_mutation_by_ci, det_discovery_burst]


def run_detections(events: list[dict[str, Any]], cfg: DetectionConfig | None = None) -> list[Alert]:
    cfg = cfg or DetectionConfig()
    alerts: list[Alert] = []
    for det in DETECTIONS:
        alerts.extend(det(events, cfg))
    return sorted(alerts, key=lambda a: (-a.severity, a.first_seen))
