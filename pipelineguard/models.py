"""Shared data models for findings and alerts."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: str) -> "Severity":
        try:
            return cls[value.strip().upper()]
        except KeyError as exc:
            names = ", ".join(s.name.lower() for s in cls)
            raise ValueError(f"unknown severity '{value}' (use one of: {names})") from exc


@dataclass
class Finding:
    """A static finding from a workflow file or a cloud configuration."""

    rule_id: str
    title: str
    severity: Severity
    target: str
    description: str
    remediation: str
    line: int | None = None
    technique: str | None = None  # MITRE ATT&CK technique ID

    @property
    def location(self) -> str:
        return f"{self.target}:{self.line}" if self.line else self.target

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity.name,
            "target": self.target,
            "line": self.line,
            "description": self.description,
            "remediation": self.remediation,
            "technique": self.technique,
        }


@dataclass
class Alert:
    """A runtime detection raised from CloudTrail-format events."""

    rule_id: str
    title: str
    severity: Severity
    technique: str
    actor: str
    first_seen: str
    details: str
    event_ids: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity.name,
            "technique": self.technique,
            "actor": self.actor,
            "first_seen": self.first_seen,
            "details": self.details,
            "event_ids": self.event_ids,
        }
