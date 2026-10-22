"""Load GitHub Actions workflow files and keep enough context for line numbers."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator

import yaml


class LineTracker:
    """Finds successive occurrences of a string so repeated snippets get distinct lines."""

    def __init__(self, lines: list[str]):
        self._lines = lines
        self._cursor: dict[str, int] = {}

    def find(self, needle: str) -> int | None:
        start = self._cursor.get(needle, 0)
        for i in range(start, len(self._lines)):
            if needle in self._lines[i]:
                self._cursor[needle] = i + 1
                return i + 1
        return None


@dataclass
class Workflow:
    path: str
    text: str
    data: dict[str, Any] | None
    error: str | None = None
    lines: list[str] = field(init=False)

    def __post_init__(self) -> None:
        self.lines = self.text.splitlines()

    def tracker(self) -> LineTracker:
        return LineTracker(self.lines)

    def line_of(self, needle: str) -> int | None:
        for i, line in enumerate(self.lines):
            if needle in line:
                return i + 1
        return None

    def triggers(self) -> set[str]:
        """Return trigger names. Note PyYAML parses the bare key `on` as boolean True."""
        if not self.data:
            return set()
        on = self.data.get("on", self.data.get(True))
        if on is None:
            return set()
        if isinstance(on, str):
            return {on}
        if isinstance(on, list):
            return {str(x) for x in on}
        if isinstance(on, dict):
            return {str(k) for k in on}
        return set()

    def jobs(self) -> dict[str, dict[str, Any]]:
        jobs = (self.data or {}).get("jobs") or {}
        return {str(k): v for k, v in jobs.items() if isinstance(v, dict)}

    def iter_steps(self) -> Iterator[tuple[str, dict[str, Any], dict[str, Any]]]:
        for name, job in self.jobs().items():
            for step in job.get("steps") or []:
                if isinstance(step, dict):
                    yield name, job, step


def load_workflow(path: Path) -> Workflow:
    text = path.read_text(encoding="utf-8", errors="replace")
    try:
        data = yaml.safe_load(text)
        if not isinstance(data, dict):
            return Workflow(str(path), text, None, "top level is not a mapping")
        return Workflow(str(path), text, data)
    except yaml.YAMLError as exc:
        return Workflow(str(path), text, None, f"YAML parse error: {exc}")


def load_workflows(path: str | Path) -> list[Workflow]:
    p = Path(path)
    if p.is_file():
        files = [p]
    elif p.is_dir():
        files = sorted([*p.rglob("*.yml"), *p.rglob("*.yaml")])
    else:
        raise FileNotFoundError(f"{p} does not exist")
    return [load_workflow(f) for f in files]
