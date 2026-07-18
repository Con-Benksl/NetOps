from __future__ import annotations

import json
import os
import tempfile
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import BUNDLE_SCHEMA_VERSION


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


@dataclass
class Observation:
    vantage_point: str
    segment: str
    probe: str
    status: str
    target: str | None = None
    protocol: str | None = None
    address_family: str | None = None
    metrics: dict[str, Any] = field(default_factory=dict)
    evidence: dict[str, Any] = field(default_factory=dict)
    confidence: str = "medium"
    limitations: list[str] = field(default_factory=list)
    observed_at: str = field(default_factory=utc_now)
    observation_id: str = field(default_factory=lambda: str(uuid.uuid4()))


@dataclass
class DiagnosticBundle:
    mode: str
    vantage_points: list[str]
    environment: dict[str, Any] = field(default_factory=dict)
    observations: list[Observation] = field(default_factory=list)
    path_segments: list[dict[str, Any]] = field(default_factory=list)
    findings: list[dict[str, Any]] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    redactions: list[str] = field(default_factory=list)
    targets: list[dict[str, Any]] = field(default_factory=list)
    started_at: str = field(default_factory=utc_now)
    completed_at: str | None = None
    run_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    schema_version: str = BUNDLE_SCHEMA_VERSION

    def finish(self) -> "DiagnosticBundle":
        self.completed_at = utc_now()
        return self

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "DiagnosticBundle":
        observations = [Observation(**item) for item in data.get("observations", [])]
        accepted = {
            "mode",
            "vantage_points",
            "environment",
            "path_segments",
            "findings",
            "limitations",
            "redactions",
            "targets",
            "started_at",
            "completed_at",
            "run_id",
            "schema_version",
        }
        kwargs = {key: value for key, value in data.items() if key in accepted}
        kwargs["observations"] = observations
        return cls(**kwargs)


def load_bundle(path: str | Path) -> DiagnosticBundle:
    with Path(path).open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    if data.get("schema_version") != BUNDLE_SCHEMA_VERSION:
        raise ValueError(
            f"unsupported bundle schema: {data.get('schema_version')!r}; "
            f"expected {BUNDLE_SCHEMA_VERSION!r}"
        )
    return DiagnosticBundle.from_dict(data)


def write_json_atomic(path: str | Path, data: dict[str, Any]) -> Path:
    destination = Path(path).expanduser().resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(
        prefix=f".{destination.name}.", suffix=".tmp", dir=destination.parent
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(data, handle, ensure_ascii=False, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, destination)
    except Exception:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise
    return destination


def write_bundle(path: str | Path, bundle: DiagnosticBundle) -> Path:
    if bundle.completed_at is None:
        bundle.finish()
    return write_json_atomic(path, bundle.to_dict())
