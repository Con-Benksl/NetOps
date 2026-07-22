from __future__ import annotations

import json
import math
import os
import tempfile
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import BUNDLE_SCHEMA_VERSION
from .redaction import Redactor
from .util import load_json_limited


_BUNDLE_REQUIRED = {
    "schema_version",
    "run_id",
    "mode",
    "started_at",
    "vantage_points",
    "environment",
    "observations",
    "path_segments",
    "findings",
    "limitations",
    "redactions",
    "targets",
}
_BUNDLE_ALLOWED = _BUNDLE_REQUIRED | {"completed_at"}
_OBSERVATION_REQUIRED = {
    "observation_id",
    "observed_at",
    "vantage_point",
    "segment",
    "probe",
    "status",
    "metrics",
    "evidence",
    "confidence",
    "limitations",
}
_OBSERVATION_ALLOWED = _OBSERVATION_REQUIRED | {
    "target",
    "protocol",
    "address_family",
}
_PATH_SEGMENT_KEYS = {
    "name",
    "status",
    "evidence",
    "limitations",
    "vantage_points",
    "observed_at",
    "confidence",
}
_PATH_STATUSES = {"observed", "partially-observed", "failed", "unknown", "ok"}
_CONFIDENCE_RANK = {"low": 0, "medium": 1, "high": 2}
MAX_BUNDLE_NESTING_DEPTH = 64
MAX_BUNDLE_COLLECTION_ITEMS = 10_000
MAX_BUNDLE_JSON_NODES = 250_000
MAX_BUNDLE_STRING_CHARS = 1_048_576


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _contract_error(path: str, message: str) -> ValueError:
    return ValueError(f"invalid diagnostic bundle at {path}: {message}")


def _require_object(value: Any, path: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise _contract_error(path, "must be an object")
    if not all(isinstance(key, str) for key in value):
        raise _contract_error(path, "object keys must be strings")
    return value


def _require_string(value: Any, path: str, *, nonempty: bool = False) -> str:
    if not isinstance(value, str):
        raise _contract_error(path, "must be a string")
    if nonempty and not value:
        raise _contract_error(path, "must not be empty")
    return value


def _require_string_or_null(value: Any, path: str) -> None:
    if value is not None and not isinstance(value, str):
        raise _contract_error(path, "must be a string or null")


def _require_string_array(value: Any, path: str) -> list[str]:
    if not isinstance(value, list):
        raise _contract_error(path, "must be an array")
    for index, item in enumerate(value):
        _require_string(item, f"{path}[{index}]")
    return value


def _require_object_array(value: Any, path: str) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        raise _contract_error(path, "must be an array")
    for index, item in enumerate(value):
        _require_object(item, f"{path}[{index}]")
        _validate_json_value(item, f"{path}[{index}]")
    return value


def _validate_json_value(value: Any, path: str) -> None:
    stack: list[tuple[Any, str, int]] = [(value, path, 0)]
    nodes = 0
    while stack:
        item, item_path, depth = stack.pop()
        nodes += 1
        if nodes > MAX_BUNDLE_JSON_NODES:
            raise _contract_error(path, "exceeds the JSON node budget")
        if depth > MAX_BUNDLE_NESTING_DEPTH:
            raise _contract_error(item_path, "exceeds the nesting depth limit")
        if item is None or isinstance(item, bool):
            continue
        if isinstance(item, str):
            if len(item) > MAX_BUNDLE_STRING_CHARS:
                raise _contract_error(item_path, "string is too large")
            continue
        if isinstance(item, int):
            if item.bit_length() > 512:
                raise _contract_error(item_path, "integer exceeds the numeric limit")
            continue
        if isinstance(item, float):
            if not math.isfinite(item):
                raise _contract_error(item_path, "must not contain NaN or infinity")
            continue
        if isinstance(item, list):
            if len(item) > MAX_BUNDLE_COLLECTION_ITEMS:
                raise _contract_error(item_path, "array has too many items")
            stack.extend(
                (child, f"{item_path}[{index}]", depth + 1)
                for index, child in reversed(list(enumerate(item)))
            )
            continue
        if isinstance(item, dict):
            if len(item) > MAX_BUNDLE_COLLECTION_ITEMS:
                raise _contract_error(item_path, "object has too many properties")
            if not all(isinstance(key, str) for key in item):
                raise _contract_error(item_path, "object keys must be strings")
            stack.extend(
                (child, f"{item_path}.{key}", depth + 1)
                for key, child in reversed(list(item.items()))
            )
            continue
        raise _contract_error(
            item_path, f"contains non-JSON value {type(item).__name__}"
        )


def _require_uuid(value: Any, path: str) -> None:
    text = _require_string(value, path)
    try:
        parsed = uuid.UUID(text)
    except (ValueError, AttributeError) as exc:
        raise _contract_error(path, "must be a UUID") from exc
    if str(parsed) != text.lower():
        raise _contract_error(path, "must use canonical UUID form")


def _require_timestamp(value: Any, path: str, *, nullable: bool = False) -> None:
    if value is None and nullable:
        return
    text = _require_string(value, path)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise _contract_error(path, "must be an ISO 8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise _contract_error(path, "must include a timezone")


def _validate_keys(
    value: dict[str, Any],
    path: str,
    *,
    required: set[str],
    allowed: set[str],
) -> None:
    missing = sorted(required - value.keys())
    if missing:
        raise _contract_error(path, f"missing required properties: {', '.join(missing)}")
    extras = sorted(value.keys() - allowed)
    if extras:
        raise _contract_error(path, f"unexpected properties: {', '.join(extras)}")


def validate_bundle_data(data: Any) -> dict[str, Any]:
    """Validate the packaged diagnostic contract without optional dependencies.

    This is an in-package equivalent of ``schemas/diagnostic-bundle.schema.json``.
    It intentionally does not locate that repository file at runtime, so an
    installed wheel behaves the same from any working directory.
    """

    root = _require_object(data, "$")
    _validate_json_value(root, "$")
    _validate_keys(root, "$", required=_BUNDLE_REQUIRED, allowed=_BUNDLE_ALLOWED)
    if root["schema_version"] != BUNDLE_SCHEMA_VERSION:
        raise _contract_error(
            "$.schema_version",
            f"must equal {BUNDLE_SCHEMA_VERSION!r}",
        )
    _require_uuid(root["run_id"], "$.run_id")
    _require_string(root["mode"], "$.mode", nonempty=True)
    _require_timestamp(root["started_at"], "$.started_at")
    if "completed_at" in root:
        _require_timestamp(root["completed_at"], "$.completed_at", nullable=True)
    _require_string_array(root["vantage_points"], "$.vantage_points")
    environment = _require_object(root["environment"], "$.environment")
    _validate_json_value(environment, "$.environment")
    _require_object_array(root["targets"], "$.targets")
    path_segments = _require_object_array(root["path_segments"], "$.path_segments")
    findings = root["findings"]
    if not isinstance(findings, list):
        raise _contract_error("$.findings", "must be an array")
    finding_references: list[tuple[str, list[str]]] = []
    for index, raw_finding in enumerate(findings):
        path = f"$.findings[{index}]"
        finding = _require_object(raw_finding, path)
        _validate_keys(
            finding,
            path,
            required={"severity", "segment", "title", "evidence", "confidence"},
            allowed={"severity", "segment", "title", "evidence", "confidence"},
        )
        if finding["severity"] not in {"info", "warning", "error", "critical"}:
            raise _contract_error(
                f"{path}.severity",
                "must be one of info, warning, error, critical",
            )
        if finding["confidence"] not in {"high", "medium", "low"}:
            raise _contract_error(
                f"{path}.confidence", "must be one of high, medium, low"
            )
        _require_string(finding["segment"], f"{path}.segment", nonempty=True)
        _require_string(finding["title"], f"{path}.title", nonempty=True)
        references = _require_string_array(finding["evidence"], f"{path}.evidence")
        finding_references.append((f"{path}.evidence", references))
    _require_string_array(root["limitations"], "$.limitations")
    _require_string_array(root["redactions"], "$.redactions")

    observations = root["observations"]
    if not isinstance(observations, list):
        raise _contract_error("$.observations", "must be an array")
    observation_ids: set[str] = set()
    for index, raw_observation in enumerate(observations):
        path = f"$.observations[{index}]"
        observation = _require_object(raw_observation, path)
        _validate_keys(
            observation,
            path,
            required=_OBSERVATION_REQUIRED,
            allowed=_OBSERVATION_ALLOWED,
        )
        _require_uuid(observation["observation_id"], f"{path}.observation_id")
        if observation["observation_id"] in observation_ids:
            raise _contract_error(
                f"{path}.observation_id",
                "must be unique within the bundle",
            )
        observation_ids.add(observation["observation_id"])
        _require_timestamp(observation["observed_at"], f"{path}.observed_at")
        for key in ("vantage_point", "segment", "probe"):
            _require_string(observation[key], f"{path}.{key}")
        if observation["status"] not in {"ok", "failed", "unknown"}:
            raise _contract_error(
                f"{path}.status", "must be one of ok, failed, unknown"
            )
        if observation["confidence"] not in {"high", "medium", "low"}:
            raise _contract_error(
                f"{path}.confidence", "must be one of high, medium, low"
            )
        for key in ("target", "protocol", "address_family"):
            if key in observation:
                _require_string_or_null(observation[key], f"{path}.{key}")
        metrics = _require_object(observation["metrics"], f"{path}.metrics")
        evidence = _require_object(observation["evidence"], f"{path}.evidence")
        _validate_json_value(metrics, f"{path}.metrics")
        _validate_json_value(evidence, f"{path}.evidence")
        _require_string_array(observation["limitations"], f"{path}.limitations")

    reference_groups = list(finding_references)
    segment_references: list[tuple[str, dict[str, Any], list[str]]] = []
    for index, segment in enumerate(path_segments):
        path = f"$.path_segments[{index}]"
        _validate_keys(
            segment,
            path,
            required=_PATH_SEGMENT_KEYS,
            allowed=_PATH_SEGMENT_KEYS,
        )
        _require_string(segment["name"], f"{path}.name", nonempty=True)
        if segment["status"] not in _PATH_STATUSES:
            raise _contract_error(
                f"{path}.status",
                "must be one of observed, partially-observed, failed, unknown, ok",
            )
        references = _require_string_array(segment["evidence"], f"{path}.evidence")
        limitations = _require_string_array(
            segment["limitations"], f"{path}.limitations"
        )
        vantage_points = _require_string_array(
            segment["vantage_points"], f"{path}.vantage_points"
        )
        if not vantage_points or any(not value for value in vantage_points):
            raise _contract_error(
                f"{path}.vantage_points", "must contain at least one non-empty value"
            )
        _require_timestamp(segment["observed_at"], f"{path}.observed_at")
        if segment["confidence"] not in _CONFIDENCE_RANK:
            raise _contract_error(
                f"{path}.confidence", "must be one of high, medium, low"
            )
        if not references and not limitations:
            raise _contract_error(
                path, "a segment without evidence must state at least one limitation"
            )
        reference_groups.append((f"{path}.evidence", references))
        segment_references.append((path, segment, references))
    for path, references in reference_groups:
        for index, reference in enumerate(references):
            _require_uuid(reference, f"{path}[{index}]")
            if reference not in observation_ids:
                raise _contract_error(
                    f"{path}[{index}]",
                    "must reference an observation_id in this bundle",
                )
    observations_by_id = {
        item["observation_id"]: item for item in observations
    }
    for path, segment, references in segment_references:
        if not references:
            if segment["confidence"] != "low":
                raise _contract_error(
                    f"{path}.confidence",
                    "must be low when the segment has no observation evidence",
                )
            continue
        referenced = [observations_by_id[reference] for reference in references]
        expected_vantage_points = sorted(
            {item["vantage_point"] for item in referenced}
        )
        if sorted(segment["vantage_points"]) != expected_vantage_points:
            raise _contract_error(
                f"{path}.vantage_points",
                "must match the referenced observations",
            )
        expected_observed_at = max(
            referenced,
            key=lambda item: datetime.fromisoformat(
                item["observed_at"].replace("Z", "+00:00")
            ),
        )["observed_at"]
        if segment["observed_at"] != expected_observed_at:
            raise _contract_error(
                f"{path}.observed_at",
                "must equal the latest referenced observation timestamp",
            )
        expected_confidence = min(
            (item["confidence"] for item in referenced),
            key=_CONFIDENCE_RANK.__getitem__,
        )
        if segment["confidence"] != expected_confidence:
            raise _contract_error(
                f"{path}.confidence",
                "must equal the lowest referenced observation confidence",
            )
    return root


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

    def enrich_path_segments(self) -> "DiagnosticBundle":
        observations = {item.observation_id: item for item in self.observations}
        fallback_time = self.completed_at or self.started_at
        fallback_vantage_points = sorted(set(self.vantage_points)) or ["unknown"]
        for segment in self.path_segments:
            references = segment.setdefault("evidence", [])
            limitations = segment.setdefault("limitations", [])
            referenced = [
                observations[reference]
                for reference in references
                if isinstance(reference, str) and reference in observations
            ]
            if referenced:
                segment["vantage_points"] = sorted(
                    {item.vantage_point for item in referenced}
                )
                latest = max(
                    referenced,
                    key=lambda item: datetime.fromisoformat(
                        item.observed_at.replace("Z", "+00:00")
                    ),
                )
                segment["observed_at"] = latest.observed_at
                segment["confidence"] = min(
                    (item.confidence for item in referenced),
                    key=_CONFIDENCE_RANK.__getitem__,
                )
            else:
                segment["vantage_points"] = fallback_vantage_points
                segment["observed_at"] = fallback_time
                segment["confidence"] = "low"
                if not limitations:
                    limitations.append("当前没有可直接引用的观察证据")
        return self

    def finish(self) -> "DiagnosticBundle":
        self.completed_at = utc_now()
        self.enrich_path_segments()
        return self

    def to_dict(self) -> dict[str, Any]:
        try:
            return asdict(self)
        except RecursionError as exc:
            # Dataclass callers may supply open evidence/environment mappings.
            # Convert a cyclic or pathologically recursive object into a
            # bounded contract failure instead of leaking an interpreter-level
            # recursion crash from a public serialization method.
            raise ValueError(
                "invalid diagnostic bundle: cyclic or excessively nested data"
            ) from exc

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "DiagnosticBundle":
        validate_bundle_data(data)
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
    data = load_json_limited(path, max_bytes=32 * 1_048_576)
    validate_bundle_data(data)
    return DiagnosticBundle.from_dict(data)


def write_json_atomic(path: str | Path, data: dict[str, Any]) -> Path:
    # Do not resolve the final component.  Callers may have reserved this exact
    # directory entry with O_EXCL; following a symlink swapped in afterward
    # could otherwise overwrite the symlink target instead of replacing the
    # entry atomically.
    destination = Path(os.path.abspath(Path(path).expanduser()))
    destination.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(
        prefix=f".{destination.name}.", suffix=".tmp", dir=destination.parent
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(
                data,
                handle,
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
                allow_nan=False,
            )
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
    else:
        bundle.enrich_path_segments()
    # Every persisted bundle receives the credential/header safety pass. Unlike
    # an exported support archive, the local machine-readable bundle retains its
    # network identifiers so diagnostics remain comparable and actionable.
    redactor = Redactor(
        include_network_identifiers=True,
        redact_hostnames=False,
    )
    data = redactor.value(bundle.to_dict())
    data["redactions"] = sorted(
        set(data.get("redactions", [])) | redactor.actions
    )
    validate_bundle_data(data)
    sanitized = DiagnosticBundle.from_dict(data)
    # ``write_bundle`` already finalizes the caller's object. Keep that object in
    # sync with the persisted representation so a report rendered immediately
    # afterward cannot reintroduce a credential removed from the JSON file.
    bundle.__dict__.update(sanitized.__dict__)
    return write_json_atomic(path, sanitized.to_dict())
