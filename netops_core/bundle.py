from __future__ import annotations

import hashlib
import json
import tempfile
import zipfile
from pathlib import Path
from typing import Any

from .models import DiagnosticBundle, load_bundle, utc_now
from .redaction import Redactor
from .report import render_report


def _json_bytes(data: dict[str, Any]) -> bytes:
    return (json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode(
        "utf-8"
    )


def export_bundle(
    source: str | Path,
    destination: str | Path,
    *,
    include_network_identifiers: bool = False,
) -> Path:
    bundle = load_bundle(source)
    redactor = Redactor(
        include_network_identifiers=include_network_identifiers
    )
    redacted_data = redactor.value(bundle.to_dict())
    redacted_data["redactions"] = sorted(
        set(redacted_data.get("redactions", [])) | redactor.actions
    )
    redacted_bundle = DiagnosticBundle.from_dict(redacted_data)
    bundle_bytes = _json_bytes(redacted_bundle.to_dict())
    report_bytes = render_report(redacted_bundle).encode("utf-8")
    manifest = {
        "format": "netops-diagnostic-archive",
        "format_version": "1.0",
        "created_at": utc_now(),
        "source_schema_version": bundle.schema_version,
        "network_identifiers_included": include_network_identifiers,
        "redactions": sorted(redactor.actions),
        "files": {
            "bundle.json": hashlib.sha256(bundle_bytes).hexdigest(),
            "report.md": hashlib.sha256(report_bytes).hexdigest(),
        },
    }
    manifest_bytes = _json_bytes(manifest)
    output = Path(destination).expanduser().resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        prefix=f".{output.name}.", suffix=".tmp", dir=output.parent, delete=False
    ) as handle:
        temporary = Path(handle.name)
    try:
        with zipfile.ZipFile(
            temporary, mode="w", compression=zipfile.ZIP_DEFLATED
        ) as archive:
            archive.writestr("bundle.json", bundle_bytes)
            archive.writestr("report.md", report_bytes)
            archive.writestr("manifest.json", manifest_bytes)
        temporary.replace(output)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise
    return output


def inspect_bundle(path: str | Path) -> tuple[DiagnosticBundle, str]:
    source = Path(path).expanduser().resolve()
    if source.suffix.lower() != ".zip":
        bundle = load_bundle(source)
        return bundle, render_report(bundle)
    with zipfile.ZipFile(source, mode="r") as archive:
        names = set(archive.namelist())
        required = {"bundle.json", "manifest.json"}
        if not required.issubset(names):
            raise ValueError("archive is missing bundle.json or manifest.json")
        for name in names:
            candidate = Path(name)
            if candidate.is_absolute() or ".." in candidate.parts:
                raise ValueError(f"unsafe archive member: {name}")
        bundle_data = json.loads(archive.read("bundle.json"))
        manifest = json.loads(archive.read("manifest.json"))
        for name, expected in (manifest.get("files") or {}).items():
            if name not in names:
                raise ValueError(f"archive is missing checksummed file: {name}")
            actual = hashlib.sha256(archive.read(name)).hexdigest()
            if expected != actual:
                raise ValueError(f"{name} checksum mismatch")
    bundle = DiagnosticBundle.from_dict(bundle_data)
    return bundle, render_report(bundle)
