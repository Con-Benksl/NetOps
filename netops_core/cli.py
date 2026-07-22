from __future__ import annotations

import argparse
import contextlib
import io
import json
import os
import re
import shutil
import stat
import sys
import tempfile
import unicodedata
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import __version__
from .bundle import export_bundle, inspect_bundle
from .change import (
    CHANGE_EXECUTION_UNAVAILABLE,
    create_plan,
    resolve_apply_receipt_path,
    resolve_rollback_receipt_path,
)
from .control_channel import (
    CHANGE_SURFACES,
    CONTINUITY_STRATEGIES,
    DEPENDENCIES,
    assess_control_channel,
    normalize_control_channel,
    normalize_rollback_timer,
)
from .fleet import get_host, load_fleet
from .external_tools import tool_catalog, tool_ids, tool_ids_for_mode, tool_status
from .models import DiagnosticBundle, load_bundle, write_bundle
from .monitor import (
    build_install_plan,
    install_monitor,
    monitor_status,
    remove_monitor,
    run_sample,
)
from .report import render_report
from .redaction import Redactor
from .scanner import (
    compare_bundles,
    scan_client,
    scan_node,
    scan_server_local,
    scan_server_remote,
)
from .util import load_json_limited, platform_id


class _SingleUseAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        if getattr(namespace, self.dest, None) is not None:
            parser.error(f"{option_string} may be supplied only once")
        setattr(namespace, self.dest, values)


def _stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _default_output(mode: str) -> Path:
    return Path.cwd() / "diagnostics" / f"{_stamp()}-{mode}.json"


def _absolute_local_path(path: str | Path) -> Path:
    return Path(os.path.abspath(Path(path).expanduser()))


def _reserve_new_output(path: str | Path, *, label: str) -> tuple[Path, tuple[int, int]]:
    """Atomically claim a new output name without following its final component."""

    destination = _absolute_local_path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    try:
        descriptor = os.open(
            destination,
            os.O_CREAT | os.O_EXCL | os.O_WRONLY,
            0o600,
        )
    except FileExistsError as exc:
        raise FileExistsError(
            f"refusing to overwrite existing {label}: {destination}"
        ) from exc
    try:
        info = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    return destination, (info.st_dev, info.st_ino)


def _remove_empty_reservation(path: Path, identity: tuple[int, int]) -> None:
    try:
        info = path.lstat()
        if (
            not path.is_symlink()
            and (info.st_dev, info.st_ino) == identity
            and info.st_size == 0
        ):
            path.unlink()
    except OSError:
        pass


def _path_identity(path: Path) -> tuple[int, int]:
    info = path.lstat()
    if path.is_symlink() or not stat.S_ISREG(info.st_mode):
        raise FileExistsError(f"reserved output path was replaced: {path}")
    return info.st_dev, info.st_ino


def _assert_reservation(path: Path, identity: tuple[int, int]) -> None:
    try:
        current = _path_identity(path)
    except FileExistsError:
        raise
    except OSError as exc:
        raise FileExistsError(f"reserved output path is no longer available: {path}") from exc
    if current != identity:
        raise FileExistsError(f"reserved output path was replaced: {path}")


def _remove_owned_output(path: Path, identity: tuple[int, int]) -> None:
    try:
        if _path_identity(path) == identity:
            path.unlink()
    except OSError:
        pass


def _publish_reserved_output(
    staged: Path,
    destination: Path,
    reservation: tuple[int, int],
) -> tuple[int, int]:
    staged_identity = _path_identity(staged)
    _assert_reservation(destination, reservation)
    os.replace(staged, destination)
    return staged_identity


def _scan_output_candidates(mode: str, output: str | None) -> tuple[Path, Path]:
    destination = Path(output).expanduser() if output else _default_output(mode)
    candidate_json = _absolute_local_path(destination)
    candidate_report = candidate_json.with_suffix(".md")
    if candidate_report == candidate_json or candidate_json.suffix.casefold() == ".md":
        raise ValueError(
            "--output is the diagnostic JSON path and must not end in .md"
        )
    return candidate_json, candidate_report


def _reserve_scan_outputs(
    mode: str, output: str | None
) -> tuple[tuple[Path, tuple[int, int]], tuple[Path, tuple[int, int]]]:
    candidate_json, candidate_report = _scan_output_candidates(mode, output)
    json_path, json_reservation = _reserve_new_output(
        candidate_json, label="diagnostic bundle"
    )
    try:
        report_path, report_reservation = _reserve_new_output(
            candidate_report, label="derived Markdown report"
        )
    except BaseException:
        _remove_empty_reservation(json_path, json_reservation)
        raise
    return (json_path, json_reservation), (report_path, report_reservation)


def _release_scan_reservations(
    reservations: tuple[
        tuple[Path, tuple[int, int]], tuple[Path, tuple[int, int]]
    ]
) -> None:
    for path, identity in reservations:
        _remove_empty_reservation(path, identity)


def _write_scan(
    bundle: DiagnosticBundle,
    output: str | None,
    *,
    reservations: tuple[
        tuple[Path, tuple[int, int]], tuple[Path, tuple[int, int]]
    ]
    | None = None,
) -> dict[str, str]:
    reservations = reservations or _reserve_scan_outputs(bundle.mode, output)
    (json_path, json_reservation), (report_path, report_reservation) = reservations
    published: list[tuple[Path, tuple[int, int]]] = []
    try:
        with tempfile.TemporaryDirectory(
            prefix=".netops-scan-",
            dir=json_path.parent,
        ) as staging_directory:
            staging_root = Path(staging_directory)
            staged_json = staging_root / json_path.name
            staged_report = staging_root / report_path.name
            write_bundle(staged_json, bundle)
            persisted_bundle = load_bundle(staged_json)
            _write_text_atomic(staged_report, render_report(persisted_bundle))

            # Validate the pair before publishing either member. Each replace
            # targets the raw absolute directory entry, never a resolved
            # symlink target.
            _assert_reservation(json_path, json_reservation)
            _assert_reservation(report_path, report_reservation)
            published.append(
                (
                    json_path,
                    _publish_reserved_output(
                        staged_json,
                        json_path,
                        json_reservation,
                    ),
                )
            )
            published.append(
                (
                    report_path,
                    _publish_reserved_output(
                        staged_report,
                        report_path,
                        report_reservation,
                    ),
                )
            )
    except BaseException:
        for path, identity in published:
            _remove_owned_output(path, identity)
        _remove_empty_reservation(json_path, json_reservation)
        _remove_empty_reservation(report_path, report_reservation)
        raise
    return {"bundle": str(json_path), "report": str(report_path), "run_id": bundle.run_id}


def _configure_utf8_stdio() -> None:
    """Make redirected CLI output deterministic across operating systems."""

    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if callable(reconfigure):
            reconfigure(encoding="utf-8", errors="backslashreplace")


def _json(data: Any) -> None:
    print(json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True))


def _write_text_atomic(
    path: str | Path,
    text: str,
    *,
    expected_identity: tuple[int, int] | None = None,
) -> Path:
    destination = _absolute_local_path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.", suffix=".tmp", dir=destination.parent
    )
    temporary = Path(temporary_name)
    published_identity: tuple[int, int] | None = None
    try:
        if hasattr(os, "fchmod"):
            os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        if expected_identity is not None:
            _assert_reservation(destination, expected_identity)
        staged_identity = _path_identity(temporary)
        os.replace(temporary, destination)
        published_identity = staged_identity
    except BaseException:
        try:
            os.close(descriptor)
        except OSError:
            pass
        temporary.unlink(missing_ok=True)
        if published_identity is not None and expected_identity is not None:
            _remove_owned_output(destination, published_identity)
        raise
    return destination


def _validated_evidence(values: list[str]) -> list[str]:
    # Reuse the authoritative change-plan contract so standalone safety
    # assessment cannot drift on length, count, printability, or secret checks.
    return normalize_control_channel({"evidence": values})["evidence"]


_ARGPARSE_VALUE_MARKER_RE = re.compile(
    r"(?:invalid (?:[^:\r\n]+ )?value|invalid choice): "
)
_ANSI_ESCAPE_RE = re.compile(
    r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07\x1b]*(?:\x07|\x1b\\)|[@-_])"
)
_CHANGE_RECEIPT_STATUSES = {
    "running",
    "applied",
    "apply-failed",
    "rolled-back",
    "rolled-back-with-errors",
    "rollback-failed",
    "rollback-pending",
    "blocked",
}


def _sanitize_stderr_text(value: str) -> str:
    value = _ANSI_ESCAPE_RE.sub("", str(value))
    cleaned = "".join(
        " "
        if character in {"\u2028", "\u2029"}
        or unicodedata.category(character) in {"Cc", "Cf"}
        else character
        for character in value
    )
    return re.sub(r"\s+", " ", cleaned).strip()


def _stderr(value: str) -> None:
    rendered = _sanitize_stderr_text(value)
    if rendered:
        # Use a printable separator so stderr contains no C0 control bytes,
        # including an injected or formatter-added newline.
        sys.stderr.write(f"{rendered} ")


def _sanitize_argparse_error(value: str) -> str:
    """Remove user-supplied values before argparse text reaches stderr."""

    boundaries: list[int] = []
    value_match = _ARGPARSE_VALUE_MARKER_RE.search(value)
    if value_match:
        boundaries.append(value_match.end())
    for marker in ("unrecognized arguments: ", "ambiguous option: "):
        marker_index = value.find(marker)
        if marker_index >= 0:
            boundaries.append(marker_index + len(marker))
    if boundaries:
        boundary = min(boundaries)
        value = value[:boundary] + "<redacted-input>\n"
    value = Redactor(include_network_identifiers=False).text(value)
    return _sanitize_stderr_text(value)


def _display_local_path(path: Path) -> str:
    """Keep a recovery path usable while removing secrets and terminal controls."""

    redactor = Redactor(
        include_network_identifiers=True,
        redact_hostnames=False,
    )
    return _sanitize_stderr_text(redactor.text(str(path)))


def _require_new_output(path: str | Path, *, label: str) -> Path:
    candidate = _absolute_local_path(path)
    if os.path.lexists(candidate):
        raise FileExistsError(f"refusing to overwrite existing {label}: {candidate}")
    return candidate


def _write_text_new(path: str | Path, text: str, *, label: str) -> Path:
    destination, reservation = _reserve_new_output(path, label=label)
    try:
        return _write_text_atomic(
            destination,
            text,
            expected_identity=reservation,
        )
    except BaseException:
        _remove_empty_reservation(destination, reservation)
        raise


def _change_receipt_destination(args: argparse.Namespace) -> Path | None:
    if getattr(args, "command", None) != "change":
        return None
    mode = getattr(args, "change_mode", None)
    if mode not in {"apply", "rollback"}:
        return None
    explicit = getattr(args, "receipt", None)
    if mode == "apply":
        return resolve_apply_receipt_path(args.plan, explicit)
    return resolve_rollback_receipt_path(args.plan, explicit)


def _change_failure_context(
    args: argparse.Namespace, *, existed_before_execution: bool = False
) -> tuple[Path, str] | None:
    destination = _change_receipt_destination(args)
    if (
        existed_before_execution
        or destination is None
        or not destination.is_file()
    ):
        return None
    try:
        data = load_json_limited(destination, max_bytes=1024 * 1024)
    except (OSError, UnicodeError, ValueError):
        return destination, "unreadable"
    status = data.get("status") if isinstance(data, dict) else None
    if status not in _CHANGE_RECEIPT_STATUSES:
        status = "unknown"
    return destination, status


def _default_scope() -> str:
    return "system" if platform_id() == "linux" else "user"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="netopsctl",
        description="Bounded VPS and proxy network diagnostics for the NetOps skills.",
    )
    parser.add_argument("--version", action="version", version=f"netopsctl {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)

    scan = commands.add_parser("scan", help="Run a bounded read-only scan")
    scan_modes = scan.add_subparsers(dest="scan_mode", required=True)

    client = scan_modes.add_parser("client", help="Scan the local client")
    client.add_argument("--external", action="store_true", help="Query public egress providers")
    client.add_argument(
        "--tool",
        action=_SingleUseAction,
        choices=tool_ids_for_mode("client"),
        help="Run one explicitly selected curated adapter",
    )
    client.add_argument(
        "--tool-external",
        action="store_true",
        help="Consent to the selected tool's requests; does not query identity providers",
    )
    client.add_argument("--output")

    server = scan_modes.add_parser("server", help="Scan a local or SSH-accessible Linux server")
    source = server.add_mutually_exclusive_group(required=True)
    source.add_argument("--local", action="store_true")
    source.add_argument("--host", help="Fleet host alias")
    server.add_argument("--fleet", help="Fleet JSON for --host")
    server.add_argument("--authorized", action="store_true")
    server.add_argument("--external", action="store_true", help="Local server only")
    server.add_argument(
        "--tool",
        action=_SingleUseAction,
        choices=tool_ids_for_mode("server"),
        help="Run one explicitly selected curated adapter on a local server",
    )
    server.add_argument(
        "--tool-external",
        action="store_true",
        help="Consent to the selected tool's requests; does not query identity providers",
    )
    server.add_argument("--output")

    node = scan_modes.add_parser("node", help="Probe one declared node or destination")
    node.add_argument("--target", required=True)
    node.add_argument("--port", required=True, type=int)
    node.add_argument("--protocol", choices=("tcp", "udp"), default="tcp")
    node.add_argument("--tls", action="store_true")
    node.add_argument("--http", action="store_true")
    node.add_argument("--path", default="/")
    node.add_argument(
        "--proxy-env",
        help="Environment variable containing an HTTP/SOCKS proxy URL",
    )
    node.add_argument("--trace", action="store_true")
    node.add_argument(
        "--tool",
        action=_SingleUseAction,
        choices=tool_ids_for_mode("node"),
        help="Run one explicitly selected curated adapter",
    )
    node.add_argument(
        "--external",
        action="store_true",
        help="Consent to the selected tool's declared network requests",
    )
    node.add_argument(
        "--allow-load",
        action="store_true",
        help="Separately consent to a bounded bandwidth test",
    )
    node.add_argument(
        "--resolver",
        help="Explicit DNS resolver for the dnsdiag adapter",
    )
    node.add_argument("--timeout", type=float, default=8)
    node.add_argument("--output")

    compare = scan_modes.add_parser("compare", help="Compare compatible node bundles")
    compare.add_argument("left")
    compare.add_argument("right")
    compare.add_argument("--max-time-delta", type=int, default=300)
    compare.add_argument("--output")

    curated = commands.add_parser("tools", help="Inspect the curated external-tool catalog")
    curated_modes = curated.add_subparsers(dest="tools_mode", required=True)
    curated_modes.add_parser("list", help="Show tool metadata, risks, and official sources")
    curated_status = curated_modes.add_parser(
        "status", help="Detect compatible tools without running network probes"
    )
    curated_status.add_argument(
        "--tool", action=_SingleUseAction, choices=tool_ids()
    )
    curated_status.add_argument(
        "--versions",
        action="store_true",
        help="Run local, non-network version commands for detected tools",
    )

    monitor = commands.add_parser(
        "monitor", help="Review bounded monitoring plans and owned-file integrity"
    )
    monitor_modes = monitor.add_subparsers(
        dest="monitor_mode",
        required=True,
        metavar="{install,status,remove}",
    )

    monitor_install = monitor_modes.add_parser(
        "install", help="Generate a non-executable scheduler review plan"
    )
    monitor_install.add_argument("--target", required=True)
    monitor_install.add_argument("--port", type=int, required=True)
    monitor_install.add_argument("--protocol", choices=("tcp", "udp"), default="tcp")
    monitor_install.add_argument("--profile", choices=("client", "server"), default="server")
    monitor_install.add_argument("--scope", choices=("system", "user"), default=_default_scope())
    monitor_install.add_argument(
        "--dry-run",
        action="store_true",
        help="Required in this release; no scheduler mutation is available",
    )
    monitor_install.add_argument("--interval", type=int, default=60)
    monitor_install.add_argument("--full-interval", type=int, default=900)
    monitor_install.add_argument("--failure-threshold", type=int, default=3)
    monitor_install.add_argument("--incident-interval", type=int, default=5)
    monitor_install.add_argument("--incident-duration", type=int, default=600)
    monitor_install.add_argument("--retention-days", type=int, default=7)
    monitor_install.add_argument("--max-bytes", type=int, default=200 * 1024 * 1024)

    monitor_status_parser = monitor_modes.add_parser(
        "status", help="Inspect owned local files without querying the scheduler"
    )
    monitor_status_parser.add_argument(
        "--scope", choices=("system", "user"), default=_default_scope()
    )

    monitor_remove = monitor_modes.add_parser(
        "remove", help="Generate a non-executable removal review plan"
    )
    monitor_remove.add_argument("--scope", choices=("system", "user"), default=_default_scope())
    monitor_remove.add_argument(
        "--dry-run",
        action="store_true",
        help="Required in this release; no scheduler mutation is available",
    )

    monitor_sample = monitor_modes.add_parser("sample", help=argparse.SUPPRESS)
    monitor_sample.add_argument("--config", required=True)
    monitor_sample.add_argument("--no-incident-loop", action="store_true")
    monitor_modes._choices_actions = [
        action
        for action in monitor_modes._choices_actions
        if action.dest != "sample"
    ]

    bundle = commands.add_parser("bundle", help="Export or inspect a diagnostic bundle")
    bundle_modes = bundle.add_subparsers(dest="bundle_mode", required=True)
    bundle_export = bundle_modes.add_parser("export", help="Create a redacted archive")
    bundle_export.add_argument("source")
    bundle_export.add_argument("--output", required=True)
    bundle_export.add_argument("--include-network-identifiers", action="store_true")
    bundle_inspect = bundle_modes.add_parser("inspect", help="Validate and render a bundle")
    bundle_inspect.add_argument("source")
    bundle_inspect.add_argument("--report-output")

    safety = commands.add_parser(
        "safety", help="Assess whether a network change could disconnect Codex"
    )
    safety_modes = safety.add_subparsers(dest="safety_mode", required=True)
    safety_assess = safety_modes.add_parser(
        "assess", help="Evaluate control-channel continuity before a change"
    )
    safety_assess.add_argument(
        "--dependency", choices=DEPENDENCIES, default="unknown"
    )
    safety_assess.add_argument(
        "--surface",
        action="append",
        choices=CHANGE_SURFACES,
        default=[],
        help="Component affected by the proposed change; repeatable",
    )
    safety_assess.add_argument(
        "--strategy",
        choices=CONTINUITY_STRATEGIES,
        default="manual-recovery",
    )
    safety_assess.add_argument("--independent-path-verified", action="store_true")
    safety_assess.add_argument("--recovery-reviewed", action="store_true")
    safety_assess.add_argument("--host-reboot-planned", action="store_true")
    safety_assess.add_argument(
        "--rollback-delay",
        type=int,
        help="Enable a remote rollback timer with this delay in seconds",
    )
    safety_assess.add_argument(
        "--platform",
        choices=("auto", "macos", "windows", "linux", "unknown"),
        default="auto",
    )
    safety_assess.add_argument(
        "--evidence",
        action="append",
        default=[],
        help="Repeatable short non-secret evidence note; never include credentials",
    )

    change = commands.add_parser(
        "change",
        help="Plan a controlled remote change; execution is unavailable in this release",
    )
    change_modes = change.add_subparsers(dest="change_mode", required=True)
    change_plan = change_modes.add_parser("plan", help="Normalize and hash a change spec")
    change_plan.add_argument("--spec", required=True)
    change_plan.add_argument("--fleet", required=True)
    change_plan.add_argument("--output", required=True)

    change_apply = change_modes.add_parser(
        "apply", help="Unavailable in this release; always fails closed"
    )
    change_apply.add_argument("--plan", required=True)
    change_apply.add_argument("--fleet", required=True)
    change_apply.add_argument("--confirm-plan-id", required=True)
    change_apply.add_argument("--receipt")

    change_rollback = change_modes.add_parser(
        "rollback", help="Unavailable in this release; always fails closed"
    )
    change_rollback.add_argument("--plan", required=True)
    change_rollback.add_argument("--fleet", required=True)
    change_rollback.add_argument("--backup-dir", required=True)
    change_rollback.add_argument(
        "--apply-receipt",
        required=True,
        help="Original durable apply receipt that binds backup integrity digests",
    )
    change_rollback.add_argument(
        "--current-control-channel",
        required=True,
        help="Fresh JSON evidence for the currently independent rollback path",
    )
    change_rollback.add_argument("--confirm-plan-id", required=True)
    change_rollback.add_argument("--receipt")
    return parser


def _entry_script() -> Path:
    root = Path(__file__).resolve().parents[1]
    script = root / "scripts/netopsctl.py"
    if script.is_file():
        return script
    invoked = Path(sys.argv[0]).expanduser()
    if invoked.is_absolute() and invoked.is_file():
        return invoked.resolve()
    installed = shutil.which(sys.argv[0])
    if installed:
        return Path(installed).resolve()
    raise RuntimeError("cannot resolve the installed netopsctl entry point")


def execute(args: argparse.Namespace) -> int:
    if args.command == "scan":
        reservations = _reserve_scan_outputs(args.scan_mode, args.output)
        try:
            selected_tool = getattr(args, "tool", None)
            selected_tools = [selected_tool] if selected_tool else []
            if getattr(args, "tool_external", False) and not selected_tools:
                raise ValueError("--tool-external requires --tool")
            if args.scan_mode == "client":
                result = scan_client(
                    external=args.external,
                    tools=selected_tools,
                    tools_external=args.tool_external,
                )
            elif args.scan_mode == "server":
                if args.local:
                    result = scan_server_local(
                        external=args.external,
                        tools=selected_tools,
                        tools_external=args.tool_external,
                    )
                else:
                    if not args.fleet:
                        raise ValueError("--fleet is required with --host")
                    if args.external:
                        raise ValueError(
                            "--external is only supported for a local server scan"
                        )
                    if selected_tools:
                        raise ValueError(
                            "curated tools run at the local observation point; run netopsctl on the VPS"
                        )
                    fleet = load_fleet(args.fleet)
                    result = scan_server_remote(
                        get_host(fleet, args.host), authorized=args.authorized
                    )
            elif args.scan_mode == "node":
                result = scan_node(
                    target=args.target,
                    port=args.port,
                    protocol=args.protocol,
                    tls=args.tls,
                    http=args.http,
                    path=args.path,
                    proxy_env=args.proxy_env,
                    trace=args.trace,
                    timeout=args.timeout,
                    tools=selected_tools,
                    external=args.external,
                    allow_load=args.allow_load,
                    resolver=args.resolver,
                )
            else:
                result = compare_bundles(
                    args.left,
                    args.right,
                    max_time_delta_seconds=args.max_time_delta,
                )
            _json(
                _write_scan(
                    result,
                    args.output,
                    reservations=reservations,
                )
            )
        finally:
            _release_scan_reservations(reservations)
        return 0

    if args.command == "tools":
        if args.tools_mode == "list":
            _json(tool_catalog())
        else:
            _json(
                tool_status(
                    [args.tool] if args.tool else None,
                    include_versions=args.versions,
                )
            )
        return 0

    if args.command == "monitor":
        if args.monitor_mode == "install":
            plan = build_install_plan(
                entry_script=_entry_script(),
                target=args.target,
                port=args.port,
                protocol=args.protocol,
                profile=args.profile,
                scope=args.scope,
                overrides={
                    "interval_seconds": args.interval,
                    "full_interval_seconds": args.full_interval,
                    "failure_threshold": args.failure_threshold,
                    "incident_interval_seconds": args.incident_interval,
                    "incident_duration_seconds": args.incident_duration,
                    "retention_days": args.retention_days,
                    "max_bytes": args.max_bytes,
                },
            )
            _json(
                install_monitor(plan, dry_run=args.dry_run)
            )
        elif args.monitor_mode == "status":
            _json(monitor_status(scope=args.scope))
        elif args.monitor_mode == "remove":
            removal = remove_monitor(
                scope=args.scope,
                dry_run=args.dry_run,
            )
            _json(removal)
            if removal.get("status") in {"blocked", "partial"}:
                return 1
        else:
            sample_result = run_sample(
                args.config,
                allow_incident_loop=not args.no_incident_loop,
            )
            _json(sample_result)
            return 1 if sample_result.get("status") == "failed" else 0
        return 0

    if args.command == "bundle":
        if args.bundle_mode == "export":
            output = export_bundle(
                args.source,
                args.output,
                include_network_identifiers=args.include_network_identifiers,
            )
            _json({"archive": str(output)})
        else:
            _, report = inspect_bundle(args.source)
            if args.report_output:
                output = _write_text_new(
                    args.report_output,
                    report,
                    label="bundle inspection report",
                )
                _json({"report": str(output)})
            else:
                print(report)
        return 0

    if args.command == "safety":
        control_channel = normalize_control_channel(
            {
                "dependency": args.dependency,
                "change_surfaces": args.surface or ["unknown"],
                "continuity_strategy": args.strategy,
                "independent_path_verified": args.independent_path_verified,
                "operator_recovery_reviewed": args.recovery_reviewed,
                "host_reboot_planned": args.host_reboot_planned,
                "evidence": _validated_evidence(args.evidence),
            }
        )
        rollback_timer = normalize_rollback_timer(
            {
                "enabled": args.rollback_delay is not None,
                "delay_seconds": args.rollback_delay or 600,
            }
        )
        current_platform = platform_id() if args.platform == "auto" else args.platform
        _json(
            {
                "control_channel": control_channel,
                "rollback_timer": rollback_timer,
                "guard": assess_control_channel(
                    control_channel,
                    rollback_timer,
                    platform_name=current_platform,
                ),
            }
        )
        return 0

    if args.command == "change":
        if args.change_mode != "plan":
            # Reject before fleet/plan/evidence reads, receipt reservation, or
            # any transport call.  There is deliberately no override.
            raise PermissionError(CHANGE_EXECUTION_UNAVAILABLE)
        _require_new_output(args.output, label="change plan")
        fleet = load_fleet(args.fleet)
        _json(create_plan(args.spec, fleet, args.output))
        return 0
    raise RuntimeError("unhandled command")


def main(argv: list[str] | None = None) -> int:
    _configure_utf8_stdio()
    parser = build_parser()
    parse_stderr = io.StringIO()
    try:
        with contextlib.redirect_stderr(parse_stderr):
            args = parser.parse_args(argv)
    except SystemExit as exc:
        captured = parse_stderr.getvalue()
        if captured:
            _stderr(_sanitize_argparse_error(captured))
        return int(exc.code or 0)
    unreleased_change = (
        getattr(args, "command", None) == "change"
        and getattr(args, "change_mode", None) in {"apply", "rollback"}
    )
    # The unreleased execution gate must precede even local receipt-path
    # resolution and existence probes, not only plan reads and remote I/O.
    receipt_destination = (
        None if unreleased_change else _change_receipt_destination(args)
    )
    receipt_existed_before = bool(
        receipt_destination is not None and os.path.lexists(receipt_destination)
    )
    try:
        return execute(args)
    except Exception as exc:
        redactor = Redactor(include_network_identifiers=False)
        normalized_error = _sanitize_stderr_text(str(exc))
        _stderr(f"netopsctl: {redactor.text(normalized_error)}")
        context = (
            None
            if unreleased_change
            else _change_failure_context(
                args, existed_before_execution=receipt_existed_before
            )
        )
        if context is not None:
            destination, status = context
            safe_path = _display_local_path(destination)
            _stderr(
                f"netopsctl: change receipt status={status} path={safe_path}"
            )
            if status == "rollback-pending":
                _stderr(
                    "netopsctl: automatic rollback may still be armed; do not retry "
                    "until the receipt and rollback status are verified"
                )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
