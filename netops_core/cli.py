from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .bundle import export_bundle, inspect_bundle
from .change import apply_plan, create_plan, rollback_plan
from .fleet import get_host, load_fleet
from .models import DiagnosticBundle, write_bundle
from .monitor import (
    build_install_plan,
    install_monitor,
    monitor_status,
    remove_monitor,
    run_sample,
)
from .report import render_report
from .scanner import (
    compare_bundles,
    scan_client,
    scan_node,
    scan_server_local,
    scan_server_remote,
)
from .util import platform_id


def _stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _default_output(mode: str) -> Path:
    return Path.cwd() / "diagnostics" / f"{_stamp()}-{mode}.json"


def _write_scan(bundle: DiagnosticBundle, output: str | None) -> dict[str, str]:
    destination = Path(output).expanduser() if output else _default_output(bundle.mode)
    json_path = write_bundle(destination, bundle)
    report_path = json_path.with_suffix(".md")
    report_path.write_text(render_report(bundle), encoding="utf-8")
    return {"bundle": str(json_path), "report": str(report_path), "run_id": bundle.run_id}


def _json(data: Any) -> None:
    print(json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True))


def _default_scope() -> str:
    return "system" if platform_id() == "linux" else "user"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="netopsctl",
        description="Bounded VPS and proxy network diagnostics for the NetOps skills.",
    )
    parser.add_argument("--version", action="version", version="netopsctl 0.1.0")
    commands = parser.add_subparsers(dest="command", required=True)

    scan = commands.add_parser("scan", help="Run a bounded read-only scan")
    scan_modes = scan.add_subparsers(dest="scan_mode", required=True)

    client = scan_modes.add_parser("client", help="Scan the local client")
    client.add_argument("--external", action="store_true", help="Query public egress providers")
    client.add_argument("--output")

    server = scan_modes.add_parser("server", help="Scan a local or SSH-accessible Linux server")
    source = server.add_mutually_exclusive_group(required=True)
    source.add_argument("--local", action="store_true")
    source.add_argument("--host", help="Fleet host alias")
    server.add_argument("--fleet", help="Fleet JSON for --host")
    server.add_argument("--authorized", action="store_true")
    server.add_argument("--external", action="store_true", help="Local server only")
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
    node.add_argument("--timeout", type=float, default=8)
    node.add_argument("--output")

    compare = scan_modes.add_parser("compare", help="Compare compatible node bundles")
    compare.add_argument("left")
    compare.add_argument("right")
    compare.add_argument("--max-time-delta", type=int, default=300)
    compare.add_argument("--output")

    monitor = commands.add_parser("monitor", help="Manage bounded scheduled monitoring")
    monitor_modes = monitor.add_subparsers(dest="monitor_mode", required=True)

    monitor_install = monitor_modes.add_parser("install", help="Install a scheduler task")
    monitor_install.add_argument("--target", required=True)
    monitor_install.add_argument("--port", type=int, required=True)
    monitor_install.add_argument("--protocol", choices=("tcp", "udp"), default="tcp")
    monitor_install.add_argument("--profile", choices=("client", "server"), default="server")
    monitor_install.add_argument("--scope", choices=("system", "user"), default=_default_scope())
    monitor_install.add_argument("--authorized", action="store_true")
    monitor_install.add_argument("--dry-run", action="store_true")
    monitor_install.add_argument("--interval", type=int, default=60)
    monitor_install.add_argument("--full-interval", type=int, default=900)
    monitor_install.add_argument("--failure-threshold", type=int, default=3)
    monitor_install.add_argument("--incident-interval", type=int, default=5)
    monitor_install.add_argument("--incident-duration", type=int, default=600)
    monitor_install.add_argument("--retention-days", type=int, default=7)
    monitor_install.add_argument("--max-bytes", type=int, default=200 * 1024 * 1024)

    monitor_status_parser = monitor_modes.add_parser("status", help="Inspect scheduler state")
    monitor_status_parser.add_argument(
        "--scope", choices=("system", "user"), default=_default_scope()
    )

    monitor_remove = monitor_modes.add_parser("remove", help="Remove scheduler, preserve data")
    monitor_remove.add_argument("--scope", choices=("system", "user"), default=_default_scope())
    monitor_remove.add_argument("--authorized", action="store_true")
    monitor_remove.add_argument("--dry-run", action="store_true")

    monitor_sample = monitor_modes.add_parser("sample", help=argparse.SUPPRESS)
    monitor_sample.add_argument("--config", required=True)
    monitor_sample.add_argument("--no-incident-loop", action="store_true")

    bundle = commands.add_parser("bundle", help="Export or inspect a diagnostic bundle")
    bundle_modes = bundle.add_subparsers(dest="bundle_mode", required=True)
    bundle_export = bundle_modes.add_parser("export", help="Create a redacted archive")
    bundle_export.add_argument("source")
    bundle_export.add_argument("--output", required=True)
    bundle_export.add_argument("--include-network-identifiers", action="store_true")
    bundle_inspect = bundle_modes.add_parser("inspect", help="Validate and render a bundle")
    bundle_inspect.add_argument("source")
    bundle_inspect.add_argument("--report-output")

    change = commands.add_parser("change", help="Plan or execute a controlled remote change")
    change_modes = change.add_subparsers(dest="change_mode", required=True)
    change_plan = change_modes.add_parser("plan", help="Normalize and hash a change spec")
    change_plan.add_argument("--spec", required=True)
    change_plan.add_argument("--fleet", required=True)
    change_plan.add_argument("--output", required=True)

    change_apply = change_modes.add_parser("apply", help="Apply one confirmed change plan")
    change_apply.add_argument("--plan", required=True)
    change_apply.add_argument("--fleet", required=True)
    change_apply.add_argument("--authorized", action="store_true")
    change_apply.add_argument("--confirm-plan-id", required=True)
    change_apply.add_argument("--receipt")

    change_rollback = change_modes.add_parser("rollback", help="Restore one plan backup")
    change_rollback.add_argument("--plan", required=True)
    change_rollback.add_argument("--fleet", required=True)
    change_rollback.add_argument("--backup-dir", required=True)
    change_rollback.add_argument("--authorized", action="store_true")
    change_rollback.add_argument("--confirm-plan-id", required=True)
    change_rollback.add_argument("--receipt")
    return parser


def _entry_script() -> Path:
    root = Path(__file__).resolve().parents[1]
    script = root / "scripts/netopsctl.py"
    return script if script.is_file() else Path(sys.argv[0]).resolve()


def execute(args: argparse.Namespace) -> int:
    if args.command == "scan":
        if args.scan_mode == "client":
            result = scan_client(external=args.external)
        elif args.scan_mode == "server":
            if args.local:
                result = scan_server_local(external=args.external)
            else:
                if not args.fleet:
                    raise ValueError("--fleet is required with --host")
                if args.external:
                    raise ValueError("--external is only supported for a local server scan")
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
            )
        else:
            result = compare_bundles(
                args.left,
                args.right,
                max_time_delta_seconds=args.max_time_delta,
            )
        _json(_write_scan(result, args.output))
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
                install_monitor(
                    plan, authorized=args.authorized, dry_run=args.dry_run
                )
            )
        elif args.monitor_mode == "status":
            _json(monitor_status(scope=args.scope))
        elif args.monitor_mode == "remove":
            _json(
                remove_monitor(
                    scope=args.scope,
                    authorized=args.authorized,
                    dry_run=args.dry_run,
                )
            )
        else:
            _json(
                run_sample(
                    args.config,
                    allow_incident_loop=not args.no_incident_loop,
                )
            )
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
                output = Path(args.report_output).expanduser().resolve()
                output.parent.mkdir(parents=True, exist_ok=True)
                output.write_text(report, encoding="utf-8")
                _json({"report": str(output)})
            else:
                print(report)
        return 0

    if args.command == "change":
        fleet = load_fleet(args.fleet)
        if args.change_mode == "plan":
            _json(create_plan(args.spec, fleet, args.output))
        elif args.change_mode == "apply":
            _json(
                apply_plan(
                    args.plan,
                    fleet,
                    authorized=args.authorized,
                    confirmed_plan_id=args.confirm_plan_id,
                    receipt_path=args.receipt,
                )
            )
        else:
            _json(
                rollback_plan(
                    args.plan,
                    fleet,
                    backup_dir=args.backup_dir,
                    authorized=args.authorized,
                    confirmed_plan_id=args.confirm_plan_id,
                    receipt_path=args.receipt,
                )
            )
        return 0
    raise RuntimeError("unhandled command")


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return execute(args)
    except (ValueError, KeyError, PermissionError, RuntimeError, OSError) as exc:
        print(f"netopsctl: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
