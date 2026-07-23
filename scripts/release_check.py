#!/usr/bin/env python3
from __future__ import annotations

import argparse
import compileall
import inspect
import re
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch


VERSION_LINE = re.compile(r'^version\s*=\s*"([0-9]+\.[0-9]+\.[0-9]+)"\s*$', re.MULTILINE)
EXAMPLE_SCHEMAS = {
    "examples/change-spec.example.json": "schemas/change-spec.schema.json",
    "examples/fleet.example.json": "schemas/fleet.schema.json",
}
EXPECTED_CI_MATRIX = (
    ("ubuntu-latest", "3.10"),
    ("ubuntu-latest", "3.11"),
    ("ubuntu-latest", "3.12"),
    ("ubuntu-latest", "3.13"),
    ("ubuntu-latest", "3.14"),
    ("macos-latest", "3.10"),
    ("macos-latest", "3.12"),
    ("macos-latest", "3.14"),
    ("windows-latest", "3.10"),
    ("windows-latest", "3.12"),
    ("windows-latest", "3.14"),
)
REQUIRED_MANIFEST_LINES = (
    "include README.md",
    "include README.zh-CN.md",
    "include LICENSE",
    "include SKILL.md",
    "include pyproject.toml",
    "include MANIFEST.in",
    "include .github/workflows/test.yml",
    "recursive-include agents *",
    "recursive-include examples *",
    "recursive-include references *",
    "recursive-include schemas *",
    "recursive-include scripts *",
    "recursive-include skills *",
    "recursive-include tests *",
    "exclude .project-notes.md",
    "prune build",
    "prune dist",
    "prune diagnostics",
    "prune .pytest_cache",
    "prune .mypy_cache",
    "prune .ruff_cache",
    "prune __pycache__",
    *(
        f"prune {'*/' * depth}{directory}"
        for depth in range(1, 5)
        for directory in (
            "build",
            "dist",
            "diagnostics",
            ".pytest_cache",
            ".mypy_cache",
            ".ruff_cache",
            "__pycache__",
        )
    ),
    "global-exclude *.py[cod]",
    "global-exclude __pycache__",
    "global-exclude .DS_Store",
)


def _load_json_documents(root: Path) -> list[str]:
    errors: list[str] = []
    paths = [
        *sorted((root / "schemas").glob("*.json")),
        *sorted((root / "examples").rglob("*.json")),
        *sorted((root / "tests/fixtures").glob("*.json")),
    ]
    if not paths:
        return ["no JSON schemas, examples, or fixtures were found"]
    sys.path.insert(0, str(root))
    try:
        from netops_core.util import load_json_limited
    finally:
        sys.path.pop(0)
    for path in paths:
        try:
            load_json_limited(path, max_bytes=4 * 1_048_576)
        except (OSError, UnicodeError, ValueError) as exc:
            errors.append(f"{path.relative_to(root)}: invalid JSON: {exc}")
    return errors


def _check_versions(root: Path) -> list[str]:
    errors: list[str] = []
    pyproject = (root / "pyproject.toml").read_text(encoding="utf-8")
    match = VERSION_LINE.search(pyproject)
    if not match:
        return ["pyproject.toml: missing strict semantic project version"]
    sys.path.insert(0, str(root))
    try:
        from netops_core import __version__
    finally:
        sys.path.pop(0)
    if match.group(1) != __version__:
        errors.append(
            f"version mismatch: pyproject={match.group(1)!r}, netops_core={__version__!r}"
        )
    scanner_text = (root / "netops_core/scanner.py").read_text(encoding="utf-8")
    if "USER_AGENT = f\"NetOps/{__version__}\"" not in scanner_text:
        errors.append("scanner user agent must derive from the package version")
    if re.search(r"NetOps/0\.[0-9]+", scanner_text):
        errors.append("scanner contains a stale hard-coded pre-release user agent")
    return errors


def _check_packaging_contract(root: Path) -> list[str]:
    pyproject = (root / "pyproject.toml").read_text(encoding="utf-8")
    required_lines = (
        'requires = ["setuptools==83.0.0"]',
        'build-backend = "setuptools.build_meta"',
        'requires-python = ">=3.10,<3.15"',
        'license = "MIT"',
    )
    return [
        f"pyproject.toml: release contract is missing {line}"
        for line in required_lines
        if line not in pyproject.splitlines()
    ]


def _check_manifest_contract(root: Path) -> list[str]:
    path = root / "MANIFEST.in"
    try:
        lines = [
            line.strip()
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
    except (OSError, UnicodeError) as exc:
        return [f"MANIFEST.in: cannot read source distribution contract: {exc}"]
    errors = [
        f"MANIFEST.in: source distribution contract is missing {line}"
        for line in REQUIRED_MANIFEST_LINES
        if line not in lines
    ]
    unexpected = [line for line in lines if line not in REQUIRED_MANIFEST_LINES]
    errors.extend(
        f"MANIFEST.in: source distribution contract has an unexpected directive: {line}"
        for line in unexpected
    )
    if not errors and lines != list(REQUIRED_MANIFEST_LINES):
        errors.append(
            "MANIFEST.in: source distribution directives must use the canonical order"
        )
    return errors


def _check_ci_contract(root: Path) -> list[str]:
    workflow = (root / ".github/workflows/test.yml").read_text(encoding="utf-8")
    errors: list[str] = []
    required_fragments = (
        "actions/checkout@df4cb1c069e1874edd31b4311f1884172cec0e10",
        "actions/setup-python@ece7cb06caefa5fff74198d8649806c4678c61a1",
        '"setuptools==83.0.0"',
        '"build==1.3.0"',
        '"jsonschema==4.25.1"',
        "if: runner.os == 'Linux'",
        "sudo apt-get install --no-install-recommends -y acl attr",
        'SOURCE_DATE_EPOCH: "1720000000"',
        "python scripts/release_check.py . --require-jsonschema",
        "python scripts/reproducible_build.py .",
        "--source-date-epoch ${{ env.SOURCE_DATE_EPOCH }}",
        "--output-dir dist",
        "python scripts/package_smoke.py . --dist-dir dist",
    )
    for fragment in required_fragments:
        if fragment not in workflow:
            errors.append(f"CI release contract is missing: {fragment}")
    for operating_system, python_version in EXPECTED_CI_MATRIX:
        fragment = (
            f"- os: {operating_system}\n"
            f'            python-version: "{python_version}"'
        )
        if fragment not in workflow:
            errors.append(
                f"CI matrix is missing {operating_system} Python {python_version}"
            )
    reproducible_script = root / "scripts/reproducible_build.py"
    if not reproducible_script.is_file() or reproducible_script.is_symlink():
        errors.append("CI release contract requires scripts/reproducible_build.py")
    return errors


def _load_release_json(path: Path):
    from netops_core.util import load_json_limited

    return load_json_limited(path, max_bytes=4 * 1_048_576)


def _check_example_contracts(root: Path) -> list[str]:
    """Exercise the authoritative stdlib validators for shipped examples."""

    sys.path.insert(0, str(root))
    try:
        from netops_core.change import validate_change_spec
        from netops_core.fleet import validate_fleet

        checks = (
            (
                root / "examples/fleet.example.json",
                lambda value: validate_fleet(value),
            ),
            (
                root / "examples/change-spec.example.json",
                lambda value: validate_change_spec(
                    value,
                    source_dir=root / "examples",
                ),
            ),
        )
        errors: list[str] = []
        for path, validate in checks:
            try:
                validate(_load_release_json(path))
            except (OSError, UnicodeError, ValueError) as exc:
                errors.append(
                    f"{path.relative_to(root)}: runtime contract validation failed: {exc}"
                )
        return errors
    finally:
        sys.path.pop(0)


def _check_json_schemas(root: Path) -> list[str]:
    """Meta-validate Draft 2020-12 schemas and their corresponding examples."""

    try:
        from jsonschema import Draft202012Validator
        from jsonschema.exceptions import SchemaError, ValidationError
    except ImportError:
        return [
            "jsonschema is required for the requested schema gate; "
            "install the pinned release dependency jsonschema==4.25.1"
        ]

    errors: list[str] = []
    validators = {}
    for path in sorted((root / "schemas").glob("*.json")):
        relative = path.relative_to(root).as_posix()
        try:
            schema = _load_release_json(path)
            Draft202012Validator.check_schema(schema)
            validators[relative] = Draft202012Validator(
                schema,
                format_checker=Draft202012Validator.FORMAT_CHECKER,
            )
        except (OSError, UnicodeError, ValueError, SchemaError) as exc:
            errors.append(f"{relative}: invalid Draft 2020-12 schema: {exc}")

    for example_name, schema_name in EXAMPLE_SCHEMAS.items():
        validator = validators.get(schema_name)
        if validator is None:
            errors.append(f"{example_name}: corresponding schema is unavailable")
            continue
        path = root / example_name
        try:
            validator.validate(_load_release_json(path))
        except ValidationError as exc:
            location = "$" + "".join(
                f"[{part}]" if isinstance(part, int) else f".{part}"
                for part in exc.absolute_path
            )
            errors.append(
                f"{example_name}: schema validation failed at {location}: {exc.message}"
            )
        except (OSError, UnicodeError, ValueError) as exc:
            errors.append(f"{example_name}: cannot validate example: {exc}")

    plan_validator = validators.get("schemas/change-plan.schema.json")
    if plan_validator is not None:
        sys.path.insert(0, str(root))
        try:
            from netops_core.change import create_plan
            from netops_core.fleet import validate_fleet

            fleet = _load_release_json(root / "examples/fleet.example.json")
            validate_fleet(fleet)
            with tempfile.TemporaryDirectory() as raw:
                plan = create_plan(
                    root / "examples/change-spec.example.json",
                    fleet,
                    Path(raw) / "change-plan.json",
                )
            plan_validator.validate(plan)
        except ValidationError as exc:
            location = "$" + "".join(
                f"[{part}]" if isinstance(part, int) else f".{part}"
                for part in exc.absolute_path
            )
            errors.append(
                "generated change plan: schema validation failed at "
                f"{location}: {exc.message}"
            )
        except (OSError, UnicodeError, ValueError) as exc:
            errors.append(f"generated change plan: cannot validate runtime plan: {exc}")
        finally:
            sys.path.pop(0)
    return errors


def _check_change_execution_gate(root: Path) -> list[str]:
    sys.path.insert(0, str(root))
    try:
        from netops_core import CHANGE_SCHEMA_VERSION
        from netops_core.change import (
            CHANGE_AUTHORIZATION_REQUIRED,
            apply_plan,
            rollback_plan,
        )
    finally:
        sys.path.pop(0)
    calls = (
        lambda: apply_plan(
            root / "missing-release-plan.json",
            {},
            authorized=False,
            confirmed_plan_id="not-a-plan",
            current_control_channel={},
        ),
        lambda: rollback_plan(
            root / "missing-release-plan.json",
            {},
            backup_dir="not-a-backup",
            authorized=False,
            confirmed_plan_id="not-a-plan",
            apply_receipt_path=root / "missing-release-receipt.json",
            current_control_channel={},
        ),
        lambda: apply_plan(
            root / "missing-release-plan.json",
            {},
            authorized="false",  # type: ignore[arg-type]
            confirmed_plan_id="not-a-plan",
            current_control_channel={},
        ),
        lambda: rollback_plan(
            root / "missing-release-plan.json",
            {},
            backup_dir="not-a-backup",
            authorized=1,  # type: ignore[arg-type]
            confirmed_plan_id="not-a-plan",
            apply_receipt_path=root / "missing-release-receipt.json",
            current_control_channel={},
        ),
    )
    errors: list[str] = []
    for name, function in (("apply", apply_plan), ("rollback", rollback_plan)):
        if "authorized" not in inspect.signature(function).parameters:
            errors.append(
                f"change {name}: public API must require an authorization parameter"
            )
    for label, callback in zip(
        ("apply", "rollback", "apply-non-bool", "rollback-non-bool"),
        calls,
        strict=True,
    ):
        try:
            callback()
        except PermissionError as exc:
            if str(exc) != CHANGE_AUTHORIZATION_REQUIRED:
                errors.append(f"change {label}: unexpected authorization error")
        except Exception as exc:
            errors.append(
                f"change {label}: authorization gate was reached too late ({type(exc).__name__})"
            )
        else:
            errors.append(f"change {label}: unauthorized execution was not rejected")
    try:
        spec_schema = _load_release_json(root / "schemas/change-spec.schema.json")
        plan_schema = _load_release_json(root / "schemas/change-plan.schema.json")
        spec_version = spec_schema["properties"]["schema_version"]["const"]
        plan_version = plan_schema["properties"]["schema_version"]["const"]
        execution_available = plan_schema["properties"]["control_channel_guard"][
            "properties"
        ]["execution_available"]["const"]
        execution_modes = set(
            plan_schema["properties"]["control_channel_guard"]["properties"][
                "execution_mode"
            ]["enum"]
        )
    except (KeyError, OSError, TypeError, UnicodeError, ValueError) as exc:
        errors.append(f"change schemas: cannot inspect execution contract: {exc}")
    else:
        if spec_version != CHANGE_SCHEMA_VERSION or plan_version != CHANGE_SCHEMA_VERSION:
            errors.append(
                "change schemas: runtime, spec, and plan schema versions must match"
            )
        if execution_available is not True:
            errors.append(
                "change plan schema: execution_available must match the released executor"
            )
        if execution_modes != {
            "direct-ssh-or-plan",
            "exact-plan",
            "manual-local-control-plane",
            "read-only",
        }:
            errors.append(
                "change plan schema: execution modes must match the control-channel policy"
            )
    return errors


def _check_monitor_execution_gate(root: Path) -> list[str]:
    sys.path.insert(0, str(root))
    try:
        import netops_core.monitor as monitor_module
    finally:
        sys.path.pop(0)

    errors: list[str] = []

    def expect_unavailable(label: str, callback) -> None:
        try:
            callback()
        except RuntimeError as exc:
            if "unavailable in this release" not in str(exc):
                errors.append(f"monitor {label}: unexpected fail-closed error")
        except Exception as exc:
            errors.append(
                f"monitor {label}: execution gate was reached too late "
                f"({type(exc).__name__})"
            )
        else:
            errors.append(f"monitor {label}: unreleased execution did not fail closed")

    if monitor_module.SCHEDULED_MONITOR_MUTATION_AVAILABLE is not False:
        errors.append("monitor mutation availability flag must remain false")
    for name in ("install_monitor", "remove_monitor"):
        if "authorized" in inspect.signature(getattr(monitor_module, name)).parameters:
            errors.append(f"monitor {name} must not expose an authorization parameter")

    with tempfile.TemporaryDirectory(prefix="netops-release-monitor-") as raw:
        isolated_root = Path(raw)
        real_paths = monitor_module._monitor_paths("user")
        isolated_paths = {
            key: isolated_root / f"{index:02d}-{key}"
            for index, key in enumerate(real_paths)
        }

        def command_was_called(*_args, **_kwargs):
            raise AssertionError("monitor release gate attempted to execute a command")

        try:
            with (
                patch.object(
                    monitor_module,
                    "_monitor_paths",
                    return_value=isolated_paths,
                ),
                patch.object(
                    monitor_module,
                    "run_command",
                    side_effect=command_was_called,
                ),
            ):
                plan = monitor_module.build_install_plan(
                    entry_script=root / "netopsctl",
                    target="example.test",
                    port=443,
                    protocol="tcp",
                    profile="server",
                    scope="user",
                )
                install_review = monitor_module.install_monitor(
                    plan,
                    dry_run=True,
                )
                if not (
                    install_review.get("dry_run") is True
                    and install_review.get("changed") is False
                    and install_review.get("execution_available") is False
                ):
                    errors.append("monitor install dry-run contract is invalid")

                removal_review = monitor_module.remove_monitor(
                    scope="user",
                    dry_run=True,
                )
                if not (
                    removal_review.get("dry_run") is True
                    and removal_review.get("execution_available") is False
                    and removal_review.get("commands_are_executable") is False
                ):
                    errors.append("monitor remove dry-run contract is invalid")

                status = monitor_module.monitor_status(scope="user")
                if status.get("scheduler") != {
                    "available": False,
                    "reason": "unreleased",
                }:
                    errors.append("monitor status must not query or imply scheduler state")

                expect_unavailable(
                    "install",
                    lambda: monitor_module.install_monitor(
                        {}, dry_run=False
                    ),
                )
                expect_unavailable(
                    "remove",
                    lambda: monitor_module.remove_monitor(
                        scope="user", dry_run=False
                    ),
                )
                expect_unavailable(
                    "private-install",
                    lambda: monitor_module._install_monitor_unreleased(
                        {}, authorized=True, dry_run=False
                    ),
                )
                expect_unavailable(
                    "private-remove",
                    lambda: monitor_module._remove_monitor_unreleased(
                        scope="invalid", authorized=True, dry_run=False
                    ),
                )
                expect_unavailable(
                    "private-status",
                    lambda: monitor_module._monitor_status_unreleased(scope="invalid"),
                )
                expect_unavailable(
                    "scheduler-command-sink",
                    lambda: monitor_module._run_scheduler_command(
                        ["systemctl", "disable", "--now", "netops-monitor.timer"],
                        timeout=1,
                    ),
                )
        except (AssertionError, OSError, PermissionError, RuntimeError, ValueError) as exc:
            errors.append(f"monitor release gate could not complete: {exc}")

        if any(isolated_root.iterdir()):
            errors.append("monitor release gate created filesystem state")
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run offline NetOps release integrity checks")
    parser.add_argument("root", nargs="?", default=".")
    parser.add_argument(
        "--require-jsonschema",
        action="store_true",
        help=(
            "Require jsonschema and validate all schemas plus their corresponding "
            "examples with Draft 2020-12"
        ),
    )
    args = parser.parse_args(argv)
    root = Path(args.root).resolve()
    errors = [
        *_load_json_documents(root),
        *_check_versions(root),
        *_check_packaging_contract(root),
        *_check_manifest_contract(root),
        *_check_ci_contract(root),
        *_check_example_contracts(root),
        *_check_change_execution_gate(root),
        *_check_monitor_execution_gate(root),
    ]
    if args.require_jsonschema:
        errors.extend(_check_json_schemas(root))
    previous_cache_prefix = sys.pycache_prefix
    with tempfile.TemporaryDirectory(prefix="netops-release-pycache-") as cache:
        sys.pycache_prefix = cache
        try:
            if not compileall.compile_dir(root / "netops_core", quiet=1):
                errors.append("netops_core: Python compilation failed")
            if not compileall.compile_dir(root / "scripts", quiet=1):
                errors.append("scripts: Python compilation failed")
        finally:
            sys.pycache_prefix = previous_cache_prefix
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    print(
        "release integrity: JSON, versions, packaging/manifest/CI, examples, change "
        "authorization and unreleased monitor gates, Python compilation"
        + (", and Draft 2020-12 schemas" if args.require_jsonschema else "")
        + " passed"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
