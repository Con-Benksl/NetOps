import contextlib
import io
import json
import os
import shlex
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path, PurePosixPath
from unittest.mock import patch

from scripts import sync_install_tree as sync_module
from scripts.sync_install_tree import (
    FLAT_TARGETS,
    TARGETS,
    SyncError,
    main,
    recover_install_tree,
    sync_install_tree,
)


def run_git(root: Path, *arguments: str) -> None:
    subprocess.run(
        ["git", "-C", str(root), *arguments],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
    )


def make_source(parent: Path) -> Path:
    root = parent / "source"
    root.mkdir()
    (root / "SKILL.md").write_text("root tracked\n", encoding="utf-8")
    (root / "root.txt").write_text("committed bytes\n", encoding="utf-8")
    for name in FLAT_TARGETS:
        child = root / "skills" / name
        agents = child / "agents"
        agents.mkdir(parents=True)
        (child / "SKILL.md").write_text(f"{name} committed\n", encoding="utf-8")
        (agents / "openai.yaml").write_text(
            f'name: "{name}"\n',
            encoding="utf-8",
        )
    run_git(root, "init")
    run_git(root, "config", "user.name", "NetOps Test")
    run_git(root, "config", "user.email", "netops-test@example.test")
    run_git(root, "add", ".")
    run_git(root, "commit", "-m", "tracked fixture")
    return root


def make_existing_install(parent: Path) -> Path:
    install = parent / "skills"
    install.mkdir()
    for name in TARGETS:
        target = install / name
        target.mkdir()
        (target / "old.txt").write_text(f"old {name}\n", encoding="utf-8")
    diagnostics = install / "netops" / "diagnostics"
    diagnostics.mkdir()
    (diagnostics / "private.json").write_text("preserve me\n", encoding="utf-8")
    return install


def dry_run_manifest(source: Path, install: Path) -> str:
    receipt = sync_install_tree(source, install)
    manifest = receipt["manifest_sha256"]
    if not isinstance(manifest, str):
        raise AssertionError("dry-run manifest must be a string")
    return manifest


def apply_confirmed(source: Path, install: Path) -> dict[str, object]:
    return sync_install_tree(
        source,
        install,
        apply=True,
        confirm_manifest_sha256=dry_run_manifest(source, install),
    )


class SyncInstallTreeTests(unittest.TestCase):
    def test_doctor_and_synchronizer_share_the_residue_contract(self):
        from scripts.check_install_tree import _residue_root

        samples = (
            ".cache/state",
            ".eggs/package",
            ".hypothesis/state",
            ".mypy_cache/state",
            ".nox/session",
            ".pytest_cache/state",
            ".ruff_cache/state",
            ".tox/session",
            ".venv/bin/python",
            "__pycache__/module.pyc",
            "build/output",
            "diagnostics/run.json",
            "dist/archive.whl",
            "htmlcov/index.html",
            "node_modules/package/index.js",
            "package.egg-info/PKG-INFO",
            "package.dist-info/METADATA",
            "archive.whl",
            "archive.egg",
            "archive.tar.gz",
            "archive.zip",
            ".coverage",
            ".coverage.worker",
            ".DS_Store",
            "module.pyc",
            "module.pyo",
            "references/clean.md",
        )
        for raw in samples:
            with self.subTest(path=raw):
                doctor_rejects = _residue_root(Path(raw)) is not None
                sync_rejects = sync_module._is_residue(PurePosixPath(raw))
                self.assertEqual(doctor_rejects, sync_rejects)

    def test_manifest_normalizes_windows_style_regular_file_modes(self):
        with tempfile.TemporaryDirectory() as raw:
            stage = Path(raw)
            for name in TARGETS:
                (stage / name).mkdir()
            member = stage / "netops" / "SKILL.md"
            member.write_text("tracked bytes\n", encoding="utf-8")
            member.chmod(0o666)
            payloads = {name: () for name in TARGETS}
            payloads["netops"] = (
                (PurePosixPath("SKILL.md"), PurePosixPath("SKILL.md")),
            )

            with patch.object(sync_module.os, "name", "nt"):
                manifest = sync_module._manifest_sha256(
                    stage,
                    stage.resolve(),
                    (stage / "installed").resolve(),
                    payloads,
                )

            self.assertEqual(len(manifest), 64)
            int(manifest, 16)

    def test_manifest_v2_binds_the_canonical_install_root(self):
        with tempfile.TemporaryDirectory() as raw:
            parent = Path(raw)
            source = make_source(parent)
            first_install = parent / "first-skills"
            second_install = parent / "second-skills"
            first_install.mkdir()
            second_install.mkdir()

            first = sync_install_tree(source, first_install)
            second = sync_install_tree(source, second_install)

            self.assertEqual(first["manifest_version"], 2)
            self.assertEqual(second["manifest_version"], 2)
            self.assertNotEqual(
                first["manifest_sha256"],
                second["manifest_sha256"],
            )

    def test_default_cli_mode_stages_current_tracked_bytes_without_installing(self):
        with tempfile.TemporaryDirectory() as raw:
            parent = Path(raw)
            source = make_source(parent)
            install = parent / "skills"
            install.mkdir()
            (source / "root.txt").write_text("dirty current bytes\n", encoding="utf-8")
            (source / "untracked.txt").write_text("exclude me\n", encoding="utf-8")
            (source / ".mypy_cache").mkdir()
            (source / ".mypy_cache" / "state").write_text("exclude\n", encoding="utf-8")

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                result = main([str(source), "--install-root", str(install)])

            self.assertEqual(result, 0)
            receipt = json.loads(output.getvalue())
            self.assertEqual(receipt["status"], "dry-run")
            self.assertEqual(receipt["manifest_version"], 2)
            self.assertEqual(receipt["managed_targets"], 6)
            self.assertIsNone(receipt["backup_path"])
            self.assertEqual(len(receipt["manifest_sha256"]), 64)
            int(receipt["manifest_sha256"], 16)
            self.assertFalse(any((install / name).exists() for name in TARGETS))

    def test_apply_requires_manifest_confirmation_before_any_live_move(self):
        with tempfile.TemporaryDirectory() as raw:
            parent = Path(raw)
            source = make_source(parent)
            install = make_existing_install(parent)

            with patch.object(sync_module, "_move_path") as move:
                with self.assertRaisesRegex(
                    SyncError,
                    "requires --confirm-manifest-sha256",
                ):
                    sync_install_tree(source, install, apply=True)

            move.assert_not_called()
            self.assertFalse((parent / "skill-backups").exists())

    def test_apply_rejects_manifest_mismatch_before_any_live_move(self):
        with tempfile.TemporaryDirectory() as raw:
            parent = Path(raw)
            source = make_source(parent)
            install = make_existing_install(parent)

            with patch.object(sync_module, "_move_path") as move:
                with self.assertRaisesRegex(
                    SyncError,
                    "staged manifest does not match",
                ):
                    sync_install_tree(
                        source,
                        install,
                        apply=True,
                        confirm_manifest_sha256="0" * 64,
                    )

            move.assert_not_called()
            self.assertFalse((parent / "skill-backups").exists())

    def test_apply_rejects_source_changed_since_dry_run(self):
        with tempfile.TemporaryDirectory() as raw:
            parent = Path(raw)
            source = make_source(parent)
            install = make_existing_install(parent)
            manifest = dry_run_manifest(source, install)
            (source / "root.txt").write_text("changed after review\n", encoding="utf-8")

            with patch.object(sync_module, "_move_path") as move:
                with self.assertRaisesRegex(
                    SyncError,
                    "staged manifest does not match",
                ):
                    sync_install_tree(
                        source,
                        install,
                        apply=True,
                        confirm_manifest_sha256=manifest,
                    )

            move.assert_not_called()
            self.assertFalse((parent / "skill-backups").exists())
            for name in TARGETS:
                self.assertTrue((install / name / "old.txt").is_file())

    def test_apply_installs_sanitized_root_and_flat_payloads_and_keeps_backup(self):
        with tempfile.TemporaryDirectory() as raw:
            parent = Path(raw)
            source = make_source(parent)
            install = make_existing_install(parent)
            (source / "root.txt").write_text("dirty current bytes\n", encoding="utf-8")
            build_skill = source / "skills" / "netops-build" / "SKILL.md"
            build_skill.write_text("netops-build dirty bytes\n", encoding="utf-8")
            (source / "diagnostics").mkdir()
            (source / "diagnostics" / "run.json").write_text(
                "untracked diagnostic\n", encoding="utf-8"
            )
            nested_residue = source / "skills" / "netops-build" / "diagnostics"
            nested_residue.mkdir()
            (nested_residue / "run.json").write_text(
                "untracked residue\n", encoding="utf-8"
            )
            untracked_cache = source / ".mypy_cache"
            untracked_cache.mkdir()
            (untracked_cache / "state").write_text(
                "untracked residue\n", encoding="utf-8"
            )

            receipt = apply_confirmed(source, install)

            self.assertEqual(receipt["status"], "applied")
            self.assertEqual(receipt["phase"], "complete")
            self.assertEqual(receipt["managed_targets"], 6)
            self.assertEqual(receipt["existing_targets"], 6)
            self.assertEqual(receipt["originally_existing"], list(TARGETS))
            self.assertEqual(receipt["backed_up"], list(TARGETS))
            self.assertEqual(receipt["installed"], list(TARGETS))
            backup = Path(str(receipt["backup_path"]))
            self.assertFalse(backup.is_relative_to(install))
            self.assertEqual(backup.parent, install.resolve().parent / "skill-backups")
            if os.name != "nt":
                self.assertEqual(stat.S_IMODE(backup.parent.stat().st_mode), 0o700)
                self.assertEqual(stat.S_IMODE(backup.stat().st_mode), 0o700)
                self.assertEqual(
                    stat.S_IMODE((backup / "sync-receipt.json").stat().st_mode),
                    0o600,
                )
            backup_receipt = json.loads(
                (backup / "sync-receipt.json").read_text(encoding="utf-8")
            )
            self.assertEqual(backup_receipt, receipt)
            self.assertEqual(backup_receipt["targets"], list(TARGETS))
            self.assertEqual(
                backup_receipt["target_file_counts"],
                receipt["target_file_counts"],
            )
            self.assertEqual(
                (backup / "netops" / "diagnostics" / "private.json").read_text(
                    encoding="utf-8"
                ),
                "preserve me\n",
            )
            self.assertEqual(
                (install / "netops" / "root.txt").read_text(encoding="utf-8"),
                "dirty current bytes\n",
            )
            self.assertEqual(
                (install / "netops-build" / "SKILL.md").read_text(encoding="utf-8"),
                "netops-build dirty bytes\n",
            )
            self.assertFalse((install / "netops" / "diagnostics").exists())
            self.assertFalse((install / "netops" / "untracked.txt").exists())
            self.assertFalse((install / "netops-build" / "diagnostics").exists())
            self.assertTrue(
                (install / "netops-build" / "agents" / "openai.yaml").is_file()
            )

    def test_in_progress_receipt_exists_before_first_live_move(self):
        with tempfile.TemporaryDirectory() as raw:
            parent = Path(raw)
            source = make_source(parent)
            install = make_existing_install(parent)
            manifest = dry_run_manifest(source, install)
            original_move = sync_module._move_path
            inspected = False

            def inspect_before_move(source_path: Path, destination_path: Path) -> None:
                nonlocal inspected
                if not inspected:
                    inspected = True
                    receipt_path = destination_path.parent / "sync-receipt.json"
                    self.assertTrue(receipt_path.is_file())
                    journal = json.loads(receipt_path.read_text(encoding="utf-8"))
                    self.assertEqual(journal["status"], "in-progress")
                    self.assertEqual(journal["phase"], "backup")
                    self.assertEqual(journal["originally_existing"], list(TARGETS))
                    self.assertEqual(journal["backed_up"], [])
                    self.assertEqual(journal["installed"], [])
                    self.assertTrue(Path(journal["stage_path"]).is_dir())
                    if os.name != "nt":
                        self.assertEqual(
                            stat.S_IMODE(receipt_path.stat().st_mode),
                            0o600,
                        )
                original_move(source_path, destination_path)

            with patch.object(
                sync_module,
                "_move_path",
                side_effect=inspect_before_move,
            ):
                receipt = sync_install_tree(
                    source,
                    install,
                    apply=True,
                    confirm_manifest_sha256=manifest,
                )

            self.assertTrue(inspected)
            self.assertEqual(receipt["status"], "applied")

    def test_transaction_receipt_updates_after_each_forward_move(self):
        with tempfile.TemporaryDirectory() as raw:
            parent = Path(raw)
            source = make_source(parent)
            install = make_existing_install(parent)
            manifest = dry_run_manifest(source, install)
            original_write = sync_module._write_backup_receipt
            snapshots: list[dict[str, object]] = []

            def record_receipt(
                backup_root: Path,
                receipt: dict[str, object],
            ) -> None:
                snapshots.append(json.loads(json.dumps(receipt)))
                original_write(backup_root, receipt)

            with patch.object(
                sync_module,
                "_write_backup_receipt",
                side_effect=record_receipt,
            ):
                result = sync_install_tree(
                    source,
                    install,
                    apply=True,
                    confirm_manifest_sha256=manifest,
                )

            backup_snapshots = [
                item
                for item in snapshots
                if item["status"] == "in-progress"
                and item["phase"] == "backup"
                and item["pending_move"] is None
            ]
            self.assertEqual(len(backup_snapshots), len(TARGETS) + 1)
            self.assertEqual(
                [item["backed_up"] for item in backup_snapshots],
                [list(TARGETS[:count]) for count in range(len(TARGETS) + 1)],
            )
            backup_pending = [
                item["pending_move"]
                for item in snapshots
                if item["status"] == "in-progress"
                and item["phase"] == "backup"
                and item["pending_move"] is not None
            ]
            self.assertEqual(
                backup_pending,
                [
                    {"target": name, "direction": "install-to-backup"}
                    for name in TARGETS
                ],
            )
            install_snapshots = [
                item
                for item in snapshots
                if item["status"] == "in-progress"
                and item["phase"] == "install"
                and item["pending_move"] is None
            ]
            self.assertEqual(len(install_snapshots), len(TARGETS) + 1)
            self.assertEqual(
                [item["installed"] for item in install_snapshots],
                [list(TARGETS[:count]) for count in range(len(TARGETS) + 1)],
            )
            install_pending = [
                item["pending_move"]
                for item in snapshots
                if item["status"] == "in-progress"
                and item["phase"] == "install"
                and item["pending_move"] is not None
            ]
            self.assertEqual(
                install_pending,
                [
                    {"target": name, "direction": "stage-to-install"}
                    for name in TARGETS
                ],
            )
            self.assertEqual(snapshots[-1]["status"], "applied")
            self.assertEqual(snapshots[-1]["phase"], "complete")
            self.assertEqual(result, snapshots[-1])

    def test_apply_failure_restores_every_original_target(self):
        with tempfile.TemporaryDirectory() as raw:
            parent = Path(raw)
            source = make_source(parent)
            install = make_existing_install(parent)
            original_move = sync_module._move_path
            calls = 0
            manifest = dry_run_manifest(source, install)

            def fail_once(source_path: Path, destination_path: Path) -> None:
                nonlocal calls
                calls += 1
                if calls == len(TARGETS) + 2:
                    raise OSError("injected install failure")
                original_move(source_path, destination_path)

            with patch.object(sync_module, "_move_path", side_effect=fail_once):
                with self.assertRaises(SyncError) as raised:
                    sync_install_tree(
                        source,
                        install,
                        apply=True,
                        confirm_manifest_sha256=manifest,
                    )

            error = raised.exception
            self.assertIsNotNone(error.backup_path)
            self.assertEqual(error.rollback_errors, ())
            self.assertIn("injected install failure", str(error))
            backup = Path(str(error.backup_path))
            self.assertTrue(backup.is_dir())
            failure_receipt = json.loads(
                (backup / "sync-receipt.json").read_text(encoding="utf-8")
            )
            self.assertEqual(failure_receipt["status"], "rolled-back")
            self.assertEqual(failure_receipt["phase"], "complete")
            self.assertEqual(failure_receipt["originally_existing"], list(TARGETS))
            self.assertEqual(failure_receipt["backed_up"], list(TARGETS))
            self.assertEqual(failure_receipt["installed"], [TARGETS[0]])
            self.assertTrue(failure_receipt["rollback_actions"])
            self.assertIn("injected install failure", failure_receipt["error"])
            if os.name != "nt":
                self.assertEqual(
                    stat.S_IMODE((backup / "sync-receipt.json").stat().st_mode),
                    0o600,
                )
            for name in TARGETS:
                self.assertEqual(
                    (install / name / "old.txt").read_text(encoding="utf-8"),
                    f"old {name}\n",
                )
            self.assertEqual(
                (install / "netops" / "diagnostics" / "private.json").read_text(
                    encoding="utf-8"
                ),
                "preserve me\n",
            )
            self.assertFalse((install / "netops" / "root.txt").exists())

    def test_keyboard_interrupt_and_system_exit_roll_back_before_stage_cleanup(self):
        for exception_type in (KeyboardInterrupt, SystemExit):
            with self.subTest(exception=exception_type.__name__), tempfile.TemporaryDirectory() as raw:
                parent = Path(raw)
                source = make_source(parent)
                install = make_existing_install(parent)
                manifest = dry_run_manifest(source, install)
                original_move = sync_module._move_path
                calls = 0

                def interrupt_once(source_path: Path, destination_path: Path) -> None:
                    nonlocal calls
                    calls += 1
                    if calls == 2:
                        raise exception_type("injected interruption")
                    original_move(source_path, destination_path)

                with patch.object(
                    sync_module,
                    "_move_path",
                    side_effect=interrupt_once,
                ):
                    with self.assertRaises(exception_type):
                        sync_install_tree(
                            source,
                            install,
                            apply=True,
                            confirm_manifest_sha256=manifest,
                        )

                for name in TARGETS:
                    self.assertEqual(
                        (install / name / "old.txt").read_text(encoding="utf-8"),
                        f"old {name}\n",
                    )
                self.assertEqual(
                    list(parent.glob("netops-install-stage-*")),
                    [],
                )
                backup_parent = parent / "skill-backups"
                self.assertEqual(
                    list(backup_parent.glob(f"{sync_module.LOCK_PREFIX}*")),
                    [],
                )

    def test_keyboard_interrupt_during_rollback_persists_recoverable_state(self):
        with tempfile.TemporaryDirectory() as raw:
            parent = Path(raw)
            source = make_source(parent)
            install = make_existing_install(parent)
            manifest = dry_run_manifest(source, install)
            original_move = sync_module._move_path
            calls = 0

            def fail_forward_then_interrupt_rollback(
                source_path: Path,
                destination_path: Path,
            ) -> None:
                nonlocal calls
                calls += 1
                if calls == 2:
                    raise OSError("injected forward failure")
                if calls == 3:
                    raise KeyboardInterrupt("injected rollback interruption")
                original_move(source_path, destination_path)

            with patch.object(
                sync_module,
                "_move_path",
                side_effect=fail_forward_then_interrupt_rollback,
            ):
                with self.assertRaises(KeyboardInterrupt):
                    sync_install_tree(
                        source,
                        install,
                        apply=True,
                        confirm_manifest_sha256=manifest,
                    )

            recovered = recover_install_tree(install)
            self.assertEqual(recovered["status"], "recovered")
            for name in TARGETS:
                self.assertEqual(
                    (install / name / "old.txt").read_text(encoding="utf-8"),
                    f"old {name}\n",
                )

    def test_keyboard_interrupt_during_failure_receipt_releases_guard(self):
        with tempfile.TemporaryDirectory() as raw:
            parent = Path(raw)
            source = make_source(parent)
            install = make_existing_install(parent)
            manifest = dry_run_manifest(source, install)
            original_move = sync_module._move_path
            original_write = sync_module._write_backup_receipt
            move_calls = 0
            interrupted = False

            def fail_forward_once(
                source_path: Path,
                destination_path: Path,
            ) -> None:
                nonlocal move_calls
                move_calls += 1
                if move_calls == 2:
                    raise OSError("injected forward failure")
                original_move(source_path, destination_path)

            def interrupt_final_failure_receipt(
                backup_root: Path,
                receipt: dict[str, object],
            ) -> None:
                nonlocal interrupted
                if not interrupted and receipt.get("status") == "rolled-back":
                    interrupted = True
                    raise KeyboardInterrupt("injected failure-receipt interruption")
                original_write(backup_root, receipt)

            with (
                patch.object(sync_module, "_move_path", side_effect=fail_forward_once),
                patch.object(
                    sync_module,
                    "_write_backup_receipt",
                    side_effect=interrupt_final_failure_receipt,
                ),
            ):
                with self.assertRaises(KeyboardInterrupt):
                    sync_install_tree(
                        source,
                        install,
                        apply=True,
                        confirm_manifest_sha256=manifest,
                    )

            self.assertTrue(interrupted)
            recovered = recover_install_tree(install)
            self.assertEqual(recovered["status"], "recovered")
            for name in TARGETS:
                self.assertEqual(
                    (install / name / "old.txt").read_text(encoding="utf-8"),
                    f"old {name}\n",
                )

    def test_recovery_hint_shell_quotes_paths(self):
        install = Path("/tmp/skills with spaces;$(touch nope)\nnext")
        receipt = Path("/tmp/receipt with spaces;&|<>^%`touch nope`.json")
        arguments = [
            sys.executable or "python3",
            str(Path(sync_module.__file__).resolve()),
            "--install-root",
            str(install),
            "--recover",
            "--recovery-receipt",
            str(receipt),
        ]
        hint = sync_module._recover_hint(install, receipt)
        if os.name == "nt":
            self.assertEqual(json.loads(hint.removeprefix("argv: ")), arguments)
        else:
            self.assertEqual(hint, shlex.join(arguments))
            self.assertEqual(shlex.split(hint), arguments)

    def test_post_apply_stage_cleanup_error_releases_guard_for_recovery(self):
        with tempfile.TemporaryDirectory() as raw:
            parent = Path(raw)
            source = make_source(parent)
            install = make_existing_install(parent)
            manifest = dry_run_manifest(source, install)

            with patch.object(
                sync_module.shutil,
                "rmtree",
                side_effect=PermissionError("injected cleanup denial"),
            ):
                with self.assertRaisesRegex(
                    SyncError,
                    "stage cleanup failed",
                ) as raised:
                    sync_install_tree(
                        source,
                        install,
                        apply=True,
                        confirm_manifest_sha256=manifest,
                    )

            self.assertTrue(raised.exception.preserve_stage)
            recovered = recover_install_tree(install)
            self.assertEqual(recovered["status"], "applied")
            self.assertEqual(recovered["recovery_status"], "already-complete")
            self.assertTrue((install / "netops" / "root.txt").is_file())

    @unittest.skipIf(os.name == "nt", "directory fsync is a POSIX durability gate")
    def test_rename_parent_fsync_failure_uses_actual_topology_for_rollback(self):
        with tempfile.TemporaryDirectory() as raw:
            parent = Path(raw)
            source = make_source(parent)
            install = make_existing_install(parent)
            manifest = dry_run_manifest(source, install)
            original_fsync_directory = sync_module._fsync_directory
            failed = False

            def fail_after_first_live_rename(path: Path) -> None:
                nonlocal failed
                if path == install.resolve() and not failed:
                    failed = True
                    raise SyncError("injected parent fsync failure")
                original_fsync_directory(path)

            with patch.object(
                sync_module,
                "_fsync_directory",
                side_effect=fail_after_first_live_rename,
            ):
                with self.assertRaisesRegex(
                    SyncError,
                    "injected parent fsync failure",
                ):
                    sync_install_tree(
                        source,
                        install,
                        apply=True,
                        confirm_manifest_sha256=manifest,
                    )

            self.assertTrue(failed)
            for name in TARGETS:
                self.assertEqual(
                    (install / name / "old.txt").read_text(encoding="utf-8"),
                    f"old {name}\n",
                )

    def test_concurrent_live_replacement_is_put_back_if_rename_wins_race(self):
        with tempfile.TemporaryDirectory() as raw:
            parent = Path(raw)
            source = make_source(parent)
            install = make_existing_install(parent)
            manifest = dry_run_manifest(source, install)
            original_move = sync_module._move_path
            displaced_original = parent / "externally-displaced-netops"
            raced = False

            def replace_between_identity_check_and_rename(
                source_path: Path,
                destination_path: Path,
            ) -> None:
                nonlocal raced
                if not raced and source_path == install.resolve() / TARGETS[0]:
                    os.replace(source_path, displaced_original)
                    source_path.mkdir()
                    (source_path / "external.txt").write_text(
                        "external replacement\n",
                        encoding="utf-8",
                    )
                    raced = True
                original_move(source_path, destination_path)

            with patch.object(
                sync_module,
                "_move_path",
                side_effect=replace_between_identity_check_and_rename,
            ):
                with self.assertRaises(SyncError) as raised:
                    sync_install_tree(
                        source,
                        install,
                        apply=True,
                        confirm_manifest_sha256=manifest,
                    )

            self.assertTrue(raced)
            self.assertTrue(raised.exception.rollback_errors)
            self.assertEqual(
                (install / TARGETS[0] / "external.txt").read_text(encoding="utf-8"),
                "external replacement\n",
            )
            self.assertEqual(
                (displaced_original / "old.txt").read_text(encoding="utf-8"),
                f"old {TARGETS[0]}\n",
            )

    def test_recovery_retains_pending_move_after_concurrent_rollback_interrupt(self):
        with tempfile.TemporaryDirectory() as raw:
            parent = Path(raw)
            source = make_source(parent)
            install = make_existing_install(parent)
            manifest = dry_run_manifest(source, install)
            original_move = sync_module._move_path
            displaced_original = parent / "externally-displaced-netops"
            calls = 0

            def race_then_interrupt_compensation(
                source_path: Path,
                destination_path: Path,
            ) -> None:
                nonlocal calls
                calls += 1
                if calls == 1:
                    os.replace(source_path, displaced_original)
                    source_path.mkdir()
                    (source_path / "external.txt").write_text(
                        "external replacement\n",
                        encoding="utf-8",
                    )
                    original_move(source_path, destination_path)
                    return
                if calls == 2:
                    raise KeyboardInterrupt("interrupt concurrent compensation")
                original_move(source_path, destination_path)

            with patch.object(
                sync_module,
                "_move_path",
                side_effect=race_then_interrupt_compensation,
            ):
                with self.assertRaises(KeyboardInterrupt):
                    sync_install_tree(
                        source,
                        install,
                        apply=True,
                        confirm_manifest_sha256=manifest,
                    )

            with self.assertRaises(SyncError):
                recover_install_tree(install)
            self.assertEqual(
                (install / TARGETS[0] / "external.txt").read_text(encoding="utf-8"),
                "external replacement\n",
            )

    def test_dry_run_needs_no_lock_and_apply_fails_closed_without_lock_primitive(self):
        with tempfile.TemporaryDirectory() as raw:
            parent = Path(raw)
            source = make_source(parent)
            install = make_existing_install(parent)

            with patch.object(sync_module, "fcntl", None), patch.object(
                sync_module,
                "msvcrt",
                None,
            ):
                manifest = dry_run_manifest(source, install)
                with patch.object(sync_module, "_move_path") as move:
                    with self.assertRaisesRegex(
                        SyncError,
                        "no supported inter-process file lock",
                    ):
                        sync_install_tree(
                            source,
                            install,
                            apply=True,
                            confirm_manifest_sha256=manifest,
                        )

            move.assert_not_called()
            self.assertEqual(list(parent.glob("netops-install-stage-*")), [])

    def test_apply_fails_before_move_without_stable_directory_identities(self):
        with tempfile.TemporaryDirectory() as raw:
            parent = Path(raw)
            source = make_source(parent)
            install = make_existing_install(parent)
            manifest = dry_run_manifest(source, install)
            original_lstat = Path.lstat

            def zero_stage_inode(path: Path):
                info = original_lstat(path)
                if path.name.startswith("netops-install-stage-"):
                    fields = list(info)
                    fields[1] = 0
                    return os.stat_result(fields)
                return info

            with patch.object(Path, "lstat", zero_stage_inode), patch.object(
                sync_module,
                "_move_path",
            ) as move:
                with self.assertRaisesRegex(
                    SyncError,
                    "without stable directory identities",
                ):
                    sync_install_tree(
                        source,
                        install,
                        apply=True,
                        confirm_manifest_sha256=manifest,
                    )

            move.assert_not_called()

    @unittest.skipIf(sync_module.fcntl is None, "POSIX flock is required")
    def test_guard_serializes_apply_and_existing_lock_does_not_orphan_new_stage(self):
        with tempfile.TemporaryDirectory() as raw:
            parent = Path(raw)
            source = make_source(parent)
            install = make_existing_install(parent)
            manifest = dry_run_manifest(source, install)
            backup_parent = sync_module._prepare_backup_parent(install.resolve())
            held_stage = parent / "held-stage"
            held_stage.mkdir()
            for name in TARGETS:
                (held_stage / name).mkdir()
            lock_path, guard, _ = sync_module._acquire_apply_lock(
                backup_parent,
                install.resolve(),
                held_stage,
            )
            try:
                with self.assertRaisesRegex(SyncError, "held by another process"):
                    sync_module._open_lock_guard(backup_parent, install.resolve())
                with self.assertRaisesRegex(SyncError, "held by another process"):
                    sync_install_tree(
                        source,
                        install,
                        apply=True,
                        confirm_manifest_sha256=manifest,
                    )
                self.assertEqual(list(parent.glob("netops-install-stage-*")), [])
            finally:
                guard.release(lock_path)

    def test_hard_crash_receipt_recovers_idempotently_via_cli_and_api(self):
        with tempfile.TemporaryDirectory() as raw:
            parent = Path(raw)
            source = make_source(parent)
            install = make_existing_install(parent)
            manifest = dry_run_manifest(source, install)
            repository = Path(__file__).resolve().parents[1]
            child_code = f"""
import os
from pathlib import Path
from scripts import sync_install_tree as module

source = Path({str(source)!r})
install = Path({str(install)!r})
manifest = {manifest!r}
original_move = module._move_path
calls = 0

def crash_after_move(source_path, destination_path):
    global calls
    calls += 1
    original_move(source_path, destination_path)
    if calls == len(module.TARGETS) + 1:
        os._exit(91)

module._move_path = crash_after_move
module.sync_install_tree(
    source,
    install,
    apply=True,
    confirm_manifest_sha256=manifest,
)
"""
            environment = dict(os.environ)
            environment["PYTHONDONTWRITEBYTECODE"] = "1"
            crashed = subprocess.run(
                [sys.executable, "-c", child_code],
                cwd=repository,
                env=environment,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            self.assertEqual(
                crashed.returncode,
                91,
                msg=crashed.stdout + crashed.stderr,
            )

            backup_parent = parent / "skill-backups"
            receipts = list(
                backup_parent.glob(f"netops-install-*/{sync_module.RECEIPT_NAME}")
            )
            self.assertEqual(len(receipts), 1)
            receipt_path = receipts[0]
            interrupted = json.loads(receipt_path.read_text(encoding="utf-8"))
            self.assertEqual(interrupted["status"], "in-progress")
            self.assertEqual(
                interrupted["pending_move"],
                {"target": TARGETS[0], "direction": "stage-to-install"},
            )

            stage_path = Path(interrupted["stage_path"])
            held_stage = stage_path.with_name(f"{stage_path.name}-held")
            os.replace(stage_path, held_stage)
            stage_path.mkdir()
            replacement_marker = stage_path / "do-not-delete.txt"
            replacement_marker.write_text("foreign stage\n", encoding="utf-8")
            with patch.object(sync_module, "_move_path") as recovery_move:
                with self.assertRaisesRegex(
                    SyncError,
                    "stage root identity does not match",
                ):
                    recover_install_tree(install)
            recovery_move.assert_not_called()
            self.assertEqual(
                replacement_marker.read_text(encoding="utf-8"),
                "foreign stage\n",
            )
            replacement_marker.unlink()
            stage_path.rmdir()
            os.replace(held_stage, stage_path)

            historical_root = backup_parent / "netops-install-historical"
            historical_root.mkdir(mode=0o700)
            historical_receipt_path = historical_root / sync_module.RECEIPT_NAME
            historical = {
                **interrupted,
                "status": "applied",
                "phase": "complete",
                "backup_path": str(historical_root.resolve()),
            }
            historical_receipt_path.write_text(
                json.dumps(historical),
                encoding="utf-8",
            )
            historical_receipt_path.chmod(0o600)
            with patch.object(sync_module, "_move_path") as recovery_move:
                with self.assertRaisesRegex(
                    SyncError,
                    "does not match the transaction lock receipt",
                ):
                    recover_install_tree(
                        install,
                        receipt=historical_receipt_path,
                    )
            recovery_move.assert_not_called()

            with self.assertRaisesRegex(SyncError, "run recovery first"):
                sync_install_tree(
                    source,
                    install,
                    apply=True,
                    confirm_manifest_sha256=manifest,
                )

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                result = main(["--install-root", str(install), "--recover"])
            self.assertEqual(result, 0)
            recovered = json.loads(output.getvalue())
            self.assertEqual(recovered["status"], "recovered")
            for name in TARGETS:
                self.assertEqual(
                    (install / name / "old.txt").read_text(encoding="utf-8"),
                    f"old {name}\n",
                )
            self.assertEqual(list(parent.glob("netops-install-stage-*")), [])
            self.assertEqual(
                list(backup_parent.glob(f"{sync_module.LOCK_PREFIX}*")),
                [],
            )

            second = recover_install_tree(install, receipt=receipt_path)
            self.assertEqual(second["recovery_status"], "already-complete")

    def test_tracked_residue_fails_closed_instead_of_being_filtered(self):
        with tempfile.TemporaryDirectory() as raw:
            parent = Path(raw)
            source = make_source(parent)
            install = make_existing_install(parent)
            diagnostics = source / "diagnostics"
            diagnostics.mkdir()
            (diagnostics / "run.json").write_text("tracked\n", encoding="utf-8")
            run_git(source, "add", "diagnostics/run.json")
            run_git(source, "commit", "-m", "tracked residue fixture")

            with self.assertRaisesRegex(SyncError, "tracked install residue"):
                sync_install_tree(source, install)

            self.assertFalse((parent / "skill-backups").exists())
            for name in TARGETS:
                self.assertTrue((install / name / "old.txt").is_file())

    def test_tracked_packaging_and_coverage_residue_fail_closed(self):
        for relative in (
            ".eggs/state",
            "package.dist-info/METADATA",
            "archive.whl",
            "archive.egg",
            "archive.tar.gz",
            "archive.zip",
            ".coverage",
            ".coverage.worker",
        ):
            with self.subTest(relative=relative), tempfile.TemporaryDirectory() as raw:
                parent = Path(raw)
                source = make_source(parent)
                install = make_existing_install(parent)
                residue = source / relative
                residue.parent.mkdir(parents=True, exist_ok=True)
                residue.write_text("tracked residue\n", encoding="utf-8")
                run_git(source, "add", relative)
                run_git(source, "commit", "-m", "tracked residue fixture")

                with self.assertRaisesRegex(SyncError, "tracked install residue"):
                    sync_install_tree(source, install)

    def test_atomic_source_replace_during_copy_fails_staging(self):
        with tempfile.TemporaryDirectory() as raw:
            parent = Path(raw)
            source = make_source(parent)
            install = make_existing_install(parent)
            tracked = source / "root.txt"
            tracked_inode = tracked.lstat().st_ino
            original_copy = sync_module.shutil.copyfileobj
            replaced = False

            def replace_after_copy(input_stream, output_stream, length=0):
                nonlocal replaced
                original_copy(input_stream, output_stream, length)
                if (
                    not replaced
                    and os.fstat(input_stream.fileno()).st_ino == tracked_inode
                ):
                    replacement = source / ".root.txt.replacement"
                    replacement.write_bytes(tracked.read_bytes())
                    os.replace(replacement, tracked)
                    replaced = True

            with patch.object(
                sync_module.shutil,
                "copyfileobj",
                side_effect=replace_after_copy,
            ):
                with self.assertRaisesRegex(
                    SyncError,
                    "source path changed while staging",
                ):
                    sync_install_tree(source, install)

            self.assertTrue(replaced)
            self.assertFalse((parent / "skill-backups").exists())

    @unittest.skipIf(os.name == "nt", "POSIX executable mode semantics are required")
    def test_source_executable_mode_change_during_copy_fails_staging(self):
        with tempfile.TemporaryDirectory() as raw:
            parent = Path(raw)
            source = make_source(parent)
            install = make_existing_install(parent)
            tracked = source / "root.txt"
            tracked_inode = tracked.lstat().st_ino
            original_copy = sync_module.shutil.copyfileobj
            changed = False

            def chmod_after_copy(input_stream, output_stream, length=0):
                nonlocal changed
                original_copy(input_stream, output_stream, length)
                if (
                    not changed
                    and os.fstat(input_stream.fileno()).st_ino == tracked_inode
                ):
                    tracked.chmod(0o755)
                    changed = True

            with patch.object(
                sync_module.shutil,
                "copyfileobj",
                side_effect=chmod_after_copy,
            ):
                with self.assertRaisesRegex(
                    SyncError,
                    "executable mode changed while staging",
                ):
                    sync_install_tree(source, install)

            self.assertTrue(changed)
            self.assertFalse((parent / "skill-backups").exists())

    def test_pre_live_check_rejects_source_changed_after_staging(self):
        with tempfile.TemporaryDirectory() as raw:
            parent = Path(raw)
            source = make_source(parent)
            install = make_existing_install(parent)
            manifest = dry_run_manifest(source, install)
            tracked = source / "SKILL.md"
            original_verify = sync_module._verify_source_payload_stable
            verification_calls = 0

            def mutate_after_first_verification(*args, **kwargs):
                nonlocal verification_calls
                original_verify(*args, **kwargs)
                verification_calls += 1
                if verification_calls == 1:
                    tracked.write_text("changed after staging\n", encoding="utf-8")

            with patch.object(
                sync_module,
                "_verify_source_payload_stable",
                side_effect=mutate_after_first_verification,
            ), patch.object(sync_module, "_move_path") as move:
                with self.assertRaisesRegex(
                    SyncError,
                    "changed after staging",
                ):
                    sync_install_tree(
                        source,
                        install,
                        apply=True,
                        confirm_manifest_sha256=manifest,
                    )

            self.assertEqual(verification_calls, 1)
            move.assert_not_called()
            for name in TARGETS:
                self.assertTrue((install / name / "old.txt").is_file())

    def test_pre_live_manifest_rejects_changed_flat_staged_payload(self):
        with tempfile.TemporaryDirectory() as raw:
            parent = Path(raw)
            source = make_source(parent)
            install = make_existing_install(parent)
            manifest = dry_run_manifest(source, install)
            original_verify = sync_module._verify_source_payload_stable
            verification_calls = 0

            def mutate_flat_stage_after_source_check(
                source_root,
                stage_root,
                tracked,
                snapshots,
            ):
                nonlocal verification_calls
                original_verify(source_root, stage_root, tracked, snapshots)
                verification_calls += 1
                if verification_calls == 2:
                    (stage_root / "netops-build" / "SKILL.md").write_text(
                        "mutated flat stage\n",
                        encoding="utf-8",
                    )

            with patch.object(
                sync_module,
                "_verify_source_payload_stable",
                side_effect=mutate_flat_stage_after_source_check,
            ), patch.object(sync_module, "_move_path") as move:
                with self.assertRaisesRegex(
                    SyncError,
                    "staged payload changed after manifest confirmation",
                ):
                    sync_install_tree(
                        source,
                        install,
                        apply=True,
                        confirm_manifest_sha256=manifest,
                    )

            self.assertEqual(verification_calls, 2)
            move.assert_not_called()

    def test_msvcrt_style_lock_fallback_locks_and_unlocks_one_byte(self):
        class FakeMsvcrt:
            LK_NBLCK = 1
            LK_UNLCK = 2

            def __init__(self):
                self.calls = []

            def locking(self, descriptor, operation, size):
                self.calls.append((operation, size))

        with tempfile.TemporaryDirectory() as raw:
            parent = Path(raw)
            install = parent / "skills"
            install.mkdir()
            backup_parent = sync_module._prepare_backup_parent(install.resolve())
            fallback = FakeMsvcrt()
            with patch.object(sync_module, "fcntl", None), patch.object(
                sync_module,
                "msvcrt",
                fallback,
            ):
                descriptor = sync_module._open_lock_guard(
                    backup_parent,
                    install.resolve(),
                )
                sync_module._close_lock_guard(descriptor)

            self.assertEqual(
                fallback.calls,
                [(fallback.LK_NBLCK, 1), (fallback.LK_UNLCK, 1)],
            )

    def test_recovery_cleans_identity_bound_stage_before_first_receipt(self):
        with tempfile.TemporaryDirectory() as raw:
            parent = Path(raw)
            source = make_source(parent).resolve()
            install = make_existing_install(parent).resolve()
            payloads, tracked = sync_module._payloads(source)
            snapshots = sync_module._snapshot_source_payload(source, tracked)
            stage = Path(
                tempfile.mkdtemp(
                    prefix="netops-install-stage-",
                    dir=install.parent,
                )
            )
            stage.chmod(0o700)
            sync_module._stage_payloads(
                source,
                stage,
                payloads,
                snapshots,
            )
            backup_parent = sync_module._prepare_backup_parent(install)
            lock_path, guard, lock = sync_module._acquire_apply_lock(
                backup_parent,
                install,
                stage,
            )
            stale_backup = backup_parent / "netops-install-stale-before-receipt"
            stale_backup.mkdir(mode=0o700)
            lock["backup_path"] = str(stale_backup)
            lock["backup_root_id"] = list(
                sync_module._directory_identity(
                    stale_backup,
                    label="stale backup root",
                )
            )
            sync_module._write_lock_info(lock_path, lock)
            receipt_temporary = stale_backup / ".sync-receipt.json-crash.tmp"
            receipt_temporary.write_text("partial", encoding="utf-8")
            receipt_temporary.chmod(0o600)
            guard.close()

            result = recover_install_tree(install)

            self.assertEqual(result["status"], "stale-lock-cleared")
            self.assertFalse(stage.exists())
            self.assertFalse(stale_backup.exists())
            self.assertFalse(lock_path.exists())

    def test_corrupt_lock_json_does_not_leak_the_parent_guard(self):
        with tempfile.TemporaryDirectory() as raw:
            parent = Path(raw)
            install = make_existing_install(parent).resolve()
            backup_parent = sync_module._prepare_backup_parent(install)
            lock_path = sync_module._lock_path(backup_parent, install)
            lock_path.mkdir(mode=0o700)
            lock_info = lock_path / sync_module.LOCK_INFO_NAME
            lock_info.write_text("{not-json", encoding="utf-8")
            lock_info.chmod(0o600)

            with self.assertRaisesRegex(SyncError, "not valid JSON"):
                recover_install_tree(install)

            descriptor = sync_module._open_lock_guard(backup_parent, install)
            sync_module._close_lock_guard(descriptor)

    def test_recovery_clears_crashed_initial_lock_temporary_file(self):
        with tempfile.TemporaryDirectory() as raw:
            parent = Path(raw)
            install = make_existing_install(parent).resolve()
            backup_parent = sync_module._prepare_backup_parent(install)
            lock_path = sync_module._lock_path(backup_parent, install)
            lock_path.mkdir(mode=0o700)
            temporary = lock_path / ".lock.json-crash.tmp"
            temporary.write_text("partial", encoding="utf-8")
            temporary.chmod(0o600)

            result = recover_install_tree(install)

            self.assertEqual(result["status"], "stale-lock-cleared")
            self.assertFalse(lock_path.exists())

    def test_final_source_sweep_catches_early_file_changed_while_checking_later_file(self):
        with tempfile.TemporaryDirectory() as raw:
            parent = Path(raw)
            source = make_source(parent)
            install = make_existing_install(parent)
            tracked = sync_module._tracked_files(source.resolve())
            early = source / Path(*tracked[0].parts)
            later = tracked[-1].as_posix()
            original_open = sync_module._open_regular_no_follow
            changed = False

            def change_early_during_late_check(path: Path, *, label: str):
                nonlocal changed
                result = original_open(path, label=label)
                if (
                    not changed
                    and label == "staged source copy"
                    and path.as_posix().endswith(f"/netops/{later}")
                ):
                    early.write_text("changed during late check\n", encoding="utf-8")
                    changed = True
                return result

            with patch.object(
                sync_module,
                "_open_regular_no_follow",
                side_effect=change_early_during_late_check,
            ):
                with self.assertRaisesRegex(
                    SyncError,
                    "final source sweep",
                ):
                    sync_install_tree(source, install)

            self.assertTrue(changed)
            self.assertFalse((parent / "skill-backups").exists())

    @unittest.skipIf(os.name == "nt", "directory fsync is a POSIX durability gate")
    def test_receipt_replace_fsyncs_backup_directory(self):
        with tempfile.TemporaryDirectory() as raw:
            backup = Path(raw) / "backup"
            backup.mkdir(mode=0o700)
            original_fsync = sync_module.os.fsync
            fsynced_directories: list[bool] = []

            def record_fsync(descriptor: int) -> None:
                fsynced_directories.append(
                    stat.S_ISDIR(os.fstat(descriptor).st_mode)
                )
                original_fsync(descriptor)

            with patch.object(
                sync_module.os,
                "fsync",
                side_effect=record_fsync,
            ):
                sync_module._write_backup_receipt(
                    backup,
                    {"status": "in-progress", "phase": "backup"},
                )

            self.assertIn(True, fsynced_directories)

    @unittest.skipIf(os.name == "nt", "directory symlink creation needs privileges")
    def test_preflight_rejects_symlink_target(self):
        with tempfile.TemporaryDirectory() as raw:
            parent = Path(raw)
            source = make_source(parent)
            install = parent / "skills"
            install.mkdir()
            outside = parent / "outside"
            outside.mkdir()
            (install / "netops").symlink_to(outside, target_is_directory=True)

            with self.assertRaisesRegex(SyncError, "must not be a symlink"):
                sync_install_tree(source, install)
            self.assertEqual(list(outside.iterdir()), [])

    def test_preflight_rejects_non_directory_target(self):
        with tempfile.TemporaryDirectory() as raw:
            parent = Path(raw)
            source = make_source(parent)
            install = parent / "skills"
            install.mkdir()
            (install / "netops").write_text("not a directory\n", encoding="utf-8")
            with self.assertRaisesRegex(SyncError, "must be a directory"):
                sync_install_tree(source, install)

    @unittest.skipIf(os.name == "nt", "directory symlink creation needs privileges")
    def test_apply_rejects_symlink_backup_parent(self):
        with tempfile.TemporaryDirectory() as raw:
            parent = Path(raw)
            source = make_source(parent)
            install = make_existing_install(parent)
            outside = parent / "outside-backups"
            outside.mkdir()
            (parent / "skill-backups").symlink_to(outside, target_is_directory=True)
            manifest = dry_run_manifest(source, install)

            with self.assertRaisesRegex(
                SyncError,
                "backup parent must not be a symlink",
            ):
                sync_install_tree(
                    source,
                    install,
                    apply=True,
                    confirm_manifest_sha256=manifest,
                )
            self.assertEqual(list(outside.iterdir()), [])
            for name in TARGETS:
                self.assertTrue((install / name / "old.txt").is_file())

    def test_apply_rejects_non_directory_backup_parent(self):
        with tempfile.TemporaryDirectory() as raw:
            parent = Path(raw)
            source = make_source(parent)
            install = make_existing_install(parent)
            (parent / "skill-backups").write_text("not a directory\n", encoding="utf-8")
            manifest = dry_run_manifest(source, install)

            with self.assertRaisesRegex(SyncError, "backup parent must be a directory"):
                sync_install_tree(
                    source,
                    install,
                    apply=True,
                    confirm_manifest_sha256=manifest,
                )
            for name in TARGETS:
                self.assertTrue((install / name / "old.txt").is_file())

    @unittest.skipIf(os.name == "nt", "POSIX directory modes are not enforced")
    def test_apply_rejects_backup_parent_with_broad_permissions(self):
        with tempfile.TemporaryDirectory() as raw:
            parent = Path(raw)
            source = make_source(parent)
            install = make_existing_install(parent)
            backup_parent = install.resolve().parent / "skill-backups"
            backup_parent.mkdir(mode=0o755)
            backup_parent.chmod(0o755)
            manifest = dry_run_manifest(source, install)

            with self.assertRaisesRegex(SyncError, "mode 0700"):
                sync_install_tree(
                    source,
                    install,
                    apply=True,
                    confirm_manifest_sha256=manifest,
                )
            for name in TARGETS:
                self.assertTrue((install / name / "old.txt").is_file())

    def test_apply_rejects_backup_parent_on_another_device(self):
        with tempfile.TemporaryDirectory() as raw:
            parent = Path(raw)
            source = make_source(parent)
            install = make_existing_install(parent)
            backup_parent = install.resolve().parent / "skill-backups"
            original_lstat = Path.lstat
            manifest = dry_run_manifest(source, install)

            def different_device(path: Path):
                info = original_lstat(path)
                if path == backup_parent:
                    fields = list(info)
                    fields[2] = info.st_dev + 1
                    return os.stat_result(fields)
                return info

            with patch.object(Path, "lstat", different_device):
                with self.assertRaisesRegex(SyncError, "same device"):
                    sync_install_tree(
                        source,
                        install,
                        apply=True,
                        confirm_manifest_sha256=manifest,
                    )
            for name in TARGETS:
                self.assertTrue((install / name / "old.txt").is_file())

    @unittest.skipIf(os.name == "nt", "tracked symlink semantics differ on Windows")
    def test_tracked_source_symlink_is_rejected_instead_of_followed(self):
        with tempfile.TemporaryDirectory() as raw:
            parent = Path(raw)
            source = make_source(parent)
            install = parent / "skills"
            install.mkdir()
            outside = parent / "outside.txt"
            outside.write_text("outside\n", encoding="utf-8")
            link = source / "tracked-link"
            link.symlink_to(outside)
            run_git(source, "add", "tracked-link")
            run_git(source, "commit", "-m", "track symlink")

            with self.assertRaisesRegex(SyncError, "must be a regular file"):
                sync_install_tree(source, install)


if __name__ == "__main__":
    unittest.main()
