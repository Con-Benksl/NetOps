#!/usr/bin/env python3
"""Build and transactionally install a sanitized NetOps Skill tree.

Only regular files tracked by Git are staged.  Their current working-tree bytes
are copied, so reviewed dirty edits are included while untracked files are
excluded.  Tracked diagnostics, caches, and other residue fail closed instead
of being silently omitted.  The default dry run emits a content manifest that
an apply must confirm.  Apply progress is journalled before and after live
directory moves so an interrupted transaction can be reconstructed.
"""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import hmac
import json
import os
import secrets
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
from collections.abc import Callable
from pathlib import Path, PurePosixPath

try:
    import fcntl
except ImportError:  # pragma: no cover - Windows fallback
    fcntl = None  # type: ignore[assignment]

try:
    import msvcrt
except ImportError:  # pragma: no cover - POSIX
    msvcrt = None  # type: ignore[assignment]


ROOT_TARGET = "netops"
FLAT_TARGETS = (
    "netops-build",
    "netops-fix",
    "netops-manage",
    "netops-scan",
    "netops-start",
)
TARGETS = (ROOT_TARGET, *FLAT_TARGETS)
GIT_TIMEOUT = 30
BACKUP_PARENT_NAME = "skill-backups"
RECEIPT_NAME = "sync-receipt.json"
LOCK_INFO_NAME = "lock.json"
LOCK_PREFIX = ".netops-install-lock-"
LOCK_GUARD_PREFIX = ".netops-install-guard-"
MAX_JOURNAL_BYTES = 1024 * 1024
INCOMPLETE_STATUSES = {"in-progress", "rollback-incomplete"}
FINAL_STATUSES = {"applied", "recovered", "rolled-back"}
KNOWN_RECEIPT_STATUSES = INCOMPLETE_STATUSES | FINAL_STATUSES
RESIDUE_DIRECTORIES = {
    ".cache",
    ".eggs",
    ".hypothesis",
    ".mypy_cache",
    ".nox",
    ".pytest_cache",
    ".ruff_cache",
    ".tox",
    ".venv",
    "__pycache__",
    "build",
    "diagnostics",
    "dist",
    "htmlcov",
    "node_modules",
}
RESIDUE_FILE_NAMES = {".DS_Store", ".coverage"}
RESIDUE_FILE_SUFFIXES = {".pyc", ".pyo"}
RESIDUE_FILE_GLOBS = (
    "*.egg",
    "*.tar.gz",
    "*.whl",
    "*.zip",
    ".coverage.*",
)
RESIDUE_COMPONENT_GLOBS = ("*.egg-info", "*.dist-info")
SourceSignature = tuple[int, int, int, int, int, int]


class SyncError(RuntimeError):
    def __init__(
        self,
        message: str,
        *,
        backup_path: Path | None = None,
        rollback_errors: tuple[str, ...] = (),
        preserve_stage: bool = False,
    ) -> None:
        super().__init__(message)
        self.backup_path = backup_path
        self.rollback_errors = rollback_errors
        self.preserve_stage = preserve_stage


class _GuardLease:
    def __init__(self, descriptor: int) -> None:
        self.descriptor = descriptor

    def close(self) -> None:
        if self.descriptor >= 0:
            descriptor = self.descriptor
            self.descriptor = -1
            _close_lock_guard(descriptor)

    def release(self, lock_path: Path) -> None:
        if self.descriptor < 0:
            return
        descriptor = self.descriptor
        self.descriptor = -1
        _release_lock(lock_path, descriptor)


def _lexical_absolute(value: str | os.PathLike[str]) -> Path:
    return Path(os.path.abspath(os.path.expanduser(os.fspath(value))))


def _existing_real_directory(value: str | os.PathLike[str], *, label: str) -> Path:
    path = _lexical_absolute(value)
    try:
        info = path.lstat()
    except OSError as exc:
        raise SyncError(f"{label} cannot be inspected: {path}: {exc}") from exc
    if stat.S_ISLNK(info.st_mode):
        raise SyncError(f"{label} must not be a symlink: {path}")
    if not stat.S_ISDIR(info.st_mode):
        raise SyncError(f"{label} must be a directory: {path}")
    return path.resolve()


def _exists(path: Path) -> bool:
    try:
        path.lstat()
    except FileNotFoundError:
        return False
    except OSError as exc:
        raise SyncError(f"path cannot be inspected: {path}: {exc}") from exc
    return True


def _is_within(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True


def _git(root: Path, *arguments: str) -> bytes:
    try:
        completed = subprocess.run(
            ["git", "-C", str(root), *arguments],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=GIT_TIMEOUT,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise SyncError(f"git command could not run: {exc}") from exc
    if completed.returncode:
        detail = completed.stderr.decode("utf-8", errors="replace").strip()
        if len(detail) > 1_000:
            detail = detail[-1_000:]
        raise SyncError(
            f"git {' '.join(arguments)} failed with exit {completed.returncode}"
            + (f": {detail}" if detail else "")
        )
    return completed.stdout


def _validate_source_file(root: Path, relative: PurePosixPath) -> Path:
    if relative.is_absolute() or not relative.parts or ".." in relative.parts:
        raise SyncError(f"Git returned an unsafe tracked path: {relative!s}")
    if any(part in {"", "."} or "\\" in part for part in relative.parts):
        raise SyncError(f"Git returned a non-portable tracked path: {relative!s}")

    current = root
    for component in relative.parts[:-1]:
        current /= component
        try:
            info = current.lstat()
        except OSError as exc:
            raise SyncError(
                f"tracked path parent cannot be inspected: {relative!s}: {exc}"
            ) from exc
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise SyncError(
                f"tracked path parent must be a real directory: {relative!s}"
            )

    path = root.joinpath(*relative.parts)
    try:
        info = path.lstat()
    except OSError as exc:
        raise SyncError(
            f"tracked file is missing or unreadable in the working tree: "
            f"{relative!s}: {exc}"
        ) from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise SyncError(f"tracked source must be a regular file: {relative!s}")
    return path


def _is_residue(relative: PurePosixPath) -> bool:
    return (
        any(
            part in RESIDUE_DIRECTORIES
            or any(
                fnmatch.fnmatch(part, pattern)
                for pattern in RESIDUE_COMPONENT_GLOBS
            )
            for part in relative.parts
        )
        or relative.name in RESIDUE_FILE_NAMES
        or relative.suffix in RESIDUE_FILE_SUFFIXES
        or any(
            fnmatch.fnmatch(relative.name, pattern)
            for pattern in RESIDUE_FILE_GLOBS
        )
    )


def _tracked_files(root: Path) -> tuple[PurePosixPath, ...]:
    repository = os.fsdecode(_git(root, "rev-parse", "--show-toplevel")).strip()
    if Path(repository).resolve() != root:
        raise SyncError(f"source root must be the Git repository root: {repository}")

    raw = _git(root, "ls-files", "--cached", "-z", "--")
    names = [os.fsdecode(item) for item in raw.split(b"\0") if item]
    if not names:
        raise SyncError("Git reported no tracked source files")
    relative_paths = tuple(sorted(PurePosixPath(name) for name in names))
    if len(set(relative_paths)) != len(relative_paths):
        raise SyncError("Git reported duplicate tracked source paths")
    residue = tuple(relative for relative in relative_paths if _is_residue(relative))
    if residue:
        sample = ", ".join(str(relative) for relative in residue[:5])
        suffix = ", ..." if len(residue) > 5 else ""
        raise SyncError(
            "tracked install residue must be removed before synchronization: "
            f"{sample}{suffix}"
        )
    for relative in relative_paths:
        _validate_source_file(root, relative)
    return relative_paths


def _payloads(
    root: Path,
) -> tuple[
    dict[str, tuple[tuple[PurePosixPath, PurePosixPath], ...]],
    tuple[PurePosixPath, ...],
]:
    tracked = _tracked_files(root)
    payloads: dict[str, tuple[tuple[PurePosixPath, PurePosixPath], ...]] = {
        ROOT_TARGET: tuple((relative, relative) for relative in tracked)
    }
    for name in FLAT_TARGETS:
        prefix = PurePosixPath("skills", name)
        files = tuple(
            (relative, relative.relative_to(prefix))
            for relative in tracked
            if relative.is_relative_to(prefix)
        )
        destinations = {destination for _, destination in files}
        if PurePosixPath("SKILL.md") not in destinations:
            raise SyncError(
                f"tracked satellite payload is missing skills/{name}/SKILL.md"
            )
        if len(destinations) != len(files):
            raise SyncError(f"satellite payload has duplicate destinations: {name}")
        payloads[name] = files
    return payloads, tracked


def _normalized_file_mode(mode: int) -> int:
    return 0o755 if mode & 0o111 else 0o644


def _windows_stat_semantics() -> bool:
    return os.name == "nt"


def _comparable_ctime_ns(info: os.stat_result) -> int:
    if _windows_stat_semantics():
        # Since Python 3.12, path-based stat calls expose creation time as
        # st_ctime_ns for compatibility while fstat() can expose the Windows
        # metadata-change time.  st_birthtime_ns is the stable creation-time
        # field shared by both views.  Older Python versions have no explicit
        # birth-time field, but their st_ctime_ns already has that meaning.
        return getattr(info, "st_birthtime_ns", info.st_ctime_ns)
    return info.st_ctime_ns


def _fsync_directory(path: Path) -> None:
    if os.name == "nt":
        return
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise SyncError(f"directory cannot be opened for fsync: {path}: {exc}") from exc
    try:
        os.fsync(descriptor)
    except OSError as exc:
        raise SyncError(f"directory fsync failed: {path}: {exc}") from exc
    finally:
        os.close(descriptor)


def _fsync_tree(root: Path) -> None:
    if os.name == "nt":
        return
    directories = [root]
    directories.extend(
        path for path in root.rglob("*") if path.is_dir() and not path.is_symlink()
    )
    for directory in sorted(directories, key=lambda path: len(path.parts), reverse=True):
        _fsync_directory(directory)
    _fsync_directory(root.parent)


def _mkdir_durable(path: Path, *, mode: int) -> None:
    path.mkdir(mode=mode)
    path.chmod(mode)
    _fsync_directory(path)
    _fsync_directory(path.parent)


def _signature(info: os.stat_result) -> SourceSignature:
    return (
        info.st_dev,
        info.st_ino,
        info.st_size,
        info.st_mtime_ns,
        _comparable_ctime_ns(info),
        _normalized_file_mode(info.st_mode),
    )


def _handle_signature(info: os.stat_result) -> SourceSignature:
    """Return metadata comparable only between reads of one open handle."""
    return (
        info.st_dev,
        info.st_ino,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
        _normalized_file_mode(info.st_mode),
    )


def _source_signature(path: Path, *, label: str) -> SourceSignature:
    try:
        info = path.lstat()
    except OSError as exc:
        raise SyncError(f"{label} cannot be inspected: {path}: {exc}") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise SyncError(f"{label} must be a regular file: {path}")
    return _signature(info)


def _snapshot_source_payload(
    source_root: Path,
    tracked: tuple[PurePosixPath, ...],
) -> dict[PurePosixPath, SourceSignature]:
    return {
        relative: _source_signature(
            _validate_source_file(source_root, relative),
            label="tracked source",
        )
        for relative in tracked
    }


def _copy_current_regular(
    source: Path,
    destination: Path,
    expected_signature: SourceSignature,
) -> None:
    if _source_signature(source, label="tracked source") != expected_signature:
        raise SyncError(f"tracked source payload changed before staging: {source}")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(source, flags)
    except OSError as exc:
        raise SyncError(
            f"tracked source cannot be opened safely: {source}: {exc}"
        ) from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise SyncError(f"tracked source changed type while staging: {source}")
        if _signature(before) != expected_signature:
            raise SyncError(f"tracked source payload changed before staging: {source}")
        handle_signature = _handle_signature(before)
        mode = _normalized_file_mode(before.st_mode)
        with os.fdopen(descriptor, "rb", closefd=False) as input_stream:
            with destination.open("xb") as output_stream:
                shutil.copyfileobj(input_stream, output_stream, length=1024 * 1024)
                if hasattr(os, "fchmod"):
                    os.fchmod(output_stream.fileno(), mode)
                else:
                    destination.chmod(mode)
                output_stream.flush()
                os.fsync(output_stream.fileno())
        try:
            path_after = source.lstat()
        except OSError as exc:
            raise SyncError(
                f"tracked source path changed while staging: {source}: {exc}"
            ) from exc
        if stat.S_ISLNK(path_after.st_mode) or not stat.S_ISREG(path_after.st_mode):
            raise SyncError(f"tracked source path changed type while staging: {source}")
        if _normalized_file_mode(path_after.st_mode) != expected_signature[-1]:
            raise SyncError(
                f"tracked source executable mode changed while staging: {source}"
            )
        if _signature(path_after) != expected_signature:
            raise SyncError(f"tracked source path changed while staging: {source}")
        after = os.fstat(descriptor)
        if not stat.S_ISREG(after.st_mode):
            raise SyncError(f"tracked source changed type while staging: {source}")
        if _normalized_file_mode(after.st_mode) != expected_signature[-1]:
            raise SyncError(
                f"tracked source executable mode changed while staging: {source}"
            )
        if _signature(after) != expected_signature:
            raise SyncError(f"tracked source changed while staging: {source}")
        if _handle_signature(after) != handle_signature:
            raise SyncError(f"tracked source changed while staging: {source}")
        _fsync_directory(destination.parent)
    finally:
        os.close(descriptor)


def _stage_payloads(
    source_root: Path,
    stage_root: Path,
    payloads: dict[str, tuple[tuple[PurePosixPath, PurePosixPath], ...]],
    snapshots: dict[PurePosixPath, SourceSignature],
) -> dict[str, int]:
    counts: dict[str, int] = {}
    for name in TARGETS:
        target_root = stage_root / name
        target_root.mkdir(mode=0o755)
        target_root.chmod(0o755)
        files = payloads[name]
        for source_relative, destination_relative in files:
            source = _validate_source_file(source_root, source_relative)
            destination = target_root.joinpath(*destination_relative.parts)
            destination.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
            _copy_current_regular(
                source,
                destination,
                snapshots[source_relative],
            )
        for directory in target_root.rglob("*"):
            if directory.is_dir() and not directory.is_symlink():
                directory.chmod(0o755)
        counts[name] = len(files)
    _fsync_tree(stage_root)
    return counts


def _open_regular_no_follow(path: Path, *, label: str) -> tuple[int, os.stat_result]:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise SyncError(f"{label} cannot be opened safely: {path}: {exc}") from exc
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise SyncError(f"{label} must be a regular file: {path}")
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor, info


def _verify_source_payload_stable(
    source_root: Path,
    stage_root: Path,
    tracked: tuple[PurePosixPath, ...],
    snapshots: dict[PurePosixPath, SourceSignature],
) -> None:
    if _tracked_files(source_root) != tracked:
        raise SyncError("Git tracked source payload changed during staging")
    for relative in tracked:
        source = _validate_source_file(source_root, relative)
        staged = stage_root / ROOT_TARGET
        staged = staged.joinpath(*relative.parts)
        expected = snapshots[relative]
        if _source_signature(source, label="tracked source") != expected:
            raise SyncError(
                f"tracked source payload changed after staging: {relative!s}"
            )
        source_descriptor, source_info = _open_regular_no_follow(
            source,
            label="tracked source",
        )
        staged_descriptor = -1
        try:
            if _signature(source_info) != expected:
                raise SyncError(
                    f"tracked source payload changed after staging: {relative!s}"
                )
            handle_signature = _handle_signature(source_info)
            staged_descriptor, staged_info = _open_regular_no_follow(
                staged,
                label="staged source copy",
            )
            if _normalized_file_mode(staged_info.st_mode) != expected[-1]:
                raise SyncError(
                    f"staged source mode differs from current source: {relative!s}"
                )
            while True:
                source_chunk = os.read(source_descriptor, 1024 * 1024)
                staged_chunk = os.read(staged_descriptor, 1024 * 1024)
                if source_chunk != staged_chunk:
                    raise SyncError(
                        f"tracked source bytes changed after staging: {relative!s}"
                    )
                if not source_chunk:
                    break
            final_source_info = os.fstat(source_descriptor)
            if _signature(final_source_info) != expected or (
                _handle_signature(final_source_info) != handle_signature
            ):
                raise SyncError(
                    f"tracked source payload changed during final verification: "
                    f"{relative!s}"
                )
            if _source_signature(source, label="tracked source") != expected:
                raise SyncError(
                    f"tracked source path changed during final verification: "
                    f"{relative!s}"
                )
        finally:
            os.close(source_descriptor)
            if staged_descriptor >= 0:
                os.close(staged_descriptor)

    # The content checks above are necessarily sequential.  Sweep the whole
    # tracked set again after the last comparison so a file checked early
    # cannot change unnoticed while a later file is being verified.
    if _tracked_files(source_root) != tracked:
        raise SyncError("Git tracked source payload changed during final sweep")
    for relative in tracked:
        source = _validate_source_file(source_root, relative)
        if _source_signature(source, label="tracked source") != snapshots[relative]:
            raise SyncError(
                "tracked source payload changed during final source sweep: "
                f"{relative!s}"
            )


def _manifest_frame(digest, value: str | bytes) -> None:
    encoded = (
        value.encode("utf-8", errors="surrogateescape")
        if isinstance(value, str)
        else value
    )
    digest.update(len(encoded).to_bytes(8, "big"))
    digest.update(encoded)


def _validate_staged_tree(
    stage_root: Path,
    payloads: dict[str, tuple[tuple[PurePosixPath, PurePosixPath], ...]],
) -> None:
    if _directory_identity(
        stage_root,
        label="stage root",
        require_stable=False,
    ) is None:
        raise SyncError(f"stage root is missing: {stage_root}")
    try:
        root_entries = {entry.name for entry in stage_root.iterdir()}
    except OSError as exc:
        raise SyncError(f"stage root cannot be listed: {stage_root}: {exc}") from exc
    if root_entries != set(TARGETS):
        raise SyncError("staged tree does not contain exactly the managed targets")

    for name in TARGETS:
        target_root = stage_root / name
        if _directory_identity(
            target_root,
            label="staged target",
            require_stable=False,
        ) is None:
            raise SyncError(f"staged target is missing: {target_root}")
        if os.name != "nt" and stat.S_IMODE(target_root.lstat().st_mode) != 0o755:
            raise SyncError(f"staged target directory must have mode 0755: {target_root}")
        expected_files = {destination for _, destination in payloads[name]}
        expected_directories: set[PurePosixPath] = set()
        for destination in expected_files:
            parent = destination.parent
            while parent != PurePosixPath("."):
                expected_directories.add(parent)
                parent = parent.parent

        actual_files: set[PurePosixPath] = set()
        actual_directories: set[PurePosixPath] = set()
        try:
            members = list(target_root.rglob("*"))
        except OSError as exc:
            raise SyncError(
                f"staged target cannot be traversed: {target_root}: {exc}"
            ) from exc
        for member in members:
            relative = PurePosixPath(member.relative_to(target_root).as_posix())
            try:
                info = member.lstat()
            except OSError as exc:
                raise SyncError(
                    f"staged member cannot be inspected: {member}: {exc}"
                ) from exc
            if stat.S_ISLNK(info.st_mode):
                raise SyncError(f"staged member must not be a symlink: {member}")
            if stat.S_ISDIR(info.st_mode):
                if os.name != "nt" and stat.S_IMODE(info.st_mode) != 0o755:
                    raise SyncError(
                        f"staged directory must have mode 0755: {member}"
                    )
                actual_directories.add(relative)
            elif stat.S_ISREG(info.st_mode):
                actual_files.add(relative)
            else:
                raise SyncError(f"staged member must be a file or directory: {member}")
        if actual_files != expected_files or actual_directories != expected_directories:
            raise SyncError(f"staged target tree differs from its payload: {name}")


def _manifest_sha256(
    stage_root: Path,
    source_root: Path,
    install_root: Path,
    payloads: dict[str, tuple[tuple[PurePosixPath, PurePosixPath], ...]],
) -> str:
    _validate_staged_tree(stage_root, payloads)
    digest = hashlib.sha256()
    digest.update(b"netops-install-manifest-v2\0")
    _manifest_frame(digest, str(source_root))
    _manifest_frame(digest, str(install_root))
    digest.update(len(TARGETS).to_bytes(4, "big"))
    for name in TARGETS:
        _manifest_frame(digest, name)
    for name in TARGETS:
        for source_relative, destination_relative in payloads[name]:
            staged = stage_root / name
            staged = staged.joinpath(*destination_relative.parts)
            target_relative = PurePosixPath(name, *destination_relative.parts)
            try:
                path_info = staged.lstat()
            except OSError as exc:
                raise SyncError(
                    f"staged manifest file cannot be inspected: "
                    f"{target_relative!s}: {exc}"
                ) from exc
            if stat.S_ISLNK(path_info.st_mode) or not stat.S_ISREG(path_info.st_mode):
                raise SyncError(
                    f"staged manifest member must be a regular file: "
                    f"{target_relative!s}"
                )
            raw_mode = stat.S_IMODE(path_info.st_mode)
            mode = _normalized_file_mode(path_info.st_mode)
            if os.name != "nt" and raw_mode != mode:
                raise SyncError(
                    f"staged manifest member has an unexpected normalized mode: "
                    f"{target_relative!s}: {raw_mode:04o}"
                )

            flags = os.O_RDONLY
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            try:
                descriptor = os.open(staged, flags)
            except OSError as exc:
                raise SyncError(
                    f"staged manifest file cannot be opened safely: "
                    f"{target_relative!s}: {exc}"
                ) from exc
            try:
                opened = os.fstat(descriptor)
                if not stat.S_ISREG(opened.st_mode) or (
                    opened.st_dev,
                    opened.st_ino,
                    opened.st_size,
                    opened.st_mtime_ns,
                ) != (
                    path_info.st_dev,
                    path_info.st_ino,
                    path_info.st_size,
                    path_info.st_mtime_ns,
                ):
                    raise SyncError(
                        f"staged manifest file changed before hashing: "
                        f"{target_relative!s}"
                    )
                if _normalized_file_mode(opened.st_mode) != mode:
                    raise SyncError(
                        f"staged manifest file mode changed before hashing: "
                        f"{target_relative!s}"
                    )
                _manifest_frame(digest, source_relative.as_posix())
                _manifest_frame(digest, target_relative.as_posix())
                digest.update(mode.to_bytes(4, "big"))
                digest.update(opened.st_size.to_bytes(8, "big"))
                with os.fdopen(descriptor, "rb", closefd=False) as stream:
                    while chunk := stream.read(1024 * 1024):
                        digest.update(chunk)
                after = os.fstat(descriptor)
                if _handle_signature(opened) != _handle_signature(after):
                    raise SyncError(
                        f"staged manifest file changed while hashing: "
                        f"{target_relative!s}"
                    )
                try:
                    path_after = staged.lstat()
                except OSError as exc:
                    raise SyncError(
                        f"staged manifest path changed while hashing: "
                        f"{target_relative!s}: {exc}"
                    ) from exc
                if (
                    stat.S_ISLNK(path_after.st_mode)
                    or not stat.S_ISREG(path_after.st_mode)
                    or _signature(path_after) != _signature(opened)
                ):
                    raise SyncError(
                        f"staged manifest path changed while hashing: "
                        f"{target_relative!s}"
                    )
            finally:
                os.close(descriptor)
    return digest.hexdigest()


def _preflight_targets(install_root: Path) -> tuple[str, ...]:
    existing: list[str] = []
    for name in TARGETS:
        target = install_root / name
        try:
            info = target.lstat()
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise SyncError(
                f"install target cannot be inspected: {target}: {exc}"
            ) from exc
        if stat.S_ISLNK(info.st_mode):
            raise SyncError(f"install target must not be a symlink: {target}")
        if not stat.S_ISDIR(info.st_mode):
            raise SyncError(f"install target must be a directory: {target}")
        existing.append(name)
    return tuple(existing)


def _prepare_backup_parent(install_root: Path) -> Path:
    backup_parent = install_root.parent / BACKUP_PARENT_NAME
    created = False
    try:
        backup_parent.mkdir(mode=0o700)
        created = True
    except FileExistsError:
        pass
    except OSError as exc:
        raise SyncError(
            f"backup parent cannot be created: {backup_parent}: {exc}"
        ) from exc

    try:
        info = backup_parent.lstat()
        install_info = install_root.lstat()
    except OSError as exc:
        raise SyncError(
            f"backup parent cannot be inspected: {backup_parent}: {exc}"
        ) from exc
    if stat.S_ISLNK(info.st_mode):
        raise SyncError(f"backup parent must not be a symlink: {backup_parent}")
    if not stat.S_ISDIR(info.st_mode):
        raise SyncError(f"backup parent must be a directory: {backup_parent}")
    if created:
        try:
            backup_parent.chmod(0o700)
            info = backup_parent.lstat()
            _fsync_directory(backup_parent)
            _fsync_directory(backup_parent.parent)
        except OSError as exc:
            raise SyncError(
                f"backup parent permissions cannot be secured: {backup_parent}: {exc}"
            ) from exc
    if os.name != "nt" and stat.S_IMODE(info.st_mode) != 0o700:
        raise SyncError(
            f"backup parent must have mode 0700: {backup_parent} "
            f"(found {stat.S_IMODE(info.st_mode):04o})"
        )
    if info.st_dev != install_info.st_dev:
        raise SyncError(
            "backup parent and install root must be on the same device for "
            f"transactional moves: {backup_parent}"
        )
    return backup_parent


def _write_private_json(
    directory: Path,
    name: str,
    payload_value: dict[str, object],
) -> None:
    final_path = directory / name
    descriptor = -1
    temporary_path: Path | None = None
    try:
        descriptor, raw_path = tempfile.mkstemp(
            prefix=f".{name}-",
            suffix=".tmp",
            dir=directory,
        )
        temporary_path = Path(raw_path)
        if hasattr(os, "fchmod"):
            os.fchmod(descriptor, 0o600)
        else:
            temporary_path.chmod(0o600)
        payload = (
            json.dumps(payload_value, ensure_ascii=False, indent=2, sort_keys=True)
            + "\n"
        ).encode("utf-8")
        with os.fdopen(descriptor, "wb", closefd=False) as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.close(descriptor)
        descriptor = -1
        os.replace(temporary_path, final_path)
        temporary_path = None
        if os.name == "nt":
            final_path.chmod(0o600)
        if os.name != "nt" and stat.S_IMODE(final_path.lstat().st_mode) != 0o600:
            raise SyncError(f"private JSON must have mode 0600: {final_path}")
        _fsync_directory(directory)
    except (OSError, SyncError) as exc:
        raise SyncError(f"private JSON could not be written: {exc}") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if temporary_path is not None:
            try:
                temporary_path.unlink()
            except OSError:
                pass


def _write_backup_receipt(backup_root: Path, receipt: dict[str, object]) -> None:
    _write_private_json(backup_root, RECEIPT_NAME, receipt)


def _read_private_json(path: Path, *, label: str) -> dict[str, object]:
    try:
        info = path.lstat()
    except OSError as exc:
        raise SyncError(f"{label} cannot be inspected: {path}: {exc}") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise SyncError(f"{label} must be a regular file: {path}")
    if info.st_size > MAX_JOURNAL_BYTES:
        raise SyncError(f"{label} exceeds the size limit: {path}")
    descriptor, opened = _open_regular_no_follow(path, label=label)
    try:
        if (
            opened.st_dev,
            opened.st_ino,
            opened.st_size,
            opened.st_mtime_ns,
        ) != (
            info.st_dev,
            info.st_ino,
            info.st_size,
            info.st_mtime_ns,
        ):
            raise SyncError(f"{label} changed before reading: {path}")
        chunks: list[bytes] = []
        total = 0
        while chunk := os.read(descriptor, 64 * 1024):
            total += len(chunk)
            if total > MAX_JOURNAL_BYTES:
                raise SyncError(f"{label} exceeds the size limit: {path}")
            chunks.append(chunk)
        raw = b"".join(chunks)
    finally:
        os.close(descriptor)
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeError, ValueError) as exc:
        raise SyncError(f"{label} is not valid JSON: {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise SyncError(f"{label} must contain a JSON object: {path}")
    return value


def _lock_token(install_root: Path) -> str:
    try:
        info = install_root.lstat()
    except OSError as exc:
        raise SyncError(
            f"install root cannot be identified for locking: {install_root}: {exc}"
        ) from exc
    if info.st_ino:
        key = f"filesystem-identity\0{info.st_dev}\0{info.st_ino}"
    else:  # pragma: no cover - filesystems without stable inode numbers
        key = f"canonical-path\0{os.path.normcase(str(install_root))}"
    encoded = key.encode("utf-8", errors="surrogateescape")
    return hashlib.sha256(encoded).hexdigest()[:24]


def _lock_path(backup_parent: Path, install_root: Path) -> Path:
    token = _lock_token(install_root)
    return backup_parent / f"{LOCK_PREFIX}{token}"


def _guard_path(backup_parent: Path, install_root: Path) -> Path:
    token = _lock_token(install_root)
    return backup_parent / f"{LOCK_GUARD_PREFIX}{token}"


def _recover_hint(install_root: Path, receipt_path: Path | None = None) -> str:
    arguments = [
        sys.executable or "python3",
        str(Path(__file__).resolve()),
        "--install-root",
        str(install_root),
        "--recover",
    ]
    if receipt_path is not None:
        arguments.extend(("--recovery-receipt", str(receipt_path)))
    if os.name == "nt":  # pragma: no cover - exercised on Windows CI
        # cmd.exe and PowerShell have incompatible quoting rules.  Present the
        # exact argument vector as inert JSON instead of emitting a string that
        # can become a copy-paste command-injection vector in either shell.
        return "argv: " + json.dumps(arguments, ensure_ascii=True)
    return shlex.join(arguments)


def _write_lock_info(lock_path: Path, value: dict[str, object]) -> None:
    _write_private_json(lock_path, LOCK_INFO_NAME, value)


def _read_lock_info(lock_path: Path) -> dict[str, object] | None:
    path = lock_path / LOCK_INFO_NAME
    try:
        path.lstat()
    except FileNotFoundError:
        try:
            temporary_candidates = sorted(
                candidate
                for candidate in lock_path.iterdir()
                if candidate.name.startswith(f".{LOCK_INFO_NAME}-")
                and candidate.name.endswith(".tmp")
            )
        except OSError as exc:
            raise SyncError(
                f"transaction lock cannot be listed: {lock_path}: {exc}"
            ) from exc
        valid: list[dict[str, object]] = []
        for candidate in temporary_candidates:
            try:
                valid.append(
                    _read_private_json(candidate, label="temporary transaction lock")
                )
            except SyncError:
                continue
        if len(valid) > 1:
            raise SyncError("multiple valid temporary transaction locks exist")
        return valid[0] if valid else None
    except OSError as exc:
        raise SyncError(f"transaction lock cannot be inspected: {path}: {exc}") from exc
    return _read_private_json(path, label="transaction lock")


def _open_lock_guard(backup_parent: Path, install_root: Path) -> int:
    path = _guard_path(backup_parent, install_root)
    flags = os.O_RDWR | os.O_CREAT
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = -1
    try:
        descriptor = os.open(path, flags, 0o600)
        if hasattr(os, "fchmod"):
            os.fchmod(descriptor, 0o600)
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode):
            raise SyncError(f"transaction guard must be a regular file: {path}")
        path_info = path.lstat()
        if (
            stat.S_ISLNK(path_info.st_mode)
            or not stat.S_ISREG(path_info.st_mode)
            or (path_info.st_dev, path_info.st_ino)
            != (opened.st_dev, opened.st_ino)
        ):
            raise SyncError(f"transaction guard path changed while opening: {path}")
        os.fsync(descriptor)
        _fsync_directory(backup_parent)
        if fcntl is not None:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        elif msvcrt is not None:
            if opened.st_size == 0:
                os.write(descriptor, b"\0")
                os.fsync(descriptor)
            os.lseek(descriptor, 0, os.SEEK_SET)
            msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
        else:
            raise SyncError(
                "no supported inter-process file lock is available on this platform"
            )
    except (OSError, BlockingIOError) as exc:
        if descriptor >= 0:
            os.close(descriptor)
        raise SyncError(f"transaction lock is held by another process: {path}") from exc
    except BaseException:
        if descriptor >= 0:
            os.close(descriptor)
        raise
    return descriptor


def _close_lock_guard(descriptor: int) -> None:
    if descriptor < 0:
        return
    try:
        if fcntl is not None:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        elif msvcrt is not None:
            os.lseek(descriptor, 0, os.SEEK_SET)
            msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
    finally:
        os.close(descriptor)


def _matching_receipts(
    backup_parent: Path,
    install_root: Path,
    *,
    statuses: set[str] | None = None,
) -> list[tuple[Path, dict[str, object]]]:
    matches: list[tuple[Path, dict[str, object]]] = []
    try:
        candidates = sorted(backup_parent.iterdir())
    except OSError as exc:
        raise SyncError(f"backup parent cannot be listed: {backup_parent}: {exc}") from exc
    for backup_root in candidates:
        if not backup_root.name.startswith("netops-install-"):
            continue
        try:
            info = backup_root.lstat()
        except OSError as exc:
            raise SyncError(f"backup directory cannot be inspected: {backup_root}: {exc}") from exc
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise SyncError(f"backup entry must be a real directory: {backup_root}")
        receipt_path = backup_root / RECEIPT_NAME
        if not _exists(receipt_path):
            continue
        receipt = _read_private_json(receipt_path, label="backup receipt")
        if receipt.get("install_root") != str(install_root):
            continue
        status = receipt.get("status")
        if status not in KNOWN_RECEIPT_STATUSES:
            raise SyncError(
                f"backup receipt has unsupported status {status!r}: {receipt_path}"
            )
        if statuses is None or status in statuses:
            matches.append((receipt_path, receipt))
    return matches


def _acquire_apply_lock(
    backup_parent: Path,
    install_root: Path,
    stage_root: Path,
) -> tuple[Path, _GuardLease, dict[str, object]]:
    lock_path = _lock_path(backup_parent, install_root)
    guard = _GuardLease(_open_lock_guard(backup_parent, install_root))
    try:
        stage_root_id = _directory_identity(stage_root, label="stage root")
        staged_target_ids = {
            name: identity
            for name in TARGETS
            if (
                identity := _directory_identity(
                    stage_root / name,
                    label="stage target",
                )
            )
            is not None
        }
    except BaseException:
        guard.close()
        raise
    if stage_root_id is None:
        guard.close()
        raise SyncError(f"stage root disappeared before locking: {stage_root}")
    if set(staged_target_ids) != set(TARGETS):
        guard.close()
        raise SyncError("a staged target disappeared before locking")
    try:
        _mkdir_durable(lock_path, mode=0o700)
    except FileExistsError:
        try:
            info = lock_path.lstat()
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
                raise SyncError(
                    f"transaction lock must be a real directory: {lock_path}"
                )
            lock = _read_lock_info(lock_path)
            receipt_path = None
            if lock is not None and isinstance(lock.get("receipt_path"), str):
                receipt_path = _lexical_absolute(str(lock["receipt_path"]))
            raise SyncError(
                "an active or incomplete installation transaction holds the lock; "
                f"run recovery first: {_recover_hint(install_root, receipt_path)}"
            )
        finally:
            guard.close()
    except BaseException:
        guard.close()
        raise

    lock: dict[str, object] = {
        "version": 1,
        "status": "active",
        "pid": os.getpid(),
        "install_root": str(install_root),
        "stage_path": str(stage_root),
        "stage_root_id": list(stage_root_id),
        "staged_target_ids": {
            name: list(staged_target_ids[name]) for name in TARGETS
        },
        "receipt_path": None,
    }
    try:
        _write_lock_info(lock_path, lock)
        incomplete = _matching_receipts(
            backup_parent,
            install_root,
            statuses=INCOMPLETE_STATUSES,
        )
    except BaseException:
        guard.release(lock_path)
        raise
    if incomplete:
        receipt_path = incomplete[0][0]
        lock.update(
            {
                "status": "recovery-required",
                "pid": None,
                "receipt_path": str(receipt_path),
            }
        )
        try:
            _write_lock_info(lock_path, lock)
        finally:
            guard.close()
        if len(incomplete) > 1:
            raise SyncError(
                "multiple incomplete installation transactions require explicit "
                f"recovery; first receipt: {receipt_path}"
            )
        raise SyncError(
            "an incomplete installation transaction must be recovered before apply: "
            f"{_recover_hint(install_root, receipt_path)}"
        )
    return lock_path, guard, lock


def _release_lock(lock_path: Path, guard: int) -> None:
    try:
        try:
            info = lock_path.lstat()
        except FileNotFoundError:
            return
        except OSError as exc:
            raise SyncError(
                f"transaction lock cannot be inspected: {lock_path}: {exc}"
            ) from exc
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise SyncError(f"transaction lock must be a real directory: {lock_path}")
        entries = list(lock_path.iterdir())
        for entry in entries:
            if entry.name == LOCK_INFO_NAME:
                continue
            if not (
                entry.name.startswith(f".{LOCK_INFO_NAME}-")
                and entry.name.endswith(".tmp")
            ):
                raise SyncError(
                    f"transaction lock contains unexpected entries: {lock_path}"
                )
            entry_info = entry.lstat()
            if stat.S_ISLNK(entry_info.st_mode) or not stat.S_ISREG(entry_info.st_mode):
                raise SyncError(f"temporary transaction lock is unsafe: {entry}")
            entry.unlink()
            _fsync_directory(lock_path)
        info_path = lock_path / LOCK_INFO_NAME
        if _exists(info_path):
            info_path.unlink()
            _fsync_directory(lock_path)
        lock_path.rmdir()
        _fsync_directory(lock_path.parent)
    finally:
        _close_lock_guard(guard)


def _move_path(source: Path, destination: Path) -> None:
    os.replace(source, destination)
    _fsync_directory(source.parent)
    if destination.parent != source.parent:
        _fsync_directory(destination.parent)


def _directory_identity(
    path: Path,
    *,
    label: str,
    require_stable: bool = True,
) -> tuple[int, int] | None:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise SyncError(f"{label} cannot be inspected: {path}: {exc}") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise SyncError(f"{label} must be a real directory: {path}")
    if require_stable and info.st_ino == 0:
        raise SyncError(
            f"{label} is on a filesystem without stable directory identities: {path}"
        )
    return info.st_dev, info.st_ino


def _rollback(
    stage_root: Path,
    install_root: Path,
    backup_root: Path,
    originally_existing: frozenset[str],
    original_target_ids: dict[str, tuple[int, int]],
    staged_target_ids: dict[str, tuple[int, int]],
    pending_move: dict[str, str] | None,
    after_move: Callable[[str, str], None],
) -> tuple[str, ...]:
    errors: list[str] = []

    def move_staged_live_out(name: str, target: Path, stage: Path) -> None:
        live_id = _directory_identity(target, label="live install target")
        if live_id != staged_target_ids[name]:
            raise SyncError(f"refusing to move an unrecognised live target: {target}")
        stage_root_id = _directory_identity(stage_root, label="stage root")
        if (
            stage_root_id is not None
            and _directory_identity(stage, label="stage target") is None
        ):
            _move_path(target, stage)
            after_move(name, "installed-to-stage")
            return
        quarantine = backup_root / f"failed-new-{name}"
        if _directory_identity(quarantine, label="rollback quarantine") is not None:
            raise SyncError(f"rollback quarantine already exists: {quarantine}")
        _move_path(target, quarantine)
        after_move(name, "installed-to-quarantine")

    for name in reversed(TARGETS):
        stage = stage_root / name
        target = install_root / name
        backup = backup_root / name
        try:
            live_id = _directory_identity(target, label="live install target")
            backup_id = _directory_identity(backup, label="backup target")
            if name in originally_existing:
                original_id = original_target_ids[name]
                if backup_id is not None and backup_id != original_id:
                    if live_id is None and pending_move == {
                        "target": name,
                        "direction": "install-to-backup",
                    }:
                        _move_path(backup, target)
                        after_move(name, "concurrent-backup-to-install")
                        raise SyncError(
                            "a concurrently replaced live target was restored, but "
                            f"the original target identity is unavailable: {name}"
                        )
                    raise SyncError(f"backup target identity changed: {backup}")
                if live_id == original_id:
                    if backup_id is not None:
                        raise SyncError(
                            f"original target exists in both live and backup: {name}"
                        )
                    continue
                if backup_id != original_id:
                    raise SyncError(f"original target is unavailable for rollback: {name}")
                if live_id is not None:
                    move_staged_live_out(name, target, stage)
                _move_path(backup, target)
                after_move(name, "backup-to-install")
            else:
                if backup_id is not None:
                    raise SyncError(
                        f"unexpected backup exists for originally absent target: {name}"
                    )
                if live_id is not None:
                    move_staged_live_out(name, target, stage)
        except (OSError, SyncError) as exc:
            errors.append(f"{name}: {exc}")

    for name in TARGETS:
        try:
            live_id = _directory_identity(
                install_root / name,
                label="live install target",
            )
            backup_id = _directory_identity(
                backup_root / name,
                label="backup target",
            )
            if name in originally_existing:
                if live_id != original_target_ids[name] or backup_id is not None:
                    errors.append(f"{name}: rollback postcondition is not satisfied")
            elif live_id is not None or backup_id is not None:
                errors.append(f"{name}: rollback postcondition is not satisfied")
        except SyncError as exc:
            errors.append(f"{name}: {exc}")
    return tuple(errors)


def _cleanup_stage_root(
    stage_root: Path,
    install_parent: Path,
    *,
    expected_identity: tuple[int, int] | None = None,
) -> None:
    if stage_root.parent != install_parent or not stage_root.name.startswith(
        "netops-install-stage-"
    ):
        raise SyncError(f"refusing to clean an unexpected stage path: {stage_root}")
    try:
        info = stage_root.lstat()
    except FileNotFoundError:
        return
    except OSError as exc:
        raise SyncError(f"stage path cannot be inspected: {stage_root}: {exc}") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise SyncError(f"stage path must be a real directory: {stage_root}")
    if expected_identity is not None and (info.st_dev, info.st_ino) != expected_identity:
        raise SyncError(f"stage root identity changed; refusing cleanup: {stage_root}")
    try:
        shutil.rmtree(stage_root)
    except OSError as exc:
        raise SyncError(f"stage path could not be removed: {stage_root}: {exc}") from exc
    _fsync_directory(install_parent)


def _cleanup_transaction_stage(
    stage_root: Path,
    install_parent: Path,
    stage_root_id: tuple[int, int],
    staged_target_ids: dict[str, tuple[int, int]],
    *,
    targets_expected: bool,
) -> None:
    root_id = _directory_identity(stage_root, label="stage root")
    if root_id is None:
        return
    if root_id != stage_root_id:
        raise SyncError(f"stage root identity changed; refusing cleanup: {stage_root}")
    try:
        entries = {entry.name for entry in stage_root.iterdir()}
    except OSError as exc:
        raise SyncError(f"stage root cannot be listed safely: {stage_root}: {exc}") from exc
    if targets_expected:
        entries_valid = entries.issubset(set(TARGETS))
    else:
        entries_valid = not entries
    if not entries_valid:
        raise SyncError(
            f"stage root contents changed; refusing cleanup: {stage_root}"
        )
    if targets_expected:
        for name in entries:
            if (
                _directory_identity(stage_root / name, label="stage target")
                != staged_target_ids[name]
            ):
                raise SyncError(
                    f"stage target identity changed; refusing cleanup: {name}"
                )
    _cleanup_stage_root(
        stage_root,
        install_parent,
        expected_identity=stage_root_id,
    )


def _stage_has_incomplete_receipt(stage_root: Path, install_root: Path) -> bool:
    backup_parent = install_root.parent / BACKUP_PARENT_NAME
    try:
        info = backup_parent.lstat()
    except FileNotFoundError:
        return False
    except OSError:
        return True
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        return True
    try:
        receipts = _matching_receipts(
            backup_parent,
            install_root,
            statuses=INCOMPLETE_STATUSES,
        )
    except SyncError:
        return True
    return any(
        receipt.get("stage_path") == str(stage_root)
        for _, receipt in receipts
    )


def _apply_staged(
    stage_root: Path,
    install_root: Path,
    receipt_base: dict[str, object],
    pre_live_check: Callable[[], None],
) -> dict[str, object]:
    backup_parent = _prepare_backup_parent(install_root)
    lock_path, guard, lock = _acquire_apply_lock(
        backup_parent,
        install_root,
        stage_root,
    )
    try:
        originally_existing = frozenset(_preflight_targets(install_root))
        original_target_ids = {
            name: identity
            for name in originally_existing
            if (
                identity := _directory_identity(
                    install_root / name,
                    label="live install target",
                )
            )
            is not None
        }
        if set(original_target_ids) != set(originally_existing):
            raise SyncError("an install target disappeared during transaction setup")
        stage_root_id = _directory_identity(stage_root, label="stage root")
        if stage_root_id is None or lock.get("stage_root_id") != list(stage_root_id):
            raise SyncError("stage root identity changed during transaction setup")
        staged_target_ids = {
            name: identity
            for name in TARGETS
            if (
                identity := _directory_identity(
                    stage_root / name,
                    label="stage target",
                )
            )
            is not None
        }
        if set(staged_target_ids) != set(TARGETS):
            raise SyncError("a staged target disappeared during transaction setup")
    except BaseException:
        guard.release(lock_path)
        raise
    backup_root: Path | None = backup_parent / (
        f"netops-install-{secrets.token_hex(12)}"
    )
    try:
        lock["backup_path"] = str(backup_root)
        _write_lock_info(lock_path, lock)
        _mkdir_durable(backup_root, mode=0o700)
        backup_root_id = _directory_identity(backup_root, label="backup root")
        if backup_root_id is None:
            raise SyncError("backup root disappeared during setup")
        lock["backup_root_id"] = list(backup_root_id)
        _write_lock_info(lock_path, lock)
        if _is_within(backup_root, install_root):
            raise SyncError("backup directory must be outside the install root")
        if backup_root.lstat().st_dev != install_root.lstat().st_dev:
            raise SyncError(
                "backup directory and install root are not on the same device"
            )
    except BaseException as exc:
        cleanup_error: BaseException | None = None
        try:
            backup_id = _directory_identity(
                backup_root,
                label="incomplete backup root",
            )
            if backup_id is not None:
                if any(backup_root.iterdir()):
                    raise SyncError(
                        f"incomplete backup root is not empty: {backup_root}"
                    )
                backup_root.rmdir()
                _fsync_directory(backup_parent)
        except BaseException as cleanup_exc:
            cleanup_error = cleanup_exc
        if cleanup_error is not None:
            guard.close()
            raise SyncError(
                "backup setup failed and its durable state requires recovery: "
                f"{exc}; cleanup failed: {cleanup_error}; "
                f"{_recover_hint(install_root)}",
                backup_path=backup_root,
                preserve_stage=True,
            ) from exc
        try:
            guard.release(lock_path)
        except SyncError as release_error:
            raise SyncError(
                "backup setup failed and transaction lock cleanup failed; "
                f"{_recover_hint(install_root)}; {release_error}",
                backup_path=backup_root,
                preserve_stage=True,
            ) from exc
        if isinstance(exc, (KeyboardInterrupt, SystemExit)):
            raise
        raise SyncError(
            f"backup directory could not be created safely: {exc}",
            backup_path=backup_root,
        ) from exc

    backed_up: list[str] = []
    installed: list[str] = []
    rollback_actions: list[str] = []
    pending_move: dict[str, str] | None = None

    def transaction_receipt(
        *,
        status: str,
        phase: str,
        error: str | None = None,
        rollback_errors: tuple[str, ...] = (),
        journal_errors: tuple[str, ...] = (),
    ) -> dict[str, object]:
        receipt = {
            **receipt_base,
            "status": status,
            "phase": phase,
            "stage_path": str(stage_root),
            "stage_root_id": list(stage_root_id),
            "backup_path": str(backup_root),
            "backup_root_id": list(backup_root_id),
            "existing_targets": len(originally_existing),
            "originally_existing": [
                name for name in TARGETS if name in originally_existing
            ],
            "original_target_ids": {
                name: list(original_target_ids[name])
                for name in TARGETS
                if name in original_target_ids
            },
            "staged_target_ids": {
                name: list(staged_target_ids[name]) for name in TARGETS
            },
            "backed_up": list(backed_up),
            "installed": list(installed),
            "rollback_actions": list(rollback_actions),
            "pending_move": dict(pending_move) if pending_move is not None else None,
        }
        if error is not None:
            receipt["error"] = error
        if rollback_errors:
            receipt["rollback_errors"] = list(rollback_errors)
        if journal_errors:
            receipt["journal_errors"] = list(journal_errors)
        return receipt

    try:
        _write_backup_receipt(
            backup_root,
            transaction_receipt(status="in-progress", phase="backup"),
        )
        lock.update(
            {
                "receipt_path": str(backup_root / RECEIPT_NAME),
                "backup_path": str(backup_root),
            }
        )
        _write_lock_info(lock_path, lock)
        pre_live_check()
        for name in TARGETS:
            target = install_root / name
            backup = backup_root / name
            live_id = _directory_identity(target, label="live install target")
            if name not in originally_existing:
                if live_id is not None:
                    raise SyncError(
                        f"an originally absent install target appeared: {target}"
                    )
                continue
            if live_id != original_target_ids[name]:
                raise SyncError(
                    f"install target identity changed before backup: {target}"
                )
            if _directory_identity(backup, label="backup target") is not None:
                raise SyncError(f"backup target already exists: {backup}")
            pending_move = {
                "target": name,
                "direction": "install-to-backup",
            }
            _write_backup_receipt(
                backup_root,
                transaction_receipt(status="in-progress", phase="backup"),
            )
            if (
                _directory_identity(target, label="live install target")
                != original_target_ids[name]
                or _directory_identity(backup, label="backup target") is not None
            ):
                raise SyncError(
                    f"install target identity changed immediately before backup: {name}"
                )
            _move_path(target, backup)
            if (
                _directory_identity(target, label="live install target") is not None
                or _directory_identity(backup, label="backup target")
                != original_target_ids[name]
            ):
                raise SyncError(f"backup move postcondition failed: {name}")
            backed_up.append(name)
            pending_move = None
            _write_backup_receipt(
                backup_root,
                transaction_receipt(status="in-progress", phase="backup"),
            )
        _write_backup_receipt(
            backup_root,
            transaction_receipt(status="in-progress", phase="install"),
        )
        for name in TARGETS:
            target = install_root / name
            if _exists(target):
                raise SyncError(
                    f"install target reappeared during transaction: {target}"
                )
            staged = stage_root / name
            if (
                _directory_identity(staged, label="stage target")
                != staged_target_ids[name]
            ):
                raise SyncError(f"staged target identity changed before install: {name}")
            pending_move = {
                "target": name,
                "direction": "stage-to-install",
            }
            _write_backup_receipt(
                backup_root,
                transaction_receipt(status="in-progress", phase="install"),
            )
            if (
                _directory_identity(target, label="live install target") is not None
                or _directory_identity(staged, label="stage target")
                != staged_target_ids[name]
            ):
                raise SyncError(
                    f"install topology changed immediately before move: {name}"
                )
            _move_path(staged, target)
            if (
                _directory_identity(staged, label="stage target") is not None
                or _directory_identity(target, label="live install target")
                != staged_target_ids[name]
            ):
                raise SyncError(f"install move postcondition failed: {name}")
            installed.append(name)
            pending_move = None
            _write_backup_receipt(
                backup_root,
                transaction_receipt(status="in-progress", phase="install"),
            )
        success_receipt = transaction_receipt(status="applied", phase="complete")
        _write_backup_receipt(backup_root, success_receipt)
    except (Exception, KeyboardInterrupt, SystemExit) as exc:
        journal_errors: list[str] = []
        error_handling_interrupted: BaseException | None = None
        try:
            _write_backup_receipt(
                backup_root,
                transaction_receipt(
                    status="in-progress",
                    phase="rollback",
                    error=str(exc),
                ),
            )
        except BaseException as journal_error:
            journal_errors.append(str(journal_error))
            if isinstance(journal_error, (KeyboardInterrupt, SystemExit)):
                error_handling_interrupted = journal_error

        def record_rollback_move(name: str, action: str) -> None:
            rollback_actions.append(f"{name}:{action}")
            try:
                _write_backup_receipt(
                    backup_root,
                    transaction_receipt(
                        status="in-progress",
                        phase="rollback",
                        error=str(exc),
                        journal_errors=tuple(journal_errors),
                    ),
                )
            except BaseException as journal_error:
                journal_errors.append(str(journal_error))
                if isinstance(journal_error, (KeyboardInterrupt, SystemExit)):
                    raise

        rollback_interrupted: BaseException | None = None
        try:
            rollback_errors = _rollback(
                stage_root,
                install_root,
                backup_root,
                originally_existing,
                original_target_ids,
                staged_target_ids,
                pending_move,
                record_rollback_move,
            )
        except (Exception, KeyboardInterrupt, SystemExit) as rollback_error:
            rollback_errors = (f"rollback interrupted: {rollback_error}",)
            rollback_interrupted = rollback_error
        if not rollback_errors:
            pending_move = None
        detail = ""
        if rollback_errors:
            detail = "; rollback incomplete: " + "; ".join(rollback_errors)
        failure_receipt = transaction_receipt(
            status="rollback-incomplete" if rollback_errors else "rolled-back",
            phase="complete",
            error=str(exc),
            rollback_errors=rollback_errors,
            journal_errors=tuple(journal_errors),
        )
        receipt_error = ""
        try:
            _write_backup_receipt(backup_root, failure_receipt)
        except BaseException as failure_receipt_error:
            receipt_error = f"; failure receipt unavailable: {failure_receipt_error}"
            if isinstance(failure_receipt_error, (KeyboardInterrupt, SystemExit)):
                error_handling_interrupted = failure_receipt_error
        if rollback_errors:
            lock.update(
                {
                    "status": "recovery-required",
                    "pid": None,
                    "receipt_path": str(backup_root / RECEIPT_NAME),
                }
            )
            try:
                _write_lock_info(lock_path, lock)
            except BaseException as lock_error:
                receipt_error += f"; lock update failed: {lock_error}"
                if isinstance(lock_error, (KeyboardInterrupt, SystemExit)):
                    error_handling_interrupted = lock_error
            guard.close()
        else:
            try:
                _cleanup_transaction_stage(
                    stage_root,
                    install_root.parent,
                    stage_root_id,
                    staged_target_ids,
                    targets_expected=True,
                )
            except BaseException as cleanup_error:
                guard.close()
                raise SyncError(
                    "rollback restored the live targets but stage cleanup was "
                    f"refused; run recovery: "
                    f"{_recover_hint(install_root, backup_root / RECEIPT_NAME)}; "
                    f"{cleanup_error}",
                    backup_path=backup_root,
                    preserve_stage=True,
                ) from cleanup_error
            guard.release(lock_path)
        if isinstance(rollback_interrupted, (KeyboardInterrupt, SystemExit)):
            raise rollback_interrupted
        if isinstance(error_handling_interrupted, (KeyboardInterrupt, SystemExit)):
            raise error_handling_interrupted
        if isinstance(exc, (KeyboardInterrupt, SystemExit)):
            raise
        raise SyncError(
            "installation failed and rollback was attempted: "
            f"{exc}{detail}{receipt_error}",
            backup_path=backup_root,
            rollback_errors=rollback_errors,
            preserve_stage=bool(rollback_errors),
        ) from exc

    try:
        _cleanup_transaction_stage(
            stage_root,
            install_root.parent,
            stage_root_id,
            staged_target_ids,
            targets_expected=False,
        )
    except BaseException as exc:
        guard.close()
        if isinstance(exc, (KeyboardInterrupt, SystemExit)):
            raise
        raise SyncError(
            "installation applied but stage cleanup failed; "
            f"run recovery: {_recover_hint(install_root, backup_root / RECEIPT_NAME)}; "
            f"{exc}",
            backup_path=backup_root,
            preserve_stage=True,
        ) from exc
    lock_cleanup_error = ""
    try:
        guard.release(lock_path)
    except SyncError as exc:
        lock_cleanup_error = str(exc)
    if lock_cleanup_error:
        raise SyncError(
            "installation applied but transaction lock cleanup failed; "
            f"run recovery: {_recover_hint(install_root, backup_root / RECEIPT_NAME)}; "
            f"{lock_cleanup_error}",
            backup_path=backup_root,
        )
    return success_receipt


def _validated_identity(value: object, *, label: str) -> tuple[int, int]:
    if (
        not isinstance(value, list)
        or len(value) != 2
        or any(
            not isinstance(item, int) or isinstance(item, bool) or item < 0
            for item in value
        )
    ):
        raise SyncError(f"recovery receipt has an invalid {label}")
    return value[0], value[1]


def _validated_identity_map(
    value: object,
    *,
    label: str,
    expected_names: set[str],
) -> dict[str, tuple[int, int]]:
    if not isinstance(value, dict) or set(value) != expected_names:
        raise SyncError(f"recovery receipt has an invalid {label}")
    identities: dict[str, tuple[int, int]] = {}
    for name, raw_identity in value.items():
        if not isinstance(name, str):
            raise SyncError(f"recovery receipt has an invalid {label}")
        identities[name] = _validated_identity(
            raw_identity,
            label=label,
        )
    return identities


def _validate_recovery_receipt(
    receipt_path: Path,
    backup_parent: Path,
    install_root: Path,
) -> tuple[
    dict[str, object],
    Path,
    Path,
    tuple[int, int],
    frozenset[str],
    dict[str, tuple[int, int]],
    dict[str, tuple[int, int]],
]:
    backup_root = receipt_path.parent
    if backup_root.parent != backup_parent or not backup_root.name.startswith(
        "netops-install-"
    ):
        raise SyncError(f"recovery receipt is outside the backup parent: {receipt_path}")
    backup_id = _directory_identity(backup_root, label="backup root")
    if backup_id is None:
        raise SyncError(f"recovery backup root is missing: {backup_root}")
    if receipt_path != backup_root / RECEIPT_NAME:
        raise SyncError(f"recovery receipt has an unexpected name: {receipt_path}")
    receipt = _read_private_json(receipt_path, label="recovery receipt")
    if receipt.get("install_root") != str(install_root):
        raise SyncError("recovery receipt install_root does not match the requested root")
    if receipt.get("backup_path") != str(backup_root):
        raise SyncError("recovery receipt backup_path does not match its directory")
    if backup_id != _validated_identity(
        receipt.get("backup_root_id"),
        label="backup_root_id",
    ):
        raise SyncError("recovery backup root identity does not match its receipt")
    if receipt.get("targets") != list(TARGETS):
        raise SyncError("recovery receipt target order does not match this synchronizer")
    original_names = receipt.get("originally_existing")
    if (
        not isinstance(original_names, list)
        or any(not isinstance(name, str) for name in original_names)
        or len(set(original_names)) != len(original_names)
        or any(name not in TARGETS for name in original_names)
    ):
        raise SyncError("recovery receipt has invalid originally_existing targets")
    originally_existing = frozenset(original_names)
    original_target_ids = _validated_identity_map(
        receipt.get("original_target_ids"),
        label="original_target_ids",
        expected_names=set(originally_existing),
    )
    staged_target_ids = _validated_identity_map(
        receipt.get("staged_target_ids"),
        label="staged_target_ids",
        expected_names=set(TARGETS),
    )
    stage_value = receipt.get("stage_path")
    if not isinstance(stage_value, str):
        raise SyncError("recovery receipt has an invalid stage_path")
    stage_root = _lexical_absolute(stage_value)
    if stage_root.parent != install_root.parent or not stage_root.name.startswith(
        "netops-install-stage-"
    ):
        raise SyncError(f"recovery stage path is outside the install parent: {stage_root}")
    stage_root_id = _validated_identity(
        receipt.get("stage_root_id"),
        label="stage_root_id",
    )
    current_stage_id = _directory_identity(stage_root, label="stage root")
    if current_stage_id is not None:
        if current_stage_id != stage_root_id:
            raise SyncError("recovery stage root identity does not match its receipt")
        try:
            stage_entries = {entry.name for entry in stage_root.iterdir()}
        except OSError as exc:
            raise SyncError(f"recovery stage root cannot be listed: {exc}") from exc
        if not stage_entries.issubset(set(TARGETS)):
            raise SyncError("recovery stage root contains unexpected entries")
        for name in stage_entries:
            if (
                _directory_identity(stage_root / name, label="stage target")
                != staged_target_ids[name]
            ):
                raise SyncError(
                    f"recovery stage target identity does not match receipt: {name}"
                )
    return (
        receipt,
        backup_root,
        stage_root,
        stage_root_id,
        originally_existing,
        original_target_ids,
        staged_target_ids,
    )


def _acquire_recovery_lock(
    backup_parent: Path,
    install_root: Path,
) -> tuple[Path, _GuardLease, dict[str, object]]:
    guard = _GuardLease(_open_lock_guard(backup_parent, install_root))
    lock_path = _lock_path(backup_parent, install_root)
    try:
        info = lock_path.lstat()
    except FileNotFoundError:
        try:
            _mkdir_durable(lock_path, mode=0o700)
        except BaseException:
            guard.close()
            raise
        lock: dict[str, object] = {
            "version": 1,
            "status": "recovery-active",
            "pid": os.getpid(),
            "install_root": str(install_root),
            "receipt_path": None,
        }
        try:
            _write_lock_info(lock_path, lock)
        except BaseException:
            guard.release(lock_path)
            raise
        return lock_path, guard, lock
    except OSError as exc:
        guard.close()
        raise SyncError(f"transaction lock cannot be inspected: {lock_path}: {exc}") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        guard.close()
        raise SyncError(f"transaction lock must be a real directory: {lock_path}")
    try:
        lock = _read_lock_info(lock_path) or {
            "version": 1,
            "status": "recovery-active",
            "pid": None,
            "install_root": str(install_root),
            "receipt_path": None,
        }
    except BaseException:
        guard.close()
        raise
    if lock.get("install_root") != str(install_root):
        guard.close()
        raise SyncError("transaction lock belongs to a different install root")
    return lock_path, guard, lock


def _recover_install_tree_locked(
    install_root: Path,
    backup_parent: Path,
    lock_path: Path,
    guard: _GuardLease,
    lock: dict[str, object],
    receipt: str | os.PathLike[str] | None,
) -> dict[str, object]:
    explicit_receipt = (
        _lexical_absolute(receipt).resolve() if receipt is not None else None
    )
    locked_receipt = (
        _lexical_absolute(str(lock["receipt_path"])).resolve()
        if isinstance(lock.get("receipt_path"), str)
        else None
    )
    incomplete = _matching_receipts(
        backup_parent,
        install_root,
        statuses=INCOMPLETE_STATUSES,
    )
    incomplete_paths = [path.resolve() for path, _ in incomplete]
    if len(incomplete_paths) > 1:
        raise SyncError(
            "multiple incomplete transactions exist; recovery is ambiguous"
        )
    current_incomplete = incomplete_paths[0] if incomplete_paths else None
    if (
        explicit_receipt is not None
        and locked_receipt is not None
        and explicit_receipt != locked_receipt
    ):
        raise SyncError(
            "explicit recovery receipt does not match the transaction lock receipt"
        )
    if (
        explicit_receipt is not None
        and current_incomplete is not None
        and explicit_receipt != current_incomplete
    ):
        raise SyncError(
            "explicit recovery receipt does not match the incomplete transaction"
        )
    if (
        locked_receipt is not None
        and current_incomplete is not None
        and locked_receipt != current_incomplete
    ):
        raise SyncError(
            "transaction lock receipt does not match the incomplete transaction"
        )
    receipt_path = explicit_receipt or locked_receipt or current_incomplete

    if receipt_path is None:
        stage_value = lock.get("stage_path")
        if stage_value is not None:
            if not isinstance(stage_value, str):
                raise SyncError("transaction lock has an invalid stage_path")
            stale_stage = _lexical_absolute(stage_value)
            if (
                stale_stage.parent != install_root.parent
                or not stale_stage.name.startswith("netops-install-stage-")
            ):
                raise SyncError("transaction lock stage_path is outside install parent")
            stale_stage_id = _validated_identity(
                lock.get("stage_root_id"),
                label="lock stage_root_id",
            )
            stale_target_ids = _validated_identity_map(
                lock.get("staged_target_ids"),
                label="lock staged_target_ids",
                expected_names=set(TARGETS),
            )
            _cleanup_transaction_stage(
                stale_stage,
                install_root.parent,
                stale_stage_id,
                stale_target_ids,
                targets_expected=True,
            )
        elif lock.get("status") != "recovery-active":
            raise SyncError("stale transaction lock is missing stage identity data")

        backup_value = lock.get("backup_path")
        if backup_value is not None:
            if not isinstance(backup_value, str):
                raise SyncError("transaction lock has an invalid backup_path")
            stale_backup = _lexical_absolute(backup_value)
            if (
                stale_backup.parent != backup_parent
                or not stale_backup.name.startswith("netops-install-")
            ):
                raise SyncError("transaction lock backup_path is outside backup parent")
            backup_id = _directory_identity(stale_backup, label="stale backup root")
            if backup_id is not None:
                raw_backup_id = lock.get("backup_root_id")
                expected_backup_id = (
                    _validated_identity(
                        raw_backup_id,
                        label="lock backup_root_id",
                    )
                    if raw_backup_id is not None
                    else None
                )
                if (
                    expected_backup_id is not None
                    and backup_id != expected_backup_id
                ):
                    raise SyncError(
                        "stale backup root identity does not match transaction lock"
                    )
                try:
                    backup_entries = list(stale_backup.iterdir())
                except OSError as exc:
                    raise SyncError(
                        f"stale backup root cannot be listed: {stale_backup}: {exc}"
                    ) from exc
                for entry in backup_entries:
                    if expected_backup_id is None or not (
                        entry.name.startswith(f".{RECEIPT_NAME}-")
                        and entry.name.endswith(".tmp")
                    ):
                        raise SyncError(
                            "stale backup root contains unexpected entries; "
                            f"refusing cleanup: {stale_backup}"
                        )
                    entry_info = entry.lstat()
                    if (
                        stat.S_ISLNK(entry_info.st_mode)
                        or not stat.S_ISREG(entry_info.st_mode)
                    ):
                        raise SyncError(f"stale receipt temporary file is unsafe: {entry}")
                    entry.unlink()
                    _fsync_directory(stale_backup)
                stale_backup.rmdir()
                _fsync_directory(backup_parent)
        guard.release(lock_path)
        return {
            "status": "stale-lock-cleared",
            "install_root": str(install_root),
            "receipt_path": None,
        }

    (
        recovery_receipt,
        backup_root,
        stage_root,
        stage_root_id,
        originally_existing,
        original_target_ids,
        staged_target_ids,
    ) = _validate_recovery_receipt(receipt_path, backup_parent, install_root)
    status = recovery_receipt.get("status")
    if status in FINAL_STATUSES:
        _cleanup_transaction_stage(
            stage_root,
            install_root.parent,
            stage_root_id,
            staged_target_ids,
            targets_expected=status != "applied",
        )
        guard.release(lock_path)
        return {
            **recovery_receipt,
            "recovery_status": "already-complete",
        }
    if status not in INCOMPLETE_STATUSES:
        raise SyncError(f"recovery receipt has unsupported status: {status!r}")

    lock.update(
        {
            "status": "recovery-active",
            "pid": os.getpid(),
            "receipt_path": str(receipt_path),
        }
    )
    _write_lock_info(lock_path, lock)
    raw_actions = recovery_receipt.get("recovery_actions", [])
    if not isinstance(raw_actions, list) or any(
        not isinstance(action, str) for action in raw_actions
    ):
        raise SyncError("recovery receipt has invalid recovery_actions")
    recovery_actions = list(raw_actions)
    raw_pending_move = recovery_receipt.get("pending_move")
    if raw_pending_move is None:
        recovery_pending_move: dict[str, str] | None = None
    elif (
        isinstance(raw_pending_move, dict)
        and set(raw_pending_move) == {"target", "direction"}
        and raw_pending_move.get("target") in TARGETS
        and raw_pending_move.get("direction")
        in {"install-to-backup", "stage-to-install"}
    ):
        recovery_pending_move = {
            "target": str(raw_pending_move["target"]),
            "direction": str(raw_pending_move["direction"]),
        }
    else:
        raise SyncError("recovery receipt has invalid pending_move")

    def recovery_snapshot(status_value: str, phase: str) -> dict[str, object]:
        return {
            **recovery_receipt,
            "status": status_value,
            "phase": phase,
            "recovery_actions": list(recovery_actions),
            "recovery_pid": os.getpid(),
        }

    _write_backup_receipt(
        backup_root,
        recovery_snapshot("in-progress", "recovery"),
    )

    def record_recovery_move(name: str, action: str) -> None:
        recovery_actions.append(f"{name}:{action}")
        _write_backup_receipt(
            backup_root,
            recovery_snapshot("in-progress", "recovery"),
        )

    try:
        recovery_errors = _rollback(
            stage_root,
            install_root,
            backup_root,
            originally_existing,
            original_target_ids,
            staged_target_ids,
            recovery_pending_move,
            record_recovery_move,
        )
    except (Exception, KeyboardInterrupt, SystemExit) as exc:
        recovery_errors = (str(exc),)
        interrupted: BaseException | None = exc
    else:
        interrupted = None

    if recovery_errors:
        failed_receipt = {
            **recovery_snapshot("rollback-incomplete", "recovery"),
            "recovery_errors": list(recovery_errors),
        }
        _write_backup_receipt(backup_root, failed_receipt)
        lock.update({"status": "recovery-required", "pid": None})
        _write_lock_info(lock_path, lock)
        guard.close()
        if isinstance(interrupted, (KeyboardInterrupt, SystemExit)):
            raise interrupted
        raise SyncError(
            "recovery could not restore every original target: "
            + "; ".join(recovery_errors),
            backup_path=backup_root,
            rollback_errors=tuple(recovery_errors),
            preserve_stage=True,
        )

    completed_receipt = recovery_snapshot("recovered", "complete")
    completed_receipt.pop("recovery_errors", None)
    _write_backup_receipt(backup_root, completed_receipt)
    _cleanup_transaction_stage(
        stage_root,
        install_root.parent,
        stage_root_id,
        staged_target_ids,
        targets_expected=True,
    )
    guard.release(lock_path)
    return completed_receipt


def recover_install_tree(
    install: str | os.PathLike[str],
    *,
    receipt: str | os.PathLike[str] | None = None,
) -> dict[str, object]:
    install_root = _existing_real_directory(install, label="install root")
    backup_parent = _prepare_backup_parent(install_root)
    lock_path, guard, lock = _acquire_recovery_lock(backup_parent, install_root)
    try:
        return _recover_install_tree_locked(
            install_root,
            backup_parent,
            lock_path,
            guard,
            lock,
            receipt,
        )
    finally:
        guard.close()


def sync_install_tree(
    source: str | os.PathLike[str],
    install: str | os.PathLike[str],
    *,
    apply: bool = False,
    confirm_manifest_sha256: str | None = None,
) -> dict[str, object]:
    if apply and confirm_manifest_sha256 is None:
        raise SyncError(
            "--apply requires --confirm-manifest-sha256 from a prior dry run"
        )
    if confirm_manifest_sha256 is not None and (
        len(confirm_manifest_sha256) != 64
        or any(
            character not in "0123456789abcdef"
            for character in confirm_manifest_sha256
        )
    ):
        raise SyncError(
            "--confirm-manifest-sha256 must be 64 lowercase hexadecimal characters"
        )
    source_root = _existing_real_directory(source, label="source root")
    install_root = _existing_real_directory(install, label="install root")
    if _is_within(source_root, install_root) or _is_within(install_root, source_root):
        raise SyncError("source and install roots must not contain one another")

    payloads, tracked = _payloads(source_root)
    snapshots = _snapshot_source_payload(source_root, tracked)
    existing_count = len(_preflight_targets(install_root))

    def prepare_stage() -> Path:
        stage_root: Path | None = None
        try:
            stage_root = Path(
                tempfile.mkdtemp(
                    prefix="netops-install-stage-",
                    dir=install_root.parent,
                )
            )
            stage_root.chmod(0o700)
            _fsync_directory(stage_root)
            _fsync_directory(stage_root.parent)
            return stage_root
        except BaseException as exc:
            if stage_root is not None:
                try:
                    _cleanup_stage_root(stage_root, install_root.parent)
                except SyncError:
                    pass
            if isinstance(exc, (KeyboardInterrupt, SystemExit)):
                raise
            raise SyncError(f"stage directory could not be created safely: {exc}") from exc

    def build_stage(stage_root: Path) -> dict[str, object]:
        counts = _stage_payloads(
            source_root,
            stage_root,
            payloads,
            snapshots,
        )
        manifest_sha256 = _manifest_sha256(
            stage_root,
            source_root,
            install_root,
            payloads,
        )
        _verify_source_payload_stable(
            source_root,
            stage_root,
            tracked,
            snapshots,
        )
        receipt_base: dict[str, object] = {
            "manifest_version": 2,
            "source_root": str(source_root),
            "install_root": str(install_root),
            "managed_targets": len(TARGETS),
            "targets": list(TARGETS),
            "source_tracked_files": len(tracked),
            "staged_files": sum(counts.values()),
            "target_file_counts": counts,
            "manifest_sha256": manifest_sha256,
        }
        return receipt_base

    if not apply:
        stage_root = prepare_stage()
        try:
            receipt_base = build_stage(stage_root)
        finally:
            _cleanup_stage_root(stage_root, install_root.parent)
        return {
            **receipt_base,
            "status": "dry-run",
            "backup_path": None,
            "existing_targets": existing_count,
        }

    stage_root = prepare_stage()
    try:
        receipt_base = build_stage(stage_root)
        if confirm_manifest_sha256 is None:
            raise SyncError(
                "--apply requires --confirm-manifest-sha256 from a prior dry run"
            )
        manifest_sha256 = str(receipt_base["manifest_sha256"])
        if not hmac.compare_digest(manifest_sha256, confirm_manifest_sha256):
            raise SyncError(
                "staged manifest does not match --confirm-manifest-sha256: "
                f"expected {confirm_manifest_sha256}, got {manifest_sha256}"
            )
    except BaseException:
        _cleanup_stage_root(stage_root, install_root.parent)
        raise

    def pre_live_check() -> None:
        _verify_source_payload_stable(
            source_root,
            stage_root,
            tracked,
            snapshots,
        )
        current_manifest = _manifest_sha256(
            stage_root,
            source_root,
            install_root,
            payloads,
        )
        if not hmac.compare_digest(current_manifest, manifest_sha256):
            raise SyncError(
                "staged payload changed after manifest confirmation and before apply"
            )

    try:
        return _apply_staged(
            stage_root,
            install_root,
            receipt_base,
            pre_live_check,
        )
    except SyncError as exc:
        if not exc.preserve_stage:
            _cleanup_stage_root(stage_root, install_root.parent)
        raise
    except (KeyboardInterrupt, SystemExit):
        if not _stage_has_incomplete_receipt(stage_root, install_root):
            _cleanup_stage_root(stage_root, install_root.parent)
        raise


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Stage a Git-tracked-only NetOps Skill payload and transactionally "
            "synchronize the root plus five flat installed Skills"
        )
    )
    parser.add_argument("root", nargs="?", default=".")
    parser.add_argument(
        "--install-root",
        required=True,
        help="Directory that directly contains netops and the five netops-* Skills",
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--apply",
        action="store_true",
        help="Apply the staged payload; without this flag the command is a dry run",
    )
    mode.add_argument(
        "--recover",
        action="store_true",
        help="Recover an interrupted apply from its persistent transaction receipt",
    )
    parser.add_argument(
        "--confirm-manifest-sha256",
        help="Manifest SHA-256 printed by a prior dry run; required with --apply",
    )
    parser.add_argument(
        "--recovery-receipt",
        help="Explicit sync-receipt.json to use with --recover",
    )
    args = parser.parse_args(argv)
    try:
        if args.recover:
            if args.confirm_manifest_sha256 is not None:
                raise SyncError(
                    "--confirm-manifest-sha256 cannot be used with --recover"
                )
            receipt = recover_install_tree(
                args.install_root,
                receipt=args.recovery_receipt,
            )
        else:
            if args.recovery_receipt is not None:
                raise SyncError("--recovery-receipt requires --recover")
            receipt = sync_install_tree(
                args.root,
                args.install_root,
                apply=args.apply,
                confirm_manifest_sha256=args.confirm_manifest_sha256,
            )
    except SyncError as exc:
        print(
            json.dumps(
                {
                    "status": "error",
                    "backup_path": (
                        str(exc.backup_path) if exc.backup_path is not None else None
                    ),
                    "error": str(exc),
                    "rollback_errors": list(exc.rollback_errors),
                },
                ensure_ascii=False,
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 1
    print(json.dumps(receipt, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
