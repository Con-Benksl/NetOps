#!/usr/bin/env python3
"""Verify the source tree and the complete installed Skill payload.

``npx skills add`` copies the working tree verbatim, so anything left lying in
this repository is installed alongside the Skill.  A stale 0.2.0 ``build/``,
``dist/`` and ``*.egg-info`` tree once survived here for two days, and agents
grepping the Skill directory read the obsolete contract about half the time.
``.gitignore`` and ``MANIFEST.in`` did not help: they govern Git and the source
distribution, not the install path.

The same stale tree also declared an obsolete version, so the check ends by
confirming that ``netops_core.__version__`` and the ``pyproject.toml`` project
version still agree.  That pairing is the cheapest signal that the payload on
disk is the payload the repository thinks it is shipping.

Cache directories are judged by what is committed rather than by what is
present.  A checkout is allowed to hold scratch caches from a test run, but they
must never enter history.  A directory with no ``.git`` marker at all is an
installed copy rather than a checkout, so any cache found there is reported
instead.  The marker is what decides, not whether the ``git`` binary happens to
be runnable, so a checkout is never failed for scratch caches just because
history could not be read.

With ``--install-root``, Git's tracked-file list is the installation manifest.
Every tracked regular file must have a byte-identical copy under
``INSTALL_ROOT/netops``.  Each flat ``netops-*`` Skill must likewise match the
complete corresponding nested subtree, including companion files.  Directory
walks use ``lstat``/non-following scans so a symlink can never conceal or replace
an installed file.

Usage::

    python3 scripts/check_install_tree.py [DIRECTORY]
"""

from __future__ import annotations

import argparse
import fnmatch
import os
import re
import stat
import subprocess
import sys
from pathlib import Path


SKIP_DIRS = {".git"}
BUILD_DIRS = {"build", "dist"}
EGG_INFO_GLOB = "*.egg-info"
BYTECODE_DIR = "__pycache__"
DIAGNOSTICS_DIR = "diagnostics"
PACKAGING_DIRS = {*BUILD_DIRS, ".eggs"}
PACKAGING_GLOBS = (EGG_INFO_GLOB, "*.dist-info")
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
    BYTECODE_DIR,
    "build",
    DIAGNOSTICS_DIR,
    "dist",
    "htmlcov",
    "node_modules",
}
CACHE_DIRS = RESIDUE_DIRECTORIES - PACKAGING_DIRS - {DIAGNOSTICS_DIR}
RESIDUE_FILE_NAMES = {".DS_Store"}
RESIDUE_FILE_SUFFIXES = {".pyc", ".pyo"}
RESIDUE_FILE_GLOBS = (
    "*.egg",
    "*.tar.gz",
    "*.whl",
    "*.zip",
    ".coverage",
    ".coverage.*",
)
GIT_TIMEOUT = 30
COMPARE_CHUNK_SIZE = 1024 * 1024
PROJECT_VERSION = re.compile(
    r'^version\s*=\s*"([0-9]+\.[0-9]+\.[0-9]+)"\s*$', re.MULTILINE
)
PACKAGE_VERSION = re.compile(
    r'^__version__\s*=\s*"([0-9]+\.[0-9]+\.[0-9]+)"\s*$', re.MULTILINE
)


def _relative(root: Path, path: Path) -> str:
    return path.relative_to(root).as_posix()


def _is_residue_file_name(name: str) -> bool:
    return (
        name in RESIDUE_FILE_NAMES
        or Path(name).suffix in RESIDUE_FILE_SUFFIXES
        or any(fnmatch.fnmatch(name, pattern) for pattern in RESIDUE_FILE_GLOBS)
    )


def _tracked_files(root: Path) -> set[str] | None:
    """Return Git tracked paths under ``root``, or None when Git cannot answer."""

    try:
        completed = subprocess.run(
            ["git", "-C", str(root), "ls-files", "-z"],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=GIT_TIMEOUT,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if completed.returncode != 0:
        return None
    return {
        item
        for item in completed.stdout.decode("utf-8", errors="replace").split("\0")
        if item
    }


def _walk(root: Path):
    """Collect the residue directories, pruning anything already reported."""

    build_outputs: list[Path] = []
    egg_infos: list[Path] = []
    caches: list[Path] = []
    diagnostics: list[tuple[Path, list[str]]] = []
    residue_files: list[Path] = []
    for current, directories, filenames in os.walk(root):
        here = Path(current)
        directories[:] = sorted(
            name
            for name in directories
            if name not in SKIP_DIRS and not (here / name).is_symlink()
        )
        for name in list(directories):
            path = here / name
            if name in PACKAGING_DIRS:
                build_outputs.append(path)
            elif any(fnmatch.fnmatch(name, pattern) for pattern in PACKAGING_GLOBS):
                egg_infos.append(path)
            elif name in CACHE_DIRS:
                caches.append(path)
            elif name == DIAGNOSTICS_DIR:
                try:
                    entries = sorted(
                        entry.name
                        for entry in path.iterdir()
                        if not entry.name.startswith(".")
                    )
                except OSError:
                    entries = []
                diagnostics.append((path, entries))
            else:
                continue
            directories.remove(name)
        egg_infos.extend(
            here / name
            for name in filenames
            if any(fnmatch.fnmatch(name, pattern) for pattern in PACKAGING_GLOBS)
        )
        residue_files.extend(
            here / name
            for name in filenames
            if _is_residue_file_name(name)
        )
    return build_outputs, egg_infos, caches, diagnostics, residue_files


def _check_tree(root: Path) -> list[str]:
    build_outputs, egg_infos, caches, diagnostics, residue_files = _walk(root)
    findings = [
        f"{_relative(root, path)}/: packaging output ships with the Skill and "
        "shadows the current source; delete it and rebuild into a directory "
        "outside the working tree"
        for path in sorted(build_outputs)
    ]
    findings.extend(
        f"{_relative(root, path)}: stale package metadata ships with the Skill "
        "and can declare a version the source no longer has; delete it"
        for path in sorted(egg_infos)
    )
    tracked = _tracked_files(root)
    installed_tree = not (root / ".git").exists()
    if tracked is None:
        if not (root / ".git").exists():
            findings.extend(
                f"{_relative(root, path)}/: cache directories must not ship in "
                "an installed Skill tree; delete it"
                for path in sorted(caches)
            )
    else:
        committed: set[str] = set()
        for item in tracked:
            parts = item.split("/")
            for index, part in enumerate(parts):
                if part in CACHE_DIRS:
                    committed.add("/".join(parts[: index + 1]))
                    break
        findings.extend(
            f"{path}/: a cache directory is committed; remove it from the "
            "repository and keep it ignored"
            for path in sorted(committed)
        )
    findings.extend(
        f"{_relative(root, path)}: generated file residue must not ship with "
        "the Skill; delete it"
        for path in sorted(residue_files)
        if installed_tree
        or (tracked is not None and _relative(root, path) in tracked)
    )
    findings.extend(
        f"{_relative(root, path)}/: runtime diagnostics output must not ship "
        + (
            f"with the Skill; delete the collected runs ({', '.join(entries[:5])}"
            + (", ..." if len(entries) > 5 else "")
            + ")"
            if entries
            else "with an installed Skill tree; delete the directory"
        )
        for path, entries in sorted(diagnostics)
        if entries or installed_tree
    )
    return findings


def _read_version(path: Path, pattern: re.Pattern, label: str) -> tuple[str, str]:
    """Return ``(version, finding)`` for one declared version."""

    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        return "", f"{label}: cannot read the declared version: {exc}"
    match = pattern.search(text)
    if match is None:
        return "", f"{label}: no strict semantic version is declared"
    return match.group(1), ""


def _check_versions(root: Path) -> list[str]:
    project, project_error = _read_version(
        root / "pyproject.toml", PROJECT_VERSION, "pyproject.toml"
    )
    package, package_error = _read_version(
        root / "netops_core/__init__.py", PACKAGE_VERSION, "netops_core/__init__.py"
    )
    findings = [error for error in (project_error, package_error) if error]
    if findings:
        return findings
    if project != package:
        return [
            f"version mismatch: pyproject.toml={project!r}, "
            f"netops_core/__init__.py={package!r}; the installed tree would "
            "declare a version its source does not match"
        ]
    return []


def _path_kind(path: Path) -> str:
    """Classify one path without following a symlink."""

    try:
        mode = path.lstat().st_mode
    except FileNotFoundError:
        return "missing"
    except OSError:
        return "unreadable"
    if stat.S_ISLNK(mode):
        return "symlink"
    if stat.S_ISREG(mode):
        return "regular file"
    if stat.S_ISDIR(mode):
        return "directory"
    return "special file"


def _managed_source_files(
    root: Path, tracked_files: set[str] | None = None
) -> tuple[list[Path], list[str]]:
    """Return the Git-tracked regular-file manifest without following links."""

    tracked = _tracked_files(root) if tracked_files is None else tracked_files
    if tracked is None:
        return [], [
            f"{root}: cannot derive the installation manifest from Git-tracked "
            "source files; run the install check from a Git checkout"
        ]

    managed: list[Path] = []
    findings: list[str] = []
    for raw in sorted(tracked):
        relative = Path(raw)
        if not raw or relative.is_absolute() or ".." in relative.parts:
            findings.append(f"{raw!r}: unsafe path in Git-tracked manifest")
            continue

        current = root
        invalid_ancestor = False
        for part in relative.parts[:-1]:
            current /= part
            kind = _path_kind(current)
            if kind != "directory":
                findings.append(
                    f"{current}: tracked source path has a {kind} ancestor; "
                    "the installation checker will not follow it"
                )
                invalid_ancestor = True
                break
        if invalid_ancestor:
            continue

        source = root / relative
        kind = _path_kind(source)
        if kind != "regular file":
            findings.append(
                f"{source}: Git tracks this path but the working tree has {kind}; "
                "only regular files can enter the installation manifest"
            )
            continue
        managed.append(relative)
    if not managed:
        findings.append(f"{root}: Git-tracked installation manifest is empty")
    return managed, findings


def _inventory_tree(root: Path) -> tuple[dict[Path, str], list[str]]:
    """Inventory ``root`` with non-following directory scans."""

    kind = _path_kind(root)
    if kind != "directory":
        return {}, [f"{root}: expected an installed directory, found {kind}"]

    inventory: dict[Path, str] = {}
    findings: list[str] = []
    pending = [(root, Path())]
    while pending:
        directory, relative_directory = pending.pop()
        try:
            with os.scandir(directory) as entries:
                children = sorted(entries, key=lambda entry: entry.name)
        except OSError as exc:
            findings.append(f"{directory}: cannot inspect installed directory: {exc}")
            continue
        for entry in children:
            relative = relative_directory / entry.name
            try:
                if entry.is_symlink():
                    entry_kind = "symlink"
                elif entry.is_file(follow_symlinks=False):
                    entry_kind = "regular file"
                elif entry.is_dir(follow_symlinks=False):
                    entry_kind = "directory"
                else:
                    entry_kind = "special file"
            except OSError:
                entry_kind = "unreadable"
            inventory[relative] = entry_kind
            if entry_kind == "directory":
                pending.append((Path(entry.path), relative))
    return inventory, findings


def _expected_directories(files: list[Path]) -> set[Path]:
    expected: set[Path] = set()
    for relative in files:
        for parent in relative.parents:
            if parent == Path():
                break
            expected.add(parent)
    return expected


def _residue_root(relative: Path) -> tuple[Path, str] | None:
    """Return the first forbidden installed-tree component, if any."""

    parts: list[str] = []
    for part in relative.parts:
        parts.append(part)
        path = Path(*parts)
        if part in PACKAGING_DIRS or any(
            fnmatch.fnmatch(part, pattern) for pattern in PACKAGING_GLOBS
        ):
            return path, "packaging residue"
        if part == DIAGNOSTICS_DIR:
            return path, "runtime diagnostics"
        if part in CACHE_DIRS:
            return path, "cache directory"
    if _is_residue_file_name(relative.name):
        return relative, "generated file residue"
    return None


def _open_regular_file(path: Path) -> tuple[int, int]:
    """Open one comparison input without following its final path component."""

    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    mode = os.fstat(descriptor).st_mode
    if not stat.S_ISREG(mode):
        os.close(descriptor)
        raise OSError(f"{path}: comparison input is not a regular file")
    return descriptor, mode


def _compare_regular_files(source: Path, target: Path) -> tuple[bool, int, int]:
    """Compare bytes and normalized executable modes through safe handles."""

    source_descriptor, source_mode = _open_regular_file(source)
    try:
        target_descriptor, target_mode = _open_regular_file(target)
    except OSError:
        os.close(source_descriptor)
        raise
    with os.fdopen(source_descriptor, "rb") as source_file, os.fdopen(
        target_descriptor, "rb"
    ) as target_file:
        while True:
            source_chunk = source_file.read(COMPARE_CHUNK_SIZE)
            target_chunk = target_file.read(COMPARE_CHUNK_SIZE)
            if source_chunk != target_chunk:
                identical = False
                break
            if not source_chunk:
                identical = True
                break
    return (
        identical,
        0o755 if source_mode & 0o111 else 0o644,
        0o755 if target_mode & 0o111 else 0o644,
    )


def _compare_managed_tree(
    source_root: Path,
    target_root: Path,
    managed_files: list[Path],
    *,
    label: str,
) -> list[str]:
    """Compare one installed tree to a regular-file source manifest."""

    inventory, findings = _inventory_tree(target_root)
    if _path_kind(target_root) != "directory":
        return findings

    expected_files = set(managed_files)
    expected_directories = _expected_directories(managed_files)

    for relative in sorted(expected_directories):
        kind = inventory.get(relative, "missing")
        if kind not in {"missing", "directory"}:
            findings.append(
                f"{target_root / relative}: expected a directory for {label}, "
                f"found {kind}; symlinks are not followed"
            )

    for relative in sorted(expected_files):
        source = source_root / relative
        target = target_root / relative
        kind = inventory.get(relative, "missing")
        if kind == "missing":
            findings.append(
                f"{target}: managed file is missing from {label}; source is {source}"
            )
        elif kind != "regular file":
            findings.append(
                f"{target}: expected a regular file for {label}, found {kind}; "
                "symlinks are not followed"
            )
        else:
            try:
                identical, source_executable, target_executable = (
                    _compare_regular_files(source, target)
                )
            except OSError as exc:
                findings.append(f"{target}: cannot compare managed file: {exc}")
                continue
            if not identical:
                findings.append(
                    f"{target}: content differs from managed source {source}"
                )
            if source_executable != target_executable:
                findings.append(
                    f"{target}: executable bits differ from managed source {source}; "
                    f"source={source_executable:#05o}, installed={target_executable:#05o}"
                )

    residue_roots: dict[Path, str] = {}
    for relative in inventory:
        residue = _residue_root(relative)
        if residue is not None:
            residue_path, description = residue
            residue_roots.setdefault(residue_path, description)
    for relative, description in sorted(residue_roots.items()):
        findings.append(
            f"{target_root / relative}: forbidden {description} in installed tree"
        )

    for relative, kind in sorted(inventory.items()):
        if relative in expected_files or relative in expected_directories:
            continue
        if any(
            relative == residue or residue in relative.parents
            for residue in residue_roots
        ):
            continue
        findings.append(
            f"{target_root / relative}: unmanaged extra {kind} in {label}"
        )
    return findings


def _satellite_manifests(managed_files: list[Path]) -> dict[str, list[Path]]:
    manifests: dict[str, list[Path]] = {}
    for relative in managed_files:
        if (
            len(relative.parts) >= 3
            and relative.parts[0] == "skills"
            and relative.parts[1].startswith("netops-")
        ):
            name = relative.parts[1]
            manifests.setdefault(name, []).append(Path(*relative.parts[2:]))
    return {name: sorted(files) for name, files in sorted(manifests.items())}


def _check_flat_copies_from_manifest(
    root: Path,
    install_root: Path,
    managed_files: list[Path],
) -> list[str]:
    """Compare every flat satellite with its complete nested source subtree."""

    findings: list[str] = []
    manifests = _satellite_manifests(managed_files)
    if not manifests:
        return [f"{root}: no tracked satellite Skills found under skills/netops-*/"]
    for name, flat_files in manifests.items():
        findings.extend(
            _compare_managed_tree(
                root / "skills" / name,
                install_root / name,
                flat_files,
                label=f"flat {name} Skill",
            )
        )

    try:
        with os.scandir(install_root) as entries:
            top_level = sorted(entries, key=lambda entry: entry.name)
    except OSError as exc:
        findings.append(f"{install_root}: cannot inspect installation root: {exc}")
        return findings
    for entry in top_level:
        if not entry.name.startswith("netops-") or entry.name in manifests:
            continue
        kind = _path_kind(Path(entry.path))
        findings.append(
            f"{entry.path}: unmanaged extra {kind} named like a flat NetOps Skill"
        )
    return findings


def _check_flat_copies(
    root: Path,
    install_root: Path,
    tracked_files: set[str] | None = None,
) -> list[str]:
    """Compatibility entry point for checking only the flat Skill copies."""

    managed, findings = _managed_source_files(root, tracked_files)
    if findings:
        return findings
    return _check_flat_copies_from_manifest(root, install_root, managed)


def _check_installed_copies(
    root: Path,
    install_root: Path,
    tracked_files: set[str] | None = None,
) -> list[str]:
    """Check the monolithic installation and all flat workflow copies."""

    managed, findings = _managed_source_files(root, tracked_files)
    if findings:
        return findings
    findings.extend(
        _compare_managed_tree(
            root,
            install_root / "netops",
            managed,
            label="monolithic netops Skill",
        )
    )
    findings.extend(_check_flat_copies_from_manifest(root, install_root, managed))
    return findings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Reject source residue and verify every Git-tracked file in the "
            "monolithic and flat installed Skill trees"
        )
    )
    parser.add_argument("root", nargs="?", default=".")
    parser.add_argument(
        "--install-root",
        help=(
            "Parent directory holding installed Skills. When given, netops/ "
            "must match every Git-tracked source file and every flat netops-* "
            "directory must match its complete nested subtree."
        ),
    )
    args = parser.parse_args(argv)
    root = Path(os.path.abspath(os.path.expanduser(args.root)))
    root_kind = _path_kind(root)
    if root_kind != "directory":
        print(f"{args.root}: expected a directory, found {root_kind}", file=sys.stderr)
        return 1
    findings = [*_check_tree(root), *_check_versions(root)]
    flat_checked = False
    if args.install_root is not None:
        install_root = Path(
            os.path.abspath(os.path.expanduser(args.install_root))
        )
        install_root_kind = _path_kind(install_root)
        if install_root_kind != "directory":
            findings.append(
                f"{args.install_root}: expected an installation-root directory, "
                f"found {install_root_kind}; symlinks are not followed"
            )
        else:
            findings.extend(_check_installed_copies(root, install_root))
            flat_checked = True
    if findings:
        print("\n".join(findings), file=sys.stderr)
        return 1
    version, _ = _read_version(root / "pyproject.toml", PROJECT_VERSION, "pyproject.toml")
    suffix = ", installed payload and flat copies identical" if flat_checked else ""
    print(f"install tree: clean, version {version} declared consistently{suffix}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
