#!/usr/bin/env python3
"""Reject packaging and runtime residue in a directory that ships as the Skill.

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

Bytecode caches are judged by what is committed rather than by what is present.
A checkout is allowed to hold scratch ``__pycache__`` directories from a test
run, but they must never enter history.  A directory with no ``.git`` marker at
all is an installed copy rather than a checkout, so any bytecode cache found
there is reported instead.  The marker is what decides, not whether the ``git``
binary happens to be runnable, so a checkout is never failed for scratch
bytecode just because history could not be read.

Usage::

    python3 scripts/check_install_tree.py [DIRECTORY]
"""

from __future__ import annotations

import argparse
import filecmp
import fnmatch
import os
import re
import subprocess
import sys
from pathlib import Path


SKIP_DIRS = {".git", ".venv"}
BUILD_DIRS = {"build", "dist"}
EGG_INFO_GLOB = "*.egg-info"
BYTECODE_DIR = "__pycache__"
DIAGNOSTICS_DIR = "diagnostics"
GIT_TIMEOUT = 30
PROJECT_VERSION = re.compile(
    r'^version\s*=\s*"([0-9]+\.[0-9]+\.[0-9]+)"\s*$', re.MULTILINE
)
PACKAGE_VERSION = re.compile(
    r'^__version__\s*=\s*"([0-9]+\.[0-9]+\.[0-9]+)"\s*$', re.MULTILINE
)


def _relative(root: Path, path: Path) -> str:
    return path.relative_to(root).as_posix()


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
    bytecode: list[Path] = []
    diagnostics: list[tuple[Path, list[str]]] = []
    for current, directories, filenames in os.walk(root):
        here = Path(current)
        directories[:] = sorted(
            name for name in directories if name not in SKIP_DIRS
        )
        for name in list(directories):
            path = here / name
            if name in BUILD_DIRS:
                build_outputs.append(path)
            elif fnmatch.fnmatch(name, EGG_INFO_GLOB):
                egg_infos.append(path)
            elif name == BYTECODE_DIR:
                bytecode.append(path)
            elif name == DIAGNOSTICS_DIR:
                try:
                    entries = sorted(
                        entry.name
                        for entry in path.iterdir()
                        if not entry.name.startswith(".")
                    )
                except OSError:
                    entries = []
                if entries:
                    diagnostics.append((path, entries))
            else:
                continue
            directories.remove(name)
        egg_infos.extend(
            here / name
            for name in filenames
            if fnmatch.fnmatch(name, EGG_INFO_GLOB)
        )
    return build_outputs, egg_infos, bytecode, diagnostics


def _check_tree(root: Path) -> list[str]:
    build_outputs, egg_infos, bytecode, diagnostics = _walk(root)
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
    if tracked is None:
        if not (root / ".git").exists():
            findings.extend(
                f"{_relative(root, path)}/: compiled bytecode must not ship in "
                "an installed Skill tree; delete it"
                for path in sorted(bytecode)
            )
    else:
        committed = sorted(
            {
                item.rsplit(f"/{BYTECODE_DIR}/", 1)[0] + f"/{BYTECODE_DIR}"
                if f"/{BYTECODE_DIR}/" in item
                else BYTECODE_DIR
                for item in tracked
                if BYTECODE_DIR in item.split("/")
            }
        )
        findings.extend(
            f"{path}/: compiled bytecode is committed; remove it from the "
            "repository and keep it ignored"
            for path in committed
        )
    findings.extend(
        f"{_relative(root, path)}/: runtime diagnostics output must not ship "
        f"with the Skill; delete the collected runs ({', '.join(entries[:5])}"
        + (", ..." if len(entries) > 5 else "")
        + ")"
        for path, entries in sorted(diagnostics)
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


def _check_flat_copies(root: Path, install_root: Path) -> list[str]:
    """Compare each satellite's nested copy with its flat installed twin.

    The router loads ``skills/netops-*/SKILL.md`` by relative path while the
    platform triggers the flat ``netops-*/SKILL.md`` beside the root Skill.  Two
    entry points reading two files is only safe while the files are identical,
    and nothing else can check this: the flat copies live outside the repository,
    so a repository scoped test cannot reach them.
    """

    findings: list[str] = []
    nested_paths = sorted((root / "skills").glob("*/SKILL.md"))
    if not nested_paths:
        return [f"{root}: no nested satellite Skills found under skills/"]
    for nested in nested_paths:
        name = nested.parent.name
        flat = install_root / name / "SKILL.md"
        if not flat.is_file():
            findings.append(
                f"{flat}: flat installation of {name} is missing; the router "
                "and direct triggering would load different Skill sets"
            )
            continue
        if not filecmp.cmp(nested, flat, shallow=False):
            findings.append(
                f"{flat}: differs from {_relative(root, nested)}; the router "
                "and direct triggering would apply different safety rules. "
                f"Re-sync with: cp {nested} {flat}"
            )
    return findings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Reject build output, package metadata, committed bytecode and "
            "runtime diagnostics in a directory that ships as the Skill"
        )
    )
    parser.add_argument("root", nargs="?", default=".")
    parser.add_argument(
        "--install-root",
        help=(
            "Directory holding the flat satellite installations, normally the "
            "parent of an installed Skill tree. When given, every flat "
            "netops-*/SKILL.md must be byte identical to its nested twin."
        ),
    )
    args = parser.parse_args(argv)
    root = Path(args.root).resolve()
    if not root.is_dir():
        print(f"{args.root}: not a directory", file=sys.stderr)
        return 1
    findings = [*_check_tree(root), *_check_versions(root)]
    flat_checked = False
    if args.install_root is not None:
        install_root = Path(args.install_root).expanduser().resolve()
        if not install_root.is_dir():
            findings.append(f"{args.install_root}: not a directory")
        else:
            findings.extend(_check_flat_copies(root, install_root))
            flat_checked = True
    if findings:
        print("\n".join(findings), file=sys.stderr)
        return 1
    version, _ = _read_version(root / "pyproject.toml", PROJECT_VERSION, "pyproject.toml")
    suffix = ", flat copies identical" if flat_checked else ""
    print(f"install tree: clean, version {version} declared consistently{suffix}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
