#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import re
import stat
import subprocess
import sys
import tarfile
import tempfile
import unicodedata
import venv
import zipfile
from pathlib import Path, PurePosixPath


SETUPTOOLS_REQUIREMENT = "setuptools==83.0.0"
VERSION_LINE = re.compile(
    r'^version\s*=\s*"([0-9]+\.[0-9]+\.[0-9]+)"\s*$', re.MULTILINE
)
REQUIRES_PYTHON_LINE = re.compile(
    r'^requires-python\s*=\s*"([^"]+)"\s*$', re.MULTILINE
)
REQUIRED_SDIST_FILES = (
    "README.md",
    "README.zh-CN.md",
    "CHANGELOG.md",
    "CONTRIBUTING.md",
    "SECURITY.md",
    "CODE_OF_CONDUCT.md",
    "LICENSE",
    "SKILL.md",
    "pyproject.toml",
    "MANIFEST.in",
    ".github/workflows/test.yml",
    "scripts/installed_smoke.py",
    "scripts/package_smoke.py",
)
REQUIRED_SDIST_DIRECTORIES = (
    "agents",
    "examples",
    "netops_core",
    "references",
    "schemas",
    "scripts",
    "skills",
    "tests",
)
FORBIDDEN_SDIST_PARTS = {
    ".git",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    "__pycache__",
    "build",
    "diagnostics",
    "dist",
}
MAX_SDIST_MEMBERS = 20_000
MAX_SDIST_MEMBER_BYTES = 64 * 1_048_576
MAX_SDIST_UNPACKED_BYTES = 512 * 1_048_576
WINDOWS_FORBIDDEN_CHARACTERS = frozenset('<>:"|?*')
WINDOWS_RESERVED_STEMS = frozenset(
    {
        "aux",
        "con",
        "nul",
        "prn",
        *(f"com{index}" for index in range(1, 10)),
        *(f"lpt{index}" for index in range(1, 10)),
    }
)


def _regular_artifact(path: Path, *, label: str) -> Path:
    try:
        info = path.lstat()
    except OSError as exc:
        raise RuntimeError(f"{label} cannot be inspected: {path}") from exc
    if path.is_symlink() or not stat.S_ISREG(info.st_mode):
        raise RuntimeError(f"{label} must be a regular file: {path}")
    return path.resolve()


def _safe_archive_member_path(name: str, *, label: str) -> PurePosixPath:
    if not isinstance(name, str) or not name or "\\" in name:
        raise RuntimeError(f"{label} contains an invalid member path")
    if any(ord(character) < 32 or ord(character) == 127 for character in name):
        raise RuntimeError(f"{label} member path contains control characters")
    path = PurePosixPath(name)
    if path.is_absolute() or not path.parts or ".." in path.parts:
        raise RuntimeError(f"{label} member path escapes the archive root: {name!r}")
    for component in path.parts:
        portable_component = unicodedata.normalize("NFKC", component)
        if any(
            character in WINDOWS_FORBIDDEN_CHARACTERS
            for character in portable_component
        ):
            raise RuntimeError(
                f"{label} member path is unsafe on Windows: {name!r}"
            )
        if portable_component.endswith((" ", ".")):
            raise RuntimeError(
                f"{label} member path has a Windows-ambiguous suffix: {name!r}"
            )
        if portable_component.split(".", 1)[0].casefold() in WINDOWS_RESERVED_STEMS:
            raise RuntimeError(
                f"{label} member path uses a Windows device name: {name!r}"
            )
    return path


def _safe_tar_member_path(member: tarfile.TarInfo) -> PurePosixPath:
    return _safe_archive_member_path(member.name, label="sdist")


def _validate_sdist_members(members: list[tarfile.TarInfo]) -> str:
    if not members:
        raise RuntimeError("sdist archive is empty")
    if len(members) > MAX_SDIST_MEMBERS:
        raise RuntimeError("sdist archive contains too many members")
    seen: set[str] = set()
    portable_seen: set[str] = set()
    top_levels: set[str] = set()
    portable_file_paths: set[str] = set()
    unpacked_bytes = 0
    for member in members:
        path = _safe_tar_member_path(member)
        normalized = path.as_posix()
        portable = unicodedata.normalize("NFKC", normalized).casefold()
        if normalized in seen or portable in portable_seen:
            raise RuntimeError(f"sdist contains a duplicate member path: {member.name!r}")
        seen.add(normalized)
        portable_seen.add(portable)
        top_levels.add(path.parts[0])
        if member.issym() or member.islnk():
            raise RuntimeError(f"sdist contains a link member: {member.name!r}")
        if member.isdev() or member.isfifo():
            raise RuntimeError(f"sdist contains a device member: {member.name!r}")
        if not (member.isfile() or member.isdir()):
            raise RuntimeError(f"sdist contains an unsupported member: {member.name!r}")
        if member.mode & 0o7000:
            raise RuntimeError(f"sdist member has unsafe special mode bits: {member.name!r}")
        if member.isfile():
            if member.size < 0 or member.size > MAX_SDIST_MEMBER_BYTES:
                raise RuntimeError(f"sdist member is unexpectedly large: {member.name!r}")
            unpacked_bytes += member.size
            if unpacked_bytes > MAX_SDIST_UNPACKED_BYTES:
                raise RuntimeError("sdist archive expands beyond the byte limit")
            portable_file_paths.add(portable)
    if len(top_levels) != 1:
        raise RuntimeError("sdist must contain exactly one top-level directory")
    for path in portable_file_paths:
        parts = path.split("/")
        if any(
            "/".join(parts[:index]) in portable_file_paths
            for index in range(1, len(parts))
        ):
            raise RuntimeError(f"sdist file shadows a parent directory: {path!r}")
    return next(iter(top_levels))


def _safe_extract_sdist(artifact: Path, destination: Path) -> Path:
    destination.mkdir(parents=True, exist_ok=False)
    with tarfile.open(artifact, mode="r:gz") as archive:
        members = archive.getmembers()
        top_level = _validate_sdist_members(members)
        if sys.version_info >= (3, 12):
            archive.extractall(destination, members=members, filter="data")
        else:
            # Python 3.10/3.11 lack filters; every member passed the strict
            # path, type, size, mode, and single-root validation above.
            archive.extractall(  # nosec B202
                destination,
                members=members,
            )
    extracted_root = destination / top_level
    try:
        root_info = extracted_root.lstat()
    except OSError as exc:
        raise RuntimeError("sdist top-level directory was not extracted") from exc
    if extracted_root.is_symlink() or not stat.S_ISDIR(root_info.st_mode):
        raise RuntimeError("sdist top-level member must be a real directory")
    for candidate in extracted_root.rglob("*"):
        info = candidate.lstat()
        if candidate.is_symlink() or not (
            stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)
        ):
            raise RuntimeError("sdist extraction created a non-regular member")
    return extracted_root


def _validate_sdist_layout(source_root: Path) -> None:
    for relative in REQUIRED_SDIST_FILES:
        candidate = source_root / relative
        if candidate.is_symlink() or not candidate.is_file():
            raise RuntimeError(f"sdist is missing required file: {relative}")
    for relative in REQUIRED_SDIST_DIRECTORIES:
        candidate = source_root / relative
        if candidate.is_symlink() or not candidate.is_dir():
            raise RuntimeError(f"sdist is missing required directory: {relative}")
        if not any(candidate.iterdir()):
            raise RuntimeError(f"sdist required directory is empty: {relative}")
    for candidate in source_root.rglob("*"):
        relative = candidate.relative_to(source_root)
        if any(part in FORBIDDEN_SDIST_PARTS for part in relative.parts):
            raise RuntimeError(f"sdist contains forbidden path: {relative}")
        if candidate.name == ".project-notes.md" or candidate.suffix in {".pyc", ".pyo"}:
            raise RuntimeError(f"sdist contains forbidden file: {relative}")


def _read_source_python_modules(source_root: Path) -> dict[str, bytes]:
    package_root = source_root / "netops_core"
    modules: dict[str, bytes] = {}
    for candidate in sorted(package_root.rglob("*.py")):
        relative = candidate.relative_to(source_root).as_posix()
        info = candidate.lstat()
        if candidate.is_symlink() or not stat.S_ISREG(info.st_mode):
            raise RuntimeError(f"sdist Python module is not a regular file: {relative}")
        if info.st_size > MAX_SDIST_MEMBER_BYTES:
            raise RuntimeError(f"sdist Python module is unexpectedly large: {relative}")
        modules[relative] = candidate.read_bytes()
    if not modules or "netops_core/__init__.py" not in modules:
        raise RuntimeError("sdist has no complete netops_core Python package")
    return modules


def _read_wheel_python_modules(wheel: Path) -> dict[str, bytes]:
    modules: dict[str, bytes] = {}
    portable_paths: set[str] = set()
    module_bytes = 0
    with zipfile.ZipFile(wheel) as archive:
        members = archive.infolist()
        if len(members) > MAX_SDIST_MEMBERS:
            raise RuntimeError("wheel archive contains too many members")
        for member in members:
            path = _safe_archive_member_path(member.filename, label="wheel")
            normalized = path.as_posix()
            portable = unicodedata.normalize("NFKC", normalized).casefold()
            if portable in portable_paths:
                raise RuntimeError(
                    f"wheel contains a duplicate portable path: {member.filename!r}"
                )
            portable_paths.add(portable)
            if (
                member.is_dir()
                or len(path.parts) < 2
                or path.parts[0] != "netops_core"
                or path.suffix != ".py"
            ):
                continue
            mode = member.external_attr >> 16
            file_type = stat.S_IFMT(mode)
            if file_type not in (0, stat.S_IFREG):
                raise RuntimeError(f"wheel Python module is not regular: {normalized}")
            if member.flag_bits & 0x1:
                raise RuntimeError(f"wheel Python module is encrypted: {normalized}")
            if member.file_size < 0 or member.file_size > MAX_SDIST_MEMBER_BYTES:
                raise RuntimeError(
                    f"wheel Python module is unexpectedly large: {normalized}"
                )
            module_bytes += member.file_size
            if module_bytes > MAX_SDIST_UNPACKED_BYTES:
                raise RuntimeError("wheel Python modules exceed the byte limit")
            with archive.open(member) as stream:
                content = stream.read(MAX_SDIST_MEMBER_BYTES + 1)
            if len(content) != member.file_size:
                raise RuntimeError(
                    f"wheel Python module size does not match metadata: {normalized}"
                )
            modules[normalized] = content
    if not modules or "netops_core/__init__.py" not in modules:
        raise RuntimeError("wheel has no complete netops_core Python package")
    return modules


def _validate_artifact_module_parity(wheel: Path, source_root: Path) -> None:
    source_modules = _read_source_python_modules(source_root)
    wheel_modules = _read_wheel_python_modules(wheel)
    source_paths = set(source_modules)
    wheel_paths = set(wheel_modules)
    missing = sorted(source_paths - wheel_paths)
    extra = sorted(wheel_paths - source_paths)
    changed = sorted(
        path
        for path in source_paths & wheel_paths
        if source_modules[path] != wheel_modules[path]
    )
    if missing or extra or changed:
        details = []
        if missing:
            details.append("missing=" + ",".join(missing[:5]))
        if extra:
            details.append("extra=" + ",".join(extra[:5]))
        if changed:
            details.append("changed=" + ",".join(changed[:5]))
        raise RuntimeError(
            "wheel and sdist netops_core Python modules differ: " + "; ".join(details)
        )
    print("package smoke: wheel and sdist netops_core Python modules match byte-for-byte")


def _find_artifacts(dist_dir: Path) -> tuple[Path, Path]:
    wheels = sorted(dist_dir.glob("netops_skill-*.whl"))
    sdists = sorted(dist_dir.glob("netops_skill-*.tar.gz"))
    if len(wheels) != 1:
        raise RuntimeError(
            f"expected exactly one netops_skill wheel in {dist_dir}, found {len(wheels)}"
        )
    if len(sdists) != 1:
        raise RuntimeError(
            f"expected exactly one netops_skill sdist in {dist_dir}, found {len(sdists)}"
        )
    return (
        _regular_artifact(wheels[0], label="wheel artifact"),
        _regular_artifact(sdists[0], label="source artifact"),
    )


def _venv_python(environment: Path) -> Path:
    if os.name == "nt":
        return environment / "Scripts" / "python.exe"
    return environment / "bin" / "python"


def _venv_scripts(environment: Path) -> Path:
    return environment / ("Scripts" if os.name == "nt" else "bin")


def _run(
    arguments: list[str],
    *,
    cwd: Path,
    environment: dict[str, str],
    label: str,
    timeout: int = 300,
) -> None:
    completed = subprocess.run(
        arguments,
        cwd=cwd,
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        errors="replace",
        timeout=timeout,
        check=False,
    )
    if completed.returncode:
        output = (completed.stderr or completed.stdout).strip()
        if len(output) > 8_000:
            output = output[-8_000:]
        raise RuntimeError(f"{label} failed with exit {completed.returncode}: {output}")


def _run_sdist_tests(source_root: Path, *, temporary_root: Path) -> None:
    isolated_home = temporary_root / "sdist-tests-home"
    isolated_home.mkdir()
    environment = os.environ.copy()
    environment.pop("PYTHONHOME", None)
    environment.pop("PYTHONPATH", None)
    environment.update(
        {
            "HOME": str(isolated_home),
            "USERPROFILE": str(isolated_home),
            "XDG_CONFIG_HOME": str(isolated_home / ".config"),
            "XDG_STATE_HOME": str(isolated_home / ".local" / "state"),
            "LOCALAPPDATA": str(isolated_home / "AppData" / "Local"),
            "APPDATA": str(isolated_home / "AppData" / "Roaming"),
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONNOUSERSITE": "1",
        }
    )
    _run(
        [
            sys.executable,
            "-m",
            "unittest",
            "discover",
            "-s",
            "tests",
            "-v",
        ],
        cwd=source_root,
        environment=environment,
        label="sdist full unittest suite",
        timeout=600,
    )
    print("package smoke: sdist full unittest suite passed from extracted source")


def _smoke_artifact(
    artifact: Path,
    *,
    source_root: Path,
    temporary_root: Path,
    label: str,
    expected_version: str,
    expected_requires_python: str,
) -> None:
    environment_root = temporary_root / label
    virtual_environment = environment_root / "venv"
    working_directory = environment_root / "arbitrary-cwd"
    isolated_home = environment_root / "home"
    working_directory.mkdir(parents=True)
    isolated_home.mkdir()
    venv.EnvBuilder(with_pip=True, clear=False).create(virtual_environment)
    python = _venv_python(virtual_environment)
    scripts = _venv_scripts(virtual_environment)

    child_environment = os.environ.copy()
    child_environment.pop("PYTHONHOME", None)
    child_environment.pop("PYTHONPATH", None)
    child_environment.update(
        {
            "HOME": str(isolated_home),
            "USERPROFILE": str(isolated_home),
            "XDG_CONFIG_HOME": str(isolated_home / ".config"),
            "XDG_STATE_HOME": str(isolated_home / ".local" / "state"),
            "LOCALAPPDATA": str(isolated_home / "AppData" / "Local"),
            "APPDATA": str(isolated_home / "AppData" / "Roaming"),
            "PIP_DISABLE_PIP_VERSION_CHECK": "1",
            "PYTHONDONTWRITEBYTECODE": "1",
            "PATH": str(scripts)
            + os.pathsep
            + child_environment.get("PATH", ""),
        }
    )

    if artifact.name.endswith(".tar.gz"):
        _run(
            [
                str(python),
                "-m",
                "pip",
                "install",
                "--no-deps",
                "--only-binary=:all:",
                SETUPTOOLS_REQUIREMENT,
            ],
            cwd=working_directory,
            environment=child_environment,
            label=f"{label} pinned build-backend install",
        )
    install_arguments = [
        str(python),
        "-m",
        "pip",
        "install",
        "--no-deps",
        "--no-index",
    ]
    if artifact.name.endswith(".tar.gz"):
        install_arguments.append("--no-build-isolation")
    install_arguments.append(str(artifact))
    _run(
        install_arguments,
        cwd=working_directory,
        environment=child_environment,
        label=f"{label} artifact install",
    )
    metadata_smoke = "\n".join(
        (
            "import importlib.metadata",
            "import pathlib",
            "import sys",
            "import netops_core",
            "metadata = importlib.metadata.metadata('netops-skill')",
            "assert importlib.metadata.version('netops-skill') == sys.argv[1]",
            "assert netops_core.__version__ == sys.argv[1]",
            "normalize = lambda value: {item.strip() for item in value.split(',')}",
            "assert normalize(metadata['Requires-Python']) == normalize(sys.argv[2])",
            "module_path = pathlib.Path(netops_core.__file__).resolve()",
            "source_root = pathlib.Path(sys.argv[3]).resolve()",
            "assert not module_path.is_relative_to(source_root)",
        )
    )
    _run(
        [
            str(python),
            "-I",
            "-c",
            metadata_smoke,
            expected_version,
            expected_requires_python,
            str(source_root),
        ],
        cwd=working_directory,
        environment=child_environment,
        label=f"{label} installed metadata isolation",
    )
    _run(
        [str(python), str(source_root / "scripts" / "installed_smoke.py")],
        cwd=working_directory,
        environment=child_environment,
        label=f"{label} installed smoke",
    )
    print(f"package smoke: {label} passed from an isolated arbitrary cwd")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Fresh-install the built wheel and sdist and run installed smoke tests"
    )
    parser.add_argument("root", nargs="?", default=".")
    parser.add_argument("--dist-dir", default="dist")
    args = parser.parse_args(argv)
    root = Path(args.root).resolve()
    dist_dir = Path(args.dist_dir)
    if not dist_dir.is_absolute():
        dist_dir = root / dist_dir
    dist_dir = dist_dir.resolve()
    try:
        wheel, sdist = _find_artifacts(dist_dir)
        with tempfile.TemporaryDirectory(prefix="netops-package-smoke-") as raw:
            temporary_root = Path(raw)
            source_root = _safe_extract_sdist(
                sdist,
                temporary_root / "extracted-sdist",
            )
            _validate_sdist_layout(source_root)
            _validate_artifact_module_parity(wheel, source_root)
            pyproject = (source_root / "pyproject.toml").read_text(encoding="utf-8")
            version_match = VERSION_LINE.search(pyproject)
            requires_python_match = REQUIRES_PYTHON_LINE.search(pyproject)
            if version_match is None or requires_python_match is None:
                raise RuntimeError(
                    "sdist pyproject.toml has no strict version or Requires-Python"
                )
            _run_sdist_tests(source_root, temporary_root=temporary_root)
            _smoke_artifact(
                wheel,
                source_root=source_root,
                temporary_root=temporary_root,
                label="wheel",
                expected_version=version_match.group(1),
                expected_requires_python=requires_python_match.group(1),
            )
            _smoke_artifact(
                sdist,
                source_root=source_root,
                temporary_root=temporary_root,
                label="sdist",
                expected_version=version_match.group(1),
                expected_requires_python=requires_python_match.group(1),
            )
    except (
        OSError,
        RuntimeError,
        subprocess.TimeoutExpired,
        tarfile.TarError,
        zipfile.BadZipFile,
    ) as exc:
        print(f"package smoke failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
