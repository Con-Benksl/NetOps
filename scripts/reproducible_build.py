#!/usr/bin/env python3
from __future__ import annotations

import argparse
import copy
import gzip
import hashlib
import importlib.metadata
import os
import shutil
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
from dataclasses import dataclass
from pathlib import Path


SCRIPT_DIRECTORY = Path(__file__).resolve().parent
if str(SCRIPT_DIRECTORY) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIRECTORY))

from package_smoke import (  # noqa: E402 - support direct script execution
    _find_artifacts,
    _regular_artifact,
    _validate_sdist_members,
)


EXPECTED_TOOL_VERSIONS = {
    "build": "1.3.0",
    "setuptools": "83.0.0",
}
MINIMUM_ZIP_EPOCH = 315_532_800  # 1980-01-01T00:00:00Z
MAXIMUM_GZIP_EPOCH = 4_294_967_295
BUILD_TIMEOUT_SECONDS = 300
COPY_CHUNK_BYTES = 1_048_576
TIME_PAX_KEYS = frozenset({"atime", "ctime", "mtime"})
DERIVED_PAX_KEYS = frozenset({"path", "size"})
IGNORED_NAMES = {
    ".DS_Store",
    ".git",
    ".mypy_cache",
    ".project-notes.md",
    ".pytest_cache",
    ".ruff_cache",
    "__pycache__",
    "build",
    "diagnostics",
    "dist",
}


@dataclass(frozen=True)
class BuildArtifacts:
    wheel: Path
    sdist: Path


def _source_date_epoch(value: str) -> int:
    try:
        epoch = int(value, 10)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("EPOCH must be a base-10 integer") from exc
    if not MINIMUM_ZIP_EPOCH <= epoch <= MAXIMUM_GZIP_EPOCH:
        raise argparse.ArgumentTypeError(
            "EPOCH must fit both ZIP and gzip timestamps "
            f"({MINIMUM_ZIP_EPOCH}..{MAXIMUM_GZIP_EPOCH})"
        )
    return epoch


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(COPY_CHUNK_BYTES), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _assert_tool_versions() -> None:
    errors = []
    for distribution, expected in EXPECTED_TOOL_VERSIONS.items():
        try:
            actual = importlib.metadata.version(distribution)
        except importlib.metadata.PackageNotFoundError:
            errors.append(f"{distribution} is not installed; expected {expected}")
            continue
        if actual != expected:
            errors.append(f"{distribution}=={actual}; expected {distribution}=={expected}")
    if errors:
        raise RuntimeError("release tooling mismatch: " + "; ".join(errors))


def _ignore_source_entries(_directory: str, names: list[str]) -> set[str]:
    return {name for name in names if _ignored_source_name(name)}


def _ignored_source_name(name: str) -> bool:
    return (
        name in IGNORED_NAMES
        or name.endswith(".egg-info")
        or name.endswith((".pyc", ".pyo"))
    )


def _snapshot_manifest(
    root: Path,
    *,
    ignore_release_artifacts: bool = False,
) -> tuple[tuple[str, str, int, str], ...]:
    entries = []
    for directory, directory_names, file_names in os.walk(root, followlinks=False):
        directory_names.sort()
        file_names.sort()
        current = Path(directory)
        retained_directories = []
        for name in directory_names:
            if ignore_release_artifacts and _ignored_source_name(name):
                continue
            candidate = current / name
            if candidate.is_symlink():
                relative = candidate.relative_to(root).as_posix()
                raise RuntimeError(
                    f"source snapshot contains a non-regular entry: {relative}"
                )
            retained_directories.append(name)
        directory_names[:] = retained_directories
        for name in file_names:
            if ignore_release_artifacts and _ignored_source_name(name):
                continue
            candidate = current / name
            relative = candidate.relative_to(root).as_posix()
            info = candidate.lstat()
            if candidate.is_symlink() or not stat.S_ISREG(info.st_mode):
                raise RuntimeError(
                    f"source snapshot contains a non-regular entry: {relative}"
                )
            entries.append(
                (
                    relative,
                    "executable" if info.st_mode & 0o111 else "regular",
                    info.st_size,
                    _sha256_file(candidate),
                )
            )
    if not entries:
        raise RuntimeError("source snapshot is empty")
    return tuple(entries)


def _copy_source_snapshot(source: Path, destination: Path) -> None:
    before = _snapshot_manifest(source, ignore_release_artifacts=True)
    shutil.copytree(
        source,
        destination,
        symlinks=True,
        ignore=_ignore_source_entries,
    )
    copied = _snapshot_manifest(destination)
    after = _snapshot_manifest(source, ignore_release_artifacts=True)
    if before != copied or copied != after:
        raise RuntimeError("source tree changed while the release snapshot was copied")


def _build_environment(epoch: int, isolation_root: Path) -> dict[str, str]:
    isolation_root.mkdir()
    isolated_home = isolation_root / "home"
    isolated_temporary = isolation_root / "tmp"
    isolated_home.mkdir()
    isolated_temporary.mkdir()
    environment: dict[str, str] = {}

    executable_directory = str(Path(sys.executable).resolve().parent)
    path_entries = [executable_directory]
    if os.name == "nt":
        windows_root = (
            os.environ.get("SYSTEMROOT")
            or os.environ.get("SystemRoot")
            or os.environ.get("WINDIR")
            or r"C:\Windows"
        )
        system32 = Path(windows_root) / "System32"
        environment.update(
            {
                "COMSPEC": str(system32 / "cmd.exe"),
                "PATHEXT": ".COM;.EXE;.BAT;.CMD",
                "SYSTEMROOT": windows_root,
                "SystemRoot": windows_root,
                "WINDIR": windows_root,
            }
        )
        path_entries.extend(
            [
                str(system32),
                str(system32 / "WindowsPowerShell" / "v1.0"),
            ]
        )
    else:
        path_entries.extend(os.defpath.split(os.pathsep))

    environment.update(
        {
            "APPDATA": str(isolated_home / "AppData" / "Roaming"),
            "HOME": str(isolated_home),
            "LANG": "C",
            "LC_ALL": "C",
            "LOCALAPPDATA": str(isolated_home / "AppData" / "Local"),
            "PATH": os.pathsep.join(dict.fromkeys(path_entries)),
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONHASHSEED": "0",
            "PYTHONNOUSERSITE": "1",
            "PYTHONUTF8": "1",
            "SOURCE_DATE_EPOCH": str(epoch),
            "TEMP": str(isolated_temporary),
            "TMP": str(isolated_temporary),
            "TMPDIR": str(isolated_temporary),
            "TZ": "UTC",
            "USERPROFILE": str(isolated_home),
            "XDG_CACHE_HOME": str(isolated_home / ".cache"),
            "XDG_CONFIG_HOME": str(isolated_home / ".config"),
            "XDG_STATE_HOME": str(isolated_home / ".local" / "state"),
        }
    )
    return environment


def _build_once(source: Path, output: Path, *, epoch: int) -> BuildArtifacts:
    output.mkdir()
    isolation_root = output.parent / f"{output.name}-environment"
    try:
        completed = subprocess.run(
            [
                sys.executable,
                "-I",
                "-m",
                "build",
                "--no-isolation",
                "--sdist",
                "--wheel",
                "--outdir",
                str(output),
                str(source),
            ],
            cwd=source,
            env=_build_environment(epoch, isolation_root),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            errors="replace",
            timeout=BUILD_TIMEOUT_SECONDS,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(
            f"isolated source build exceeded {BUILD_TIMEOUT_SECONDS} seconds"
        ) from exc
    if completed.returncode:
        detail = (completed.stderr or completed.stdout).strip()
        if len(detail) > 8_000:
            detail = detail[-8_000:]
        raise RuntimeError(
            f"isolated source build failed with exit {completed.returncode}: {detail}"
        )
    wheel, sdist = _find_artifacts(output)
    return BuildArtifacts(wheel=wheel, sdist=sdist)


def _member_content_digest(archive: tarfile.TarFile, member: tarfile.TarInfo) -> str:
    if not member.isfile():
        return ""
    stream = archive.extractfile(member)
    if stream is None:
        raise RuntimeError(f"sdist member cannot be read: {member.name!r}")
    digest = hashlib.sha256()
    with stream:
        for chunk in iter(lambda: stream.read(COPY_CHUNK_BYTES), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _sdist_content_manifest(
    archive: tarfile.TarFile,
    members: list[tarfile.TarInfo],
) -> tuple[tuple[str, str, int, bool, str, tuple[tuple[str, str], ...]], ...]:
    manifest = []
    for member in members:
        if member.isdir():
            kind = "directory"
        elif member.isreg():
            kind = "file"
        else:
            raise RuntimeError(f"sdist contains a non-canonical type: {member.name!r}")
        manifest.append(
            (
                member.name,
                kind,
                member.size if member.isreg() else 0,
                bool(member.mode & 0o111),
                _member_content_digest(archive, member),
                _semantic_pax_headers(member),
            )
        )
    return tuple(sorted(manifest))


def _semantic_pax_headers(
    member: tarfile.TarInfo,
) -> tuple[tuple[str, str], ...]:
    # tarfile may synthesize path/size PAX records when the base header cannot
    # encode the effective name or size. Those semantics are already bound by
    # the manifest's member.name/member.size fields. Every other non-time PAX
    # value is preserved and compared explicitly.
    return tuple(
        sorted(
            (key, value)
            for key, value in member.pax_headers.items()
            if key not in TIME_PAX_KEYS and key not in DERIVED_PAX_KEYS
        )
    )


def _gzip_header(path: Path) -> tuple[int, int]:
    with path.open("rb") as stream:
        header = stream.read(10)
    if len(header) != 10 or header[:3] != b"\x1f\x8b\x08":
        raise RuntimeError("normalized sdist has no valid gzip header")
    return header[3], struct.unpack("<I", header[4:8])[0]


def _canonical_member(original: tarfile.TarInfo, *, epoch: int) -> tarfile.TarInfo:
    member = copy.copy(original)
    member.uid = 0
    member.gid = 0
    member.uname = ""
    member.gname = ""
    member.mtime = epoch
    member.pax_headers = dict(
        sorted(
            (key, value)
            for key, value in original.pax_headers.items()
            if key not in TIME_PAX_KEYS
        )
    )
    member.linkname = ""
    member.devmajor = 0
    member.devminor = 0
    if member.isdir():
        member.mode = 0o755
        member.size = 0
    else:
        member.mode = 0o755 if original.mode & 0o111 else 0o644
    return member


def _validate_normalized_sdist(
    path: Path,
    *,
    epoch: int,
    expected_manifest: tuple[
        tuple[str, str, int, bool, str, tuple[tuple[str, str], ...]], ...
    ],
) -> None:
    flags, gzip_mtime = _gzip_header(path)
    if flags != 0 or gzip_mtime != epoch:
        raise RuntimeError("normalized sdist has a non-canonical gzip header")

    with tarfile.open(path, mode="r:gz") as archive:
        members = archive.getmembers()
        _validate_sdist_members(members)
        if [member.name for member in members] != sorted(member.name for member in members):
            raise RuntimeError("normalized sdist members are not sorted")
        for member in members:
            if not (member.isdir() or member.isreg()):
                raise RuntimeError(
                    f"normalized sdist contains an unsupported type: {member.name!r}"
                )
            expected_mode = 0o755 if member.isdir() or member.mode & 0o111 else 0o644
            if (
                member.mtime != epoch
                or member.uid != 0
                or member.gid != 0
                or member.uname
                or member.gname
                or member.mode != expected_mode
                or any(key in member.pax_headers for key in TIME_PAX_KEYS)
            ):
                raise RuntimeError(
                    f"normalized sdist has non-canonical metadata: {member.name!r}"
                )
        actual_manifest = _sdist_content_manifest(archive, members)
    if actual_manifest != expected_manifest:
        raise RuntimeError("sdist normalization changed archive content or executable bits")


def normalize_sdist(source: Path, destination: Path, *, epoch: int) -> Path:
    source = _regular_artifact(source, label="source distribution")
    if destination.is_symlink() or destination.exists():
        raise RuntimeError(f"normalized sdist destination already exists: {destination}")
    if not destination.parent.is_dir():
        raise RuntimeError(
            f"normalized sdist destination parent does not exist: {destination.parent}"
        )

    try:
        with tarfile.open(source, mode="r:gz") as archive:
            members = archive.getmembers()
            _validate_sdist_members(members)
            expected_manifest = _sdist_content_manifest(archive, members)
            with destination.open("xb") as raw_output:
                with gzip.GzipFile(
                    filename="",
                    mode="wb",
                    fileobj=raw_output,
                    compresslevel=9,
                    mtime=epoch,
                ) as compressed_output:
                    with tarfile.open(
                        fileobj=compressed_output,
                        mode="w",
                        format=tarfile.PAX_FORMAT,
                    ) as normalized_archive:
                        for original in sorted(members, key=lambda item: item.name):
                            if not (original.isdir() or original.isreg()):
                                raise RuntimeError(
                                    "sdist normalization only supports regular files and "
                                    f"directories: {original.name!r}"
                                )
                            stream = (
                                archive.extractfile(original) if original.isreg() else None
                            )
                            if original.isreg() and stream is None:
                                raise RuntimeError(
                                    f"sdist member cannot be read: {original.name!r}"
                                )
                            try:
                                normalized_archive.addfile(
                                    _canonical_member(original, epoch=epoch),
                                    stream,
                                )
                            finally:
                                if stream is not None:
                                    stream.close()
        _validate_normalized_sdist(
            destination,
            epoch=epoch,
            expected_manifest=expected_manifest,
        )
    except Exception:
        destination.unlink(missing_ok=True)
        raise
    return destination


def _verify_build_pair(
    first: BuildArtifacts,
    second: BuildArtifacts,
    workspace: Path,
    *,
    epoch: int,
) -> BuildArtifacts:
    if first.wheel.name != second.wheel.name or first.sdist.name != second.sdist.name:
        raise RuntimeError("the two builds produced different artifact names")
    first_wheel_hash = _sha256_file(first.wheel)
    second_wheel_hash = _sha256_file(second.wheel)
    if first_wheel_hash != second_wheel_hash:
        raise RuntimeError("wheel is not byte-for-byte reproducible")

    first_directory = workspace / "normalized-a"
    second_directory = workspace / "normalized-b"
    first_directory.mkdir()
    second_directory.mkdir()
    first_sdist = normalize_sdist(
        first.sdist,
        first_directory / first.sdist.name,
        epoch=epoch,
    )
    second_sdist = normalize_sdist(
        second.sdist,
        second_directory / second.sdist.name,
        epoch=epoch,
    )
    if _sha256_file(first_sdist) != _sha256_file(second_sdist):
        raise RuntimeError("normalized sdist is not byte-for-byte reproducible")
    return BuildArtifacts(wheel=first.wheel, sdist=first_sdist)


def _publish_artifacts(artifacts: BuildArtifacts, output: Path) -> BuildArtifacts:
    if output.is_symlink() or output.exists():
        raise RuntimeError(
            f"output directory already exists; refusing to overwrite: {output}"
        )
    if not output.parent.is_dir():
        raise RuntimeError(f"output directory parent does not exist: {output.parent}")

    output.mkdir(mode=0o755)
    try:
        published = []
        for source in (artifacts.wheel, artifacts.sdist):
            source = _regular_artifact(source, label="verified build artifact")
            destination = output / source.name
            with source.open("rb") as input_stream, destination.open("xb") as output_stream:
                shutil.copyfileobj(input_stream, output_stream, length=COPY_CHUNK_BYTES)
            destination.chmod(0o644)
            if _sha256_file(source) != _sha256_file(destination):
                raise RuntimeError(
                    "published artifact failed checksum verification: "
                    f"{source.name}"
                )
            published.append(destination.resolve())
    except Exception:
        shutil.rmtree(output)
        raise
    return BuildArtifacts(wheel=published[0], sdist=published[1])


def build_reproducible_release(root: Path, output: Path, *, epoch: int) -> BuildArtifacts:
    root = root.resolve()
    output = Path(os.path.abspath(output))
    if not root.is_dir() or not (root / "pyproject.toml").is_file():
        raise RuntimeError(f"source root is not a Python project: {root}")
    if output.is_symlink() or output.exists():
        raise RuntimeError(
            f"output directory already exists; refusing to overwrite: {output}"
        )
    if not output.parent.is_dir():
        raise RuntimeError(f"output directory parent does not exist: {output.parent}")
    _assert_tool_versions()

    with tempfile.TemporaryDirectory(prefix="netops-reproducible-build-") as raw:
        workspace = Path(raw)
        snapshot = workspace / "snapshot"
        first_source = workspace / "source-a"
        second_source = workspace / "source-b"
        _copy_source_snapshot(root, snapshot)
        shutil.copytree(snapshot, first_source, symlinks=True)
        shutil.copytree(snapshot, second_source, symlinks=True)
        expected_manifest = _snapshot_manifest(snapshot)
        if (
            _snapshot_manifest(first_source) != expected_manifest
            or _snapshot_manifest(second_source) != expected_manifest
        ):
            raise RuntimeError("the two build inputs do not match the source snapshot")

        first = _build_once(first_source, workspace / "build-a", epoch=epoch)
        second = _build_once(second_source, workspace / "build-b", epoch=epoch)
        verified = _verify_build_pair(first, second, workspace, epoch=epoch)
        if (
            _snapshot_manifest(root, ignore_release_artifacts=True)
            != expected_manifest
        ):
            raise RuntimeError("source tree changed while release artifacts were built")
        published = _publish_artifacts(verified, output)

    return published


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Build two isolated copies, verify the wheel and normalized sdist, "
            "then publish one verified artifact pair"
        )
    )
    parser.add_argument("root", nargs="?", default=".")
    parser.add_argument(
        "--source-date-epoch",
        required=True,
        type=_source_date_epoch,
        metavar="EPOCH",
        help="Required canonical build timestamp as a base-10 Unix epoch",
    )
    parser.add_argument(
        "--output-dir",
        required=True,
        help="New directory for verified artifacts; existing paths are rejected",
    )
    args = parser.parse_args(argv)
    root = Path(args.root).resolve()
    output = Path(args.output_dir)
    if not output.is_absolute():
        output = root / output
    try:
        artifacts = build_reproducible_release(
            root,
            output,
            epoch=args.source_date_epoch,
        )
    except (OSError, RuntimeError, tarfile.TarError, ValueError) as exc:
        print(f"reproducible build failed: {exc}", file=sys.stderr)
        return 1
    print(
        "reproducible build: verified two independent copies and published "
        f"{artifacts.wheel.name} sha256={_sha256_file(artifacts.wheel)}"
    )
    print(
        "reproducible build: published normalized "
        f"{artifacts.sdist.name} sha256={_sha256_file(artifacts.sdist)}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
