import argparse
import gzip
import io
import os
import struct
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts import reproducible_build
from scripts.reproducible_build import (
    BuildArtifacts,
    _assert_tool_versions,
    _build_environment,
    _copy_source_snapshot,
    _publish_artifacts,
    _sha256_file,
    _source_date_epoch,
    _verify_build_pair,
    normalize_sdist,
)


EPOCH = 1_720_000_000


def _directory(name: str, *, variant: int) -> tuple[tarfile.TarInfo, None]:
    member = tarfile.TarInfo(name)
    member.type = tarfile.DIRTYPE
    member.mode = 0o700 if variant == 1 else 0o755
    member.uid = 501 if variant == 1 else 1001
    member.gid = 20 if variant == 1 else 1001
    member.uname = "builder-a" if variant == 1 else "builder-b"
    member.gname = "staff" if variant == 1 else "runner"
    member.mtime = 1_784_561_535.125 if variant == 1 else 1_784_561_540.875
    member.pax_headers = {
        "atime": str(member.mtime + 1),
        "mtime": str(member.mtime),
    }
    return member, None


def _regular(
    name: str,
    content: bytes,
    *,
    variant: int,
    executable: bool,
    pax_note: str = "preserved-note",
) -> tuple[tarfile.TarInfo, bytes]:
    member = tarfile.TarInfo(name)
    member.size = len(content)
    if executable:
        member.mode = 0o700 if variant == 1 else 0o755
    else:
        member.mode = 0o600 if variant == 1 else 0o664
    member.uid = 501 if variant == 1 else 1001
    member.gid = 20 if variant == 1 else 1001
    member.uname = "builder-a" if variant == 1 else "builder-b"
    member.gname = "staff" if variant == 1 else "runner"
    member.mtime = 1_784_561_535.25 if variant == 1 else 1_784_561_540.75
    member.pax_headers = {
        "ctime": str(member.mtime + 2),
        "mtime": str(member.mtime),
        "netops.note": pax_note,
    }
    ordered_extra = (
        (("netops.zeta", "z"), ("netops.alpha", "a"))
        if variant == 1
        else (("netops.alpha", "a"), ("netops.zeta", "z"))
    )
    member.pax_headers.update(ordered_extra)
    member.pax_headers.update({"path": name, "size": str(len(content))})
    return member, content


def write_sdist(
    path: Path,
    *,
    variant: int,
    metadata: bytes = b"Name: example\nVersion: 1.0.0\n",
    executable: bool = True,
    pax_note: str = "preserved-note",
) -> None:
    members = [
        _directory("example-1.0.0", variant=variant),
        _directory("example-1.0.0/scripts", variant=variant),
        _regular(
            "example-1.0.0/PKG-INFO",
            metadata,
            variant=variant,
            executable=False,
            pax_note=pax_note,
        ),
        _regular(
            "example-1.0.0/scripts/tool.py",
            b"#!/usr/bin/env python3\nprint('ok')\n",
            variant=variant,
            executable=executable,
            pax_note=pax_note,
        ),
    ]
    if variant == 2:
        members.reverse()
    with path.open("wb") as raw:
        with gzip.GzipFile(
            filename=f"source-{variant}.tar",
            mode="wb",
            fileobj=raw,
            mtime=EPOCH + variant,
        ) as compressed:
            with tarfile.open(
                fileobj=compressed,
                mode="w",
                format=tarfile.PAX_FORMAT,
            ) as archive:
                for member, content in members:
                    archive.addfile(
                        member,
                        io.BytesIO(content) if content is not None else None,
                    )


class ReproducibleSdistTests(unittest.TestCase):
    def test_normalization_removes_host_time_order_and_gzip_drift(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            first = root / "first.tar.gz"
            second = root / "second.tar.gz"
            normalized_first = root / "normalized-first.tar.gz"
            normalized_second = root / "normalized-second.tar.gz"
            write_sdist(first, variant=1)
            write_sdist(second, variant=2)

            normalize_sdist(first, normalized_first, epoch=EPOCH)
            normalize_sdist(second, normalized_second, epoch=EPOCH)

            self.assertEqual(normalized_first.read_bytes(), normalized_second.read_bytes())
            header = normalized_first.read_bytes()[:10]
            self.assertEqual(header[:4], b"\x1f\x8b\x08\x00")
            self.assertEqual(struct.unpack("<I", header[4:8])[0], EPOCH)
            with tarfile.open(normalized_first, mode="r:gz") as archive:
                members = archive.getmembers()
                self.assertEqual(
                    [member.name for member in members],
                    sorted(member.name for member in members),
                )
                for member in members:
                    self.assertEqual(member.mtime, EPOCH)
                    self.assertEqual((member.uid, member.gid), (0, 0))
                    self.assertEqual((member.uname, member.gname), ("", ""))
                    self.assertFalse(
                        {"atime", "ctime", "mtime"} & set(member.pax_headers)
                    )
                    if member.isfile():
                        self.assertEqual(
                            member.pax_headers.get("netops.note"),
                            "preserved-note",
                        )
                        self.assertEqual(member.pax_headers.get("netops.alpha"), "a")
                        self.assertEqual(member.pax_headers.get("netops.zeta"), "z")
                    self.assertEqual(
                        member.mode,
                        0o755 if member.isdir() or member.name.endswith("tool.py") else 0o644,
                    )

    def test_normalization_does_not_hide_content_or_executable_changes(self):
        cases = (
            (b"Name: changed\nVersion: 1.0.0\n", True, "preserved-note"),
            (b"Name: example\nVersion: 1.0.0\n", False, "preserved-note"),
            (b"Name: example\nVersion: 1.0.0\n", True, "changed-note"),
        )
        for index, (metadata, executable, pax_note) in enumerate(cases):
            with self.subTest(case=index), tempfile.TemporaryDirectory() as raw:
                root = Path(raw)
                first = root / "first.tar.gz"
                second = root / "second.tar.gz"
                normalized_first = root / "normalized-first.tar.gz"
                normalized_second = root / "normalized-second.tar.gz"
                write_sdist(first, variant=1)
                write_sdist(
                    second,
                    variant=2,
                    metadata=metadata,
                    executable=executable,
                    pax_note=pax_note,
                )
                normalize_sdist(first, normalized_first, epoch=EPOCH)
                normalize_sdist(second, normalized_second, epoch=EPOCH)
                self.assertNotEqual(
                    _sha256_file(normalized_first),
                    _sha256_file(normalized_second),
                )

    def test_normalization_rejects_unsafe_member_and_existing_destination(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            source = root / "unsafe.tar.gz"
            destination = root / "normalized.tar.gz"
            with tarfile.open(source, mode="w:gz") as archive:
                top, _ = _directory("example-1.0.0", variant=1)
                archive.addfile(top)
                unsafe, content = _regular(
                    "example-1.0.0/../escape",
                    b"escape\n",
                    variant=1,
                    executable=False,
                    pax_note="unsafe",
                )
                archive.addfile(unsafe, io.BytesIO(content))
            with self.assertRaisesRegex(RuntimeError, "escapes the archive root"):
                normalize_sdist(source, destination, epoch=EPOCH)
            self.assertFalse(destination.exists())

            safe = root / "safe.tar.gz"
            write_sdist(safe, variant=1)
            destination.write_bytes(b"keep")
            with self.assertRaisesRegex(RuntimeError, "already exists"):
                normalize_sdist(safe, destination, epoch=EPOCH)
            self.assertEqual(destination.read_bytes(), b"keep")


class ReproducibleBuildGateTests(unittest.TestCase):
    def test_epoch_is_required_to_fit_zip_and_gzip(self):
        self.assertEqual(_source_date_epoch(str(EPOCH)), EPOCH)
        for value in ("not-an-integer", "0", str(2**32)):
            with self.subTest(value=value), self.assertRaises(
                argparse.ArgumentTypeError
            ):
                _source_date_epoch(value)

    def test_snapshot_copy_rejects_a_concurrent_source_change(self):
        initial = (("README.md", "regular", 4, "before"),)
        changed = (("README.md", "regular", 5, "after"),)
        with patch.object(
            reproducible_build,
            "_snapshot_manifest",
            side_effect=(initial, initial, changed),
        ), patch.object(reproducible_build.shutil, "copytree"):
            with self.assertRaisesRegex(RuntimeError, "changed while"):
                _copy_source_snapshot(Path("source"), Path("snapshot"))

    def test_tool_versions_are_exact(self):
        expected = {"build": "1.3.0", "setuptools": "83.0.0"}
        with patch.object(
            reproducible_build.importlib.metadata,
            "version",
            side_effect=lambda name: expected[name],
        ):
            _assert_tool_versions()
        expected["build"] = "1.2.2"
        with patch.object(
            reproducible_build.importlib.metadata,
            "version",
            side_effect=lambda name: expected[name],
        ):
            with self.assertRaisesRegex(RuntimeError, "build==1.2.2"):
                _assert_tool_versions()

    def test_build_environment_does_not_inherit_unrelated_secrets(self):
        with tempfile.TemporaryDirectory() as raw:
            isolation_root = Path(raw) / "isolated"
            with patch.dict(
                os.environ,
                {
                    "NETOPS_TEST_API_TOKEN": "must-not-leak",
                    "HTTPS_PROXY": "http://secret.example",
                },
                clear=False,
            ):
                environment = _build_environment(EPOCH, isolation_root)
            self.assertNotIn("NETOPS_TEST_API_TOKEN", environment)
            self.assertNotIn("HTTPS_PROXY", environment)
            self.assertEqual(environment["SOURCE_DATE_EPOCH"], str(EPOCH))
            self.assertEqual(environment["HOME"], str(isolation_root / "home"))
            self.assertEqual(environment["TMPDIR"], str(isolation_root / "tmp"))

    def test_pair_verification_checks_raw_wheel_and_normalized_sdist(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            first_root = root / "first"
            second_root = root / "second"
            workspace = root / "workspace"
            first_root.mkdir()
            second_root.mkdir()
            workspace.mkdir()
            first_wheel = first_root / "example-1.0.0-py3-none-any.whl"
            second_wheel = second_root / first_wheel.name
            first_wheel.write_bytes(b"same-wheel")
            second_wheel.write_bytes(b"same-wheel")
            first_sdist = first_root / "example-1.0.0.tar.gz"
            second_sdist = second_root / first_sdist.name
            write_sdist(first_sdist, variant=1)
            write_sdist(second_sdist, variant=2)

            verified = _verify_build_pair(
                BuildArtifacts(first_wheel, first_sdist),
                BuildArtifacts(second_wheel, second_sdist),
                workspace,
                epoch=EPOCH,
            )
            self.assertEqual(verified.wheel, first_wheel)
            self.assertTrue(verified.sdist.is_file())

    def test_pair_verification_rejects_wheel_drift_before_publication(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            first_root = root / "first"
            second_root = root / "second"
            workspace = root / "workspace"
            first_root.mkdir()
            second_root.mkdir()
            workspace.mkdir()
            wheel_name = "example-1.0.0-py3-none-any.whl"
            first_wheel = first_root / wheel_name
            second_wheel = second_root / wheel_name
            first_wheel.write_bytes(b"first")
            second_wheel.write_bytes(b"second")
            with self.assertRaisesRegex(RuntimeError, "wheel is not"):
                _verify_build_pair(
                    BuildArtifacts(first_wheel, first_root / "example.tar.gz"),
                    BuildArtifacts(second_wheel, second_root / "example.tar.gz"),
                    workspace,
                    epoch=EPOCH,
                )

    def test_publish_refuses_existing_output_and_copies_verified_pair(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            wheel = root / "example.whl"
            sdist = root / "example.tar.gz"
            wheel.write_bytes(b"wheel")
            sdist.write_bytes(b"sdist")
            artifacts = BuildArtifacts(wheel, sdist)
            existing = root / "existing"
            existing.mkdir()
            marker = existing / "marker"
            marker.write_bytes(b"keep")
            with self.assertRaisesRegex(RuntimeError, "refusing to overwrite"):
                _publish_artifacts(artifacts, existing)
            self.assertEqual(marker.read_bytes(), b"keep")

            published = _publish_artifacts(artifacts, root / "published")
            self.assertEqual(published.wheel.read_bytes(), b"wheel")
            self.assertEqual(published.sdist.read_bytes(), b"sdist")


if __name__ == "__main__":
    unittest.main()
