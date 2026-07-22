import io
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path

from scripts.package_smoke import (
    REQUIRED_SDIST_DIRECTORIES,
    REQUIRED_SDIST_FILES,
    _safe_extract_sdist,
    _validate_artifact_module_parity,
    _validate_sdist_layout,
)


def directory_member(name: str) -> tarfile.TarInfo:
    member = tarfile.TarInfo(name)
    member.type = tarfile.DIRTYPE
    member.mode = 0o755
    return member


def regular_member(name: str, content: bytes = b"content\n") -> tuple[tarfile.TarInfo, bytes]:
    member = tarfile.TarInfo(name)
    member.size = len(content)
    member.mode = 0o644
    return member, content


def write_archive(
    path: Path,
    members: list[tuple[tarfile.TarInfo, bytes | None]],
) -> None:
    with tarfile.open(path, mode="w:gz") as archive:
        for member, content in members:
            archive.addfile(
                member,
                io.BytesIO(content) if content is not None else None,
            )


class PackageSmokeArchiveTests(unittest.TestCase):
    def test_safe_extract_accepts_regular_single_root_archive(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            archive = root / "source.tar.gz"
            readme, content = regular_member("package/README.md")
            write_archive(
                archive,
                [
                    (directory_member("package"), None),
                    (readme, content),
                ],
            )
            extracted = _safe_extract_sdist(archive, root / "extracted")
            self.assertEqual(extracted.name, "package")
            self.assertEqual((extracted / "README.md").read_bytes(), content)

    def test_safe_extract_rejects_unsafe_member_types_and_paths(self):
        cases = []
        for name in (
            "/absolute.txt",
            "package/../escape.txt",
            "package\\escape.txt",
            "package/file:stream",
            "package/CON",
            "package/aux.txt",
            "package/trailing.",
            "package/trailing ",
        ):
            member, content = regular_member(name)
            cases.append((name, member, content))
        for label, member_type in (
            ("symlink", tarfile.SYMTYPE),
            ("hardlink", tarfile.LNKTYPE),
            ("character-device", tarfile.CHRTYPE),
            ("block-device", tarfile.BLKTYPE),
            ("fifo", tarfile.FIFOTYPE),
        ):
            member = tarfile.TarInfo(f"package/{label}")
            member.type = member_type
            member.mode = 0o644
            member.linkname = "package/README.md"
            cases.append((label, member, None))

        for index, (label, unsafe, content) in enumerate(cases):
            with self.subTest(member=label), tempfile.TemporaryDirectory() as raw:
                root = Path(raw)
                archive = root / "source.tar.gz"
                write_archive(
                    archive,
                    [
                        (directory_member("package"), None),
                        (unsafe, content),
                    ],
                )
                with self.assertRaises(RuntimeError):
                    _safe_extract_sdist(archive, root / f"extracted-{index}")

    def test_safe_extract_rejects_windows_casefold_collisions(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            archive = root / "source.tar.gz"
            upper, upper_content = regular_member("package/Module.py", b"upper\n")
            lower, lower_content = regular_member("package/module.py", b"lower\n")
            write_archive(
                archive,
                [
                    (directory_member("package"), None),
                    (upper, upper_content),
                    (lower, lower_content),
                ],
            )
            with self.assertRaisesRegex(RuntimeError, "duplicate member path"):
                _safe_extract_sdist(archive, root / "extracted")

    def test_layout_requires_self_contained_source_and_rejects_cache(self):
        with tempfile.TemporaryDirectory() as raw:
            source = Path(raw) / "package"
            source.mkdir()
            for relative in REQUIRED_SDIST_DIRECTORIES:
                (source / relative).mkdir(parents=True, exist_ok=True)
                (source / relative / ".keep").write_text("kept\n", encoding="utf-8")
            for relative in REQUIRED_SDIST_FILES:
                path = source / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("content\n", encoding="utf-8")
            _validate_sdist_layout(source)

            cache = source / "tests" / "nested" / ".pytest_cache"
            cache.mkdir(parents=True)
            (cache / "README.md").write_bytes(b"cache")
            with self.assertRaisesRegex(RuntimeError, "forbidden"):
                _validate_sdist_layout(source)

    def test_artifact_module_parity_accepts_identical_modules(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            source = root / "source"
            package = source / "netops_core"
            package.mkdir(parents=True)
            modules = {
                "netops_core/__init__.py": b'__version__ = "1.0.0"\n',
                "netops_core/worker.py": b"VALUE = 1\n",
            }
            for relative, content in modules.items():
                path = source / relative
                path.write_bytes(content)
            wheel = root / "package.whl"
            with zipfile.ZipFile(wheel, mode="w") as archive:
                for relative, content in modules.items():
                    archive.writestr(relative, content)

            _validate_artifact_module_parity(wheel, source)

    def test_artifact_module_parity_rejects_stale_missing_and_extra_modules(self):
        cases = {
            "stale": {
                "netops_core/__init__.py": b'__version__ = "1.0.0"\n',
                "netops_core/worker.py": b"VALUE = 0\n",
            },
            "missing": {
                "netops_core/__init__.py": b'__version__ = "1.0.0"\n',
            },
            "extra": {
                "netops_core/__init__.py": b'__version__ = "1.0.0"\n',
                "netops_core/worker.py": b"VALUE = 1\n",
                "netops_core/legacy.py": b"VALUE = 0\n",
            },
        }
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            source = root / "source"
            package = source / "netops_core"
            package.mkdir(parents=True)
            (package / "__init__.py").write_bytes(b'__version__ = "1.0.0"\n')
            (package / "worker.py").write_bytes(b"VALUE = 1\n")
            for label, modules in cases.items():
                with self.subTest(case=label):
                    wheel = root / f"{label}.whl"
                    with zipfile.ZipFile(wheel, mode="w") as archive:
                        for relative, content in modules.items():
                            archive.writestr(relative, content)
                    with self.assertRaisesRegex(RuntimeError, "modules differ"):
                        _validate_artifact_module_parity(wheel, source)


if __name__ == "__main__":
    unittest.main()
