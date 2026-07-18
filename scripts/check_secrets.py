#!/usr/bin/env python3
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path


SKIP_DIRS = {".git", "__pycache__", ".venv", "build", "dist"}
SKIP_FILES = {
    Path("scripts/check_secrets.py"),
    Path("netops_core/redaction.py"),
}
PATTERNS = {
    "private-key": re.compile(r"-----BEGIN [^-\n]*PRIVATE KEY-----"),
    "github-token": re.compile(r"\b(?:ghp|gho|ghu|ghs|github_pat)_[A-Za-z0-9_]{20,}\b"),
    "cloudflare-token": re.compile(r"\b[A-Za-z0-9_-]{40}\b"),
    "node-link": re.compile(r"\b(?:vless|hysteria2|vmess|trojan)://", re.I),
    "url-credentials": re.compile(r"[a-zA-Z][a-zA-Z0-9+.-]*://[^/@\s:]+:[^/@\s]+@"),
}


def files(root: Path):
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.relative_to(root).parts):
            continue
        if path.relative_to(root) in SKIP_FILES:
            continue
        try:
            path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        yield path


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", nargs="?", default=".")
    args = parser.parse_args(argv)
    root = Path(args.root).resolve()
    findings = []
    for path in files(root):
        text = path.read_text(encoding="utf-8")
        for label, pattern in PATTERNS.items():
            for match in pattern.finditer(text):
                line = text.count("\n", 0, match.start()) + 1
                findings.append(f"{path.relative_to(root)}:{line}: {label}")
    if findings:
        print("\n".join(findings), file=sys.stderr)
        return 1
    print("secret scan: clean")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
