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
NODE_LINK_SCHEMES = (
    "anytls",
    "hysteria",
    "hysteria2",
    "hy2",
    "juicity",
    "mieru",
    "shadowtls",
    "snell",
    "ss",
    "ssr",
    "trojan",
    "tuic",
    "vless",
    "vmess",
    "wg",
    "wireguard",
)
PATTERNS = {
    "private-key": re.compile(r"-----BEGIN [^-\n]*PRIVATE KEY-----"),
    "github-token": re.compile(r"\b(?:ghp|gho|ghu|ghs|github_pat)_[A-Za-z0-9_]{20,}\b"),
    "provider-token": re.compile(
        r"(?<![A-Za-z0-9_-])(?:"
        r"sk-(?:[A-Za-z0-9]{32,}|(?:proj|svcacct|ant-api03|or-v1)-[A-Za-z0-9_-]{20,})|"
        r"(?:AKIA|ASIA|AIDA|AROA|AIPA|ANPA|ANVA)[A-Z0-9]{16}|"
        r"xox[baprs]-[A-Za-z0-9-]{10,}|glpat-[A-Za-z0-9_-]{20,}|"
        r"(?:sk|rk)_live_[A-Za-z0-9]{16,}|AIza[0-9A-Za-z_-]{35}|"
        r"npm_[A-Za-z0-9]{36}|pypi-[A-Za-z0-9_-]{40,}|"
        r"(?:dop|doo|dor)_v1_[a-fA-F0-9]{64}|hf_[A-Za-z0-9]{20,}|"
        r"ya29\.[A-Za-z0-9_-]{20,}|"
        r"eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"
        r")(?![A-Za-z0-9_-])"
    ),
    # A bare 40-character value is indistinguishable from a Git SHA-1 or a
    # source identifier.  Require a provider-specific assignment label instead
    # of guessing from length alone; this still catches hexadecimal API keys.
    "cloudflare-token": re.compile(
        r"\b(?:cloudflare|cf)(?:[_-]?(?:api|access))?[_-]?(?:token|key)\b"
        r"\s*[:=]\s*['\"]?[A-Za-z0-9_-]{20,200}",
        re.I,
    ),
    "node-link": re.compile(
        r"\b(?:" + "|".join(map(re.escape, NODE_LINK_SCHEMES)) + r")://",
        re.I,
    ),
    "url-credentials": re.compile(r"[a-zA-Z][a-zA-Z0-9+.-]*://[^/@\s:]+:[^/@\s]+@"),
    "bearer-credential": re.compile(
        r"(?i)(?<![A-Za-z0-9_-])Bearer\s+[A-Za-z0-9._~+/=-]+"
    ),
    "secret-assignment": re.compile(
        r"(?i)\b(?:password|passwd|passphrase|api[_-]?key|account[_-]?key|"
        r"aws[_-]?secret[_-]?access[_-]?key|secret[_-]?access[_-]?key|"
        r"azure[_-]?storage[_-]?key|shared[_-]?access[_-]?(?:key|signature)|"
        r"access[_-]?token|refresh[_-]?token|client[_-]?secret|"
        r"private[_-]?key|sshpass|pgpassword|mysql[_-]?pwd)\s*[:=]\s*"
        r"(?:['\"])?(?!<redacted>)(?!os\.(?:environ|getenv)\b)(?!getenv\()"
        r"[^\s,;&'\"]+"
    ),
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
        relative = path.relative_to(root)
        for label, pattern in PATTERNS.items():
            for match in pattern.finditer(text):
                line = text.count("\n", 0, match.start()) + 1
                findings.append(f"{relative}:{line}: {label}")
    if findings:
        print("\n".join(findings), file=sys.stderr)
        return 1
    print("secret scan: clean")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
