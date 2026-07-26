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
# Mirrors netops_core.redaction.UUID_RE.  The scanner is run as a standalone
# script (``python3 scripts/check_secrets.py .``), so the package is not on
# sys.path and cannot be imported here; tests/test_secret_scan.py asserts that
# both spellings stay identical.
UUID_RE = re.compile(
    r"(?<![0-9a-fA-F])[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
    r"(?![0-9a-fA-F])"
)
# NetOps generated run/observation identifiers are declared non-secret
# diagnostic foreign keys, which is why netops_core.redaction preserves
# ('run_id',), ('observations', 'observation_id') and the findings /
# path_segments evidence reference lists.  Recognise the same identifiers in
# their JSON, YAML and Python source spellings, including a leading qualifier
# such as ``root_run_id``.  Plain text carries no schema path, so ``evidence``
# is trusted only in the reference list shape the redactor also requires.
DIAGNOSTIC_UUID_KEY_RE = re.compile(
    r"(?i)(?<![0-9a-z_])(?:"
    r"(?:[a-z0-9]+_)?(?:run_id|observation_id)['\"]?\s*[:=]\s*['\"]?"
    r"|evidence['\"]?\s*[:=]\s*\[\s*"
    r"(?:['\"][0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}['\"]\s*,\s*)*['\"]?"
    r")$"
)
# The RFC 4122 documentation example and its version 4 respelling are the
# placeholder every fixture and doc reaches for.
DOCUMENTATION_UUID_RE = re.compile(
    r"(?i)123e4567-e89b-[0-9a-f]{4}-a456-4266[0-9a-f]{8}"
)
# A random uuid4 carries about 15 of the 16 hexadecimal digits, so a value
# built from four or fewer of them is a placeholder such as the nil UUID or a
# hand numbered fixture.  A panel operator can still set a client id by hand to
# exactly that shape; such a value is indistinguishable from the placeholder
# every document uses, and the two cannot be told apart from text alone.
PLACEHOLDER_UUID_DIGITS = 4
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
    # A 3x-ui / VLESS client credential is a bare uuid4, so an unqualified UUID
    # is a credential unless it is a NetOps diagnostic foreign key or a
    # documentation placeholder.
    "credential-uuid": UUID_RE,
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


def is_placeholder_uuid(value: str) -> bool:
    digits = value.replace("-", "").casefold()
    return (
        len(set(digits)) <= PLACEHOLDER_UUID_DIGITS
        or DOCUMENTATION_UUID_RE.fullmatch(value) is not None
    )


def uuid_is_allowed(text: str, match: re.Match) -> bool:
    if is_placeholder_uuid(match.group(0)):
        return True
    return DIAGNOSTIC_UUID_KEY_RE.search(text[: match.start()]) is not None


ALLOWLISTS = {"credential-uuid": uuid_is_allowed}


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
            allowed = ALLOWLISTS.get(label)
            for match in pattern.finditer(text):
                if allowed is not None and allowed(text, match):
                    continue
                line = text.count("\n", 0, match.start()) + 1
                findings.append(f"{relative}:{line}: {label}")
    if findings:
        print("\n".join(findings), file=sys.stderr)
        return 1
    print("secret scan: clean")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
