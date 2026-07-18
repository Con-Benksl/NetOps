#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path


EXPECTED = {
    "netops-start",
    "netops-scan",
    "netops-build",
    "netops-fix",
    "netops-manage",
}
FORBIDDEN = {
    "北京移动",
    "杭州",
    "PayPal",
    "Netlify",
}
IP_LITERAL = re.compile(r"(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)")


def frontmatter(path: Path) -> dict[str, str]:
    text = path.read_text(encoding="utf-8")
    match = re.match(r"^---\n(.*?)\n---\n", text, re.DOTALL)
    if not match:
        raise ValueError(f"{path}: missing YAML frontmatter")
    data = {}
    for line in match.group(1).splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        data[key.strip()] = value.strip()
    return data


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", nargs="?", default=".")
    args = parser.parse_args(argv)
    root = Path(args.root).resolve()
    errors = []
    root_meta = frontmatter(root / "SKILL.md")
    if root_meta.get("name") != "netops":
        errors.append("root skill name must be netops")
    child_paths = sorted((root / "skills").glob("*/SKILL.md"))
    names = set()
    for path in child_paths:
        meta = frontmatter(path)
        names.add(meta.get("name", ""))
        if not meta.get("description"):
            errors.append(f"{path}: missing description")
        if not (path.parent / "agents/openai.yaml").is_file():
            errors.append(f"{path}: missing agents/openai.yaml")
        text = path.read_text(encoding="utf-8")
        if IP_LITERAL.search(text):
            errors.append(f"{path}: skill files must not hardcode IPv4 addresses")
        if ".top" in text:
            errors.append(f"{path}: skill files must not hardcode private domains")
        for value in FORBIDDEN:
            if value in text:
                errors.append(f"{path}: hardcoded historical identifier {value!r}")
    if names != EXPECTED:
        errors.append(f"child skill set differs: {sorted(names)}")
    corpus_path = root / "tests/fixtures/generalized-intents.json"
    corpus = json.loads(corpus_path.read_text(encoding="utf-8"))
    if len(corpus) < 40:
        errors.append("generalized intent corpus must contain at least 40 cases")
    for index, case in enumerate(corpus):
        if case.get("skill") not in EXPECTED:
            errors.append(f"intent {index} has invalid skill")
        for value in FORBIDDEN:
            if value in case.get("prompt", ""):
                errors.append(f"intent {index} contains {value!r}")
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    print(f"skill validation: root + {len(names)} child skills; {len(corpus)} intents")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
