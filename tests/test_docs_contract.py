"""Contract test for the netopsctl examples printed in the shipped documentation.

tests/test_cli_contract.py exercises CLI behaviour and tests/test_skill_contract.py
asserts that required phrases are present, but neither notices when a documented
command stops matching the parser.  A renamed flag would leave the README and the
Chinese reference guides quietly telling a beginner to run something the CLI
rejects, and this repository has already shipped one stale documentation contract.

Every logical command line inside a fenced code block that begins with a netopsctl
entry point is extracted, joined across shell continuations, stripped of obvious
placeholders and handed to netops_core.cli.build_parser().parse_args().  Nothing is
executed: argument parsing never touches the network or the filesystem.

Known limitation: a fence indented by four spaces or more, which CommonMark reads
as a code block nested inside a list item, is not scanned.  No shipped guide uses
one today.  Documented commands belong in a top level fence so that this contract
can see them.
"""

import contextlib
import io
import json
import re
import shlex
import unittest
from pathlib import Path
from typing import NamedTuple

from netops_core.cli import build_parser
from netops_core.control_channel import normalize_control_channel


ROOT = Path(__file__).resolve().parents[1]

# Documentation that may contain runnable examples.  Adding a new guide here is
# the only step needed to bring it under the contract.
DOCUMENTATION_GLOBS = (
    "README.md",
    "README.zh-CN.md",
    "SKILL.md",
    "references/*.md",
    "references/cases/*.md",
    "skills/*/SKILL.md",
)

# The extraction must never be allowed to quietly find nothing: a test that
# collects zero commands and reports success is worse than no test at all.  The
# audited tree carries clearly more than this many examples, so the floor only
# fires when the fence scanner or the entry point pattern has broken.
MINIMUM_EXAMPLES = 12

# CommonMark allows a fence to be indented by up to three spaces and to be
# written with backticks or tildes.  A backtick fence may not carry a backtick in
# its info string.
FENCE = re.compile(r"^(?P<indent> {0,3})(?P<fence>`{3,}|~{3,})(?P<info>.*)$")

# ``netopsctl``, ``python3 scripts/netopsctl.py``, ``python -m netops_core`` and
# the Skill root spelling ``python3 <skill-root>/scripts/netopsctl.py`` are the
# documented ways to reach the same parser.
ENTRY_POINT = re.compile(
    r"^(?:python3? +-m +netops_core(?:\.cli)?"
    r"|(?:python3? +)?(?:\S*/)?netopsctl(?:\.py)?)(?= |$)"
)

# ``NETOPS_TOOL_IPQUALITY=/opt/... netopsctl scan server`` documents an explicit
# tool path.  The assignments belong to the shell, not to argparse.
ENVIRONMENT_ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=\S*\s+")
SHELL_PROMPT = re.compile(r"^\$ +")

# ``<full reviewed plan ID>`` and friends stand in for a value the reader
# supplies.  Substitution happens before the command is split into tokens, so a
# placeholder that contains spaces still collapses to a single argument.  ``0``
# is used because it is accepted both as a bare string and by an ``int`` typed
# option, so a placeholder never fails the parse on its own.
PLACEHOLDER = re.compile(r"<[^<>]+>")
PLACEHOLDER_SUBSTITUTE = "0"

# argparse exits with status 0 once one of these has been accepted, which still
# proves the surrounding arguments parsed.
HELP_FLAGS = frozenset({"-h", "--help", "--version"})


class Example(NamedTuple):
    """One documented command, with enough context to fix it in one step."""

    path: str
    line: int
    command: str
    argv: tuple
    error: str

    def locate(self) -> str:
        return f"{self.path}:{self.line}: {self.command}"


def _code_blocks(text):
    """Yield ``(first_content_line_number, lines)`` for each fenced code block."""

    lines = text.splitlines()
    index = 0
    while index < len(lines):
        opening = FENCE.match(lines[index])
        if opening is None or (
            opening.group("fence").startswith("`") and "`" in opening.group("info")
        ):
            index += 1
            continue
        marker = opening.group("fence")
        indent = len(opening.group("indent"))
        start = index + 2
        body = []
        index += 1
        while index < len(lines):
            closing = FENCE.match(lines[index])
            if (
                closing is not None
                and closing.group("fence")[0] == marker[0]
                and len(closing.group("fence")) >= len(marker)
                and not closing.group("info").strip()
            ):
                index += 1
                break
            content = lines[index]
            leading = len(content) - len(content.lstrip(" "))
            body.append(content[min(indent, leading):])
            index += 1
        if body:
            yield start, body


def _logical_lines(start, body):
    """Join shell continuations, keeping the line number the command starts on."""

    pending = []
    first = None
    for offset, raw in enumerate(body):
        line = raw.rstrip()
        if first is None:
            first = start + offset
        if line.endswith("\\") and not line.endswith("\\\\"):
            pending.append(line[:-1])
            continue
        pending.append(line)
        yield first, " ".join(part.strip() for part in pending).strip()
        pending = []
        first = None
    if pending:
        yield first, " ".join(part.strip() for part in pending).strip()


def _argv(command):
    """Return ``(argv, error)`` for a documented command, or ``None`` if it is not one."""

    text = SHELL_PROMPT.sub("", command.strip())
    while True:
        assignment = ENVIRONMENT_ASSIGNMENT.match(text)
        if assignment is None:
            break
        text = text[assignment.end():]
    entry = ENTRY_POINT.match(text)
    if entry is None:
        return None
    remainder = PLACEHOLDER.sub(PLACEHOLDER_SUBSTITUTE, text[entry.end():]).strip()
    if not remainder:
        return None
    try:
        tokens = shlex.split(remainder)
    except ValueError as exc:
        return (), f"the example is not a well formed shell command: {exc}"
    return tuple(tokens), ""


def extract(path, text):
    """Collect every documented netopsctl invocation in one Markdown document."""

    found = []
    for start, body in _code_blocks(text):
        for line, command in _logical_lines(start, body):
            parsed = _argv(command)
            if parsed is None:
                continue
            argv, error = parsed
            found.append(Example(path, line, command, argv, error))
    return found


def documented_examples():
    examples = []
    for pattern in DOCUMENTATION_GLOBS:
        for path in sorted(ROOT.glob(pattern)):
            examples.extend(
                extract(
                    path.relative_to(ROOT).as_posix(),
                    path.read_text(encoding="utf-8"),
                )
            )
    return examples


def _parse(argv):
    """Parse one argument vector, returning ``(exit_code, message)``."""

    stdout, stderr = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
        try:
            build_parser().parse_args(list(argv))
        except SystemExit as stop:
            return stop.code, (stderr.getvalue() or stdout.getvalue()).strip()
    return None, ""


class DocumentationCommandTests(unittest.TestCase):
    def test_documented_commands_parse_against_the_shipped_parser(self):
        failures = []
        for example in documented_examples():
            if example.error:
                failures.append(f"{example.locate()}\n    {example.error}")
                continue
            code, message = _parse(example.argv)
            accepted = code is None or (
                code == 0 and HELP_FLAGS.intersection(example.argv)
            )
            if accepted:
                continue
            detail = message.splitlines()[-1] if message else f"exit status {code}"
            failures.append(
                f"{example.locate()}\n"
                f"    parsed as {list(example.argv)}\n"
                f"    rejected by netops_core.cli.build_parser(): {detail}"
            )
        if failures:
            self.fail(
                "documented commands no longer match the shipped CLI:\n"
                + "\n".join(failures)
            )

    def test_extraction_is_not_vacuous(self):
        examples = documented_examples()
        self.assertGreaterEqual(
            len(examples),
            MINIMUM_EXAMPLES,
            f"only {len(examples)} documented commands were extracted; the fence "
            f"scanner or the entry point pattern in {Path(__file__).name} is "
            "broken, and this contract is no longer guarding anything",
        )

    def test_extraction_spans_more_than_one_document(self):
        # Guards the glob list itself: one guide keeping the count above the
        # floor must not hide a scanner that has stopped seeing the others.
        # Deliberately not tied to particular filenames, so that reorganising
        # the guides does not turn this contract red.
        covered = {example.path for example in documented_examples()}
        self.assertGreaterEqual(len(covered), 2, sorted(covered))


class ExtractionTests(unittest.TestCase):
    """The extractor is the load bearing part, so it is exercised directly."""

    DOCUMENT = "\n".join(
        (
            "# 标题",
            "",
            "Prose mentioning `netopsctl scan client` must not be collected.",
            "",
            "```bash",
            "git clone --depth 1 https://example.test/NetOps.git",
            "netopsctl tools list",
            "```",
            "",
            "```bash",
            "python3 scripts/netopsctl.py scan node \\",
            "  --target example.com \\",
            "  --port 443 --output node.json",
            "```",
            "",
            "```",
            "NETOPS_TOOL_IPQUALITY=/opt/netops-tools/ipquality/ip.sh \\",
            "netopsctl scan server --local --tool ipquality",
            "```",
            "",
            "```bash",
            "netopsctl change apply --plan plan.json --fleet fleet.json"
            " --current-control-channel current.json"
            " --confirm-plan-id <full reviewed plan ID> --authorized",
            "python3 <skill-root>/scripts/netopsctl.py --help",
            "python3 -m pip install .",
            "```",
        )
    )

    def setUp(self):
        self.examples = extract("fixture.md", self.DOCUMENT)

    def test_prose_and_unrelated_commands_are_ignored(self):
        commands = [example.command for example in self.examples]
        self.assertNotIn("python3 -m pip install .", commands)
        self.assertTrue(
            all("git clone" not in command for command in commands), commands
        )

    def test_line_continuations_are_joined_and_reported_at_the_first_line(self):
        joined = [example for example in self.examples if example.line == 11]
        self.assertEqual(len(joined), 1, self.examples)
        self.assertEqual(
            joined[0].argv,
            (
                "scan",
                "node",
                "--target",
                "example.com",
                "--port",
                "443",
                "--output",
                "node.json",
            ),
        )

    def test_environment_assignments_and_placeholders_are_handled(self):
        by_line = {example.line: example for example in self.examples}
        self.assertEqual(
            by_line[17].argv,
            ("scan", "server", "--local", "--tool", "ipquality"),
        )
        self.assertEqual(
            by_line[22].argv[-3:],
            ("--confirm-plan-id", PLACEHOLDER_SUBSTITUTE, "--authorized"),
        )
        self.assertEqual(by_line[23].argv, ("--help",))

    def test_every_extracted_fixture_command_parses(self):
        for example in self.examples:
            with self.subTest(command=example.command):
                self.assertEqual(example.error, "")
                code, message = _parse(example.argv)
                accepted = code is None or (
                    code == 0 and HELP_FLAGS.intersection(example.argv)
                )
                self.assertTrue(accepted, message)


class DocumentedControlChannelPayloadTests(unittest.TestCase):
    """Documented control_channel JSON must survive runtime normalisation.

    Command lines are only half of the documented interface.  The change executor
    rejects control-channel evidence whose normalised form differs from what was
    supplied, so a guide showing a payload that is missing a field teaches an
    operator to build one the executor will refuse.  Adding
    target_independence_verified in 0.4.0 broke exactly such an example.
    """

    def test_documented_control_channel_blocks_are_fully_normalized(self):
        checked = 0
        failures = []
        for pattern in DOCUMENTATION_GLOBS:
            for path in sorted(ROOT.glob(pattern)):
                text = path.read_text(encoding="utf-8")
                for block in re.findall(r"```json\n(.*?)```", text, re.DOTALL):
                    try:
                        payload = json.loads(block)
                    except json.JSONDecodeError:
                        continue
                    if not isinstance(payload, dict):
                        continue
                    candidate = payload.get("control_channel", payload)
                    if (
                        not isinstance(candidate, dict)
                        or "dependency" not in candidate
                    ):
                        continue
                    checked += 1
                    relative = path.relative_to(ROOT).as_posix()
                    try:
                        normalized = normalize_control_channel(candidate)
                    except ValueError as error:
                        failures.append(f"{relative}: rejected outright: {error}")
                        continue
                    missing = sorted(set(normalized) - set(candidate))
                    if missing:
                        failures.append(
                            f"{relative}: documented control_channel omits "
                            f"{missing}, so the executor would reject it with "
                            "'control-channel evidence must be fully normalized'"
                        )
        self.assertGreaterEqual(
            checked,
            1,
            "no documented control_channel payload was found; the extractor is "
            "probably broken rather than the documentation being clean",
        )
        self.assertEqual(failures, [], "\n".join(failures))


if __name__ == "__main__":
    unittest.main()
