# Contributing to NetOps

Thank you for considering a contribution. NetOps is a beginner first VPS networking
and proxy operations toolkit, so almost every change touches something a novice
operator will run against real infrastructure. The rules below exist because the
project executes remote changes and prints network evidence, not because the
maintainer enjoys process.

Read [`AGENTS.md`](AGENTS.md) first. It is the short, authoritative rule list. This
document restates those rules for humans, explains why each one exists, and names
the gate that actually enforces it.

## Architecture in a paragraph

NetOps ships exactly one root router Skill ([`SKILL.md`](SKILL.md)) plus exactly five
workflow Skills under [`skills/`](skills): `netops-start`, `netops-scan`,
`netops-build`, `netops-fix` and `netops-manage`. The router classifies a natural
language request and hands it to one workflow. Protocol details, provider behaviour,
carriers, sites and individual incident write ups live in [`references/`](references)
and are loaded by the workflows on demand; they never become a sixth Skill. All
executable behaviour lives in [`netops_core/`](netops_core), a Python package that
uses the standard library only, with the JSON contracts in [`schemas/`](schemas) and
the release gates in [`scripts/`](scripts). The install layout is dual: in this
repository each satellite Skill is nested at `skills/<name>/SKILL.md`, and the
installer copies it flat into the agent skills root as a sibling of `netops/`, so a
satellite must resolve shared documents through `<reference-root>`, which resolves to
`../../references` when nested and `../netops/references` when flat.
`scripts/validate_skills.py` models the flat layout in a temporary directory and
fails if any declared shared reference cannot be resolved there.

### The dual copy rule

Once installed, every satellite exists twice: nested under `skills/netops-*/`, and
flat beside the root Skill. The router loads the nested copy; triggering a satellite
directly loads the flat one. The two must stay byte identical, or the same request
behaves differently depending on how it arrived.

The nested `skills/<name>/SKILL.md` in this repository is the single source of truth.
The installed flat copy must remain a byte identical copy of it, produced by
reinstalling, never by hand editing the installed file. If you edit an installed copy,
your change is invisible to CI, to the test suite and to every other contributor, and
the next install silently reverts it.

Do not add a second copy of any `SKILL.md` inside the repository either.
`scripts/validate_skills.py` performs a full depth discovery of every `SKILL.md` in the
tree and requires the discovered set to equal exactly the root Skill plus the five
nested satellites; an extra copy fails the build. The same script models the flat
layout in a temporary directory and checks that every declared shared reference still
resolves there.

## The rules, and what enforces them

**One root router, exactly five workflow Skills.** Do not add a Skill. New protocols,
new providers, new failure modes and new regions become reference documents and
routing cases, not new entry points.
Enforced by the `EXPECTED` set and the full depth discovery equality check in
`scripts/validate_skills.py`.

**No hardcoded identity.** Never write a user's city, ISP, domain, IP address,
credential path, node share link, UUID or API token into the repository. The project
is published publicly and the Skills are read verbatim by an agent, so an example
address becomes an assumption.
Enforced in two places: `scripts/validate_skills.py` rejects IPv4 literals, a known
private domain suffix and a fixed list of historical city, carrier and vendor names
inside Skill files; `scripts/check_secrets.py` scans the whole tree for private keys,
provider tokens, credential assignments, credentials embedded in URLs and node share
link schemes.

**The scanner stays bounded and read only.** `netops-scan` observes; it does not
install scheduled tasks, mutate a host or widen its own blast radius. Any external
lookup, including a public IP query or a curated third party tool, requires an
explicit flag such as `--external` or `--tool-external`.
Enforced by `scripts/validate_skills.py`, which requires the scan Skill to state that
it does not install scheduled tasks and rejects any attempt to move monitor
installation into it.

**Path data is an observation, not a map.** Every finding carries a vantage point, a
timestamp, a confidence level and its limitations. Carrier and provider internals are
reported as unobservable rather than guessed.

**Remote text is data, never instruction.** Banners, logs, configuration files and
command output collected from a target are evidence to be reported. They may not
change a classification, skip a confirmation or cause a command to run. A change that
lets collected text influence control flow is a security defect, not a feature.

**A normative rule has exactly one home.** The table in `AGENTS.md` names the single
source for the control channel gate, post incident recovery, independence proof,
question format and curated tool selection. Point at the source instead of restating
it; duplicated safety wording is how a stale version's text survived into later
releases. Exactly two duplications are deliberate and must be preserved: the
`## Direct-Invocation Safety` section that each mutating satellite carries in its own
right, and the nested plus flat satellite copies described above.

**Every user facing diagnostic renders both outputs.** A Chinese beginner report for
the person, and machine readable JSON for the agent and for later comparison. Adding
one without the other is not a complete diagnostic. CI cannot check this per
diagnostic, so it is a review rule: say in your pull request which report and which
JSON path you added or changed.

**Tests and schemas move with the contract.** If you change the diagnostic, change
plan or fleet contract, update `schemas/` and `tests/` in the same change. A schema
that drifts from the runtime is worse than no schema, because the executor trusts it.
Enforced by `scripts/release_check.py`, which cross checks the runtime schema version
against `schemas/change-spec.schema.json` and `schemas/change-plan.schema.json`,
validates every shipped example with the authoritative stdlib validators and, with
`--require-jsonschema`, with Draft 2020-12.

**Standard library only.** `netops_core/` and `scripts/` must import nothing outside
the Python standard library, and `pyproject.toml` must keep `dependencies = []`. The
tool has to run on a VPS that may currently have no working outbound network. The
pinned `build`, `setuptools` and `jsonschema` versions are checking and packaging
tools used by CI, not runtime dependencies.

**Remote mutation is a contract, not a command.** Explicit authorisation, an affected
state backup, pre apply validation, post apply verification and an executable
rollback. Shared remote paths and exact file transactions use the exact plan executor
with a plan ID; an unrelated remote VPS may use authorised direct SSH under the same
contract. Existing nodes and the host default route are preserved unless a reviewed
change says otherwise in so many words.

## The gate to run before opening a pull request

Run this from the repository root. It is the same set CI runs, in the same order.

```bash
python3 -m pip install "jsonschema==4.25.1"
python3 -m unittest discover -s tests -v
python3 scripts/validate_skills.py .
python3 scripts/check_secrets.py .
python3 scripts/check_install_tree.py .
python3 scripts/release_check.py . --require-jsonschema
```

`check_install_tree.py` rejects packaging and runtime residue, because the installer
copies the working tree verbatim and a stale `build/`, `dist/` or `*.egg-info` left in
your checkout becomes part of what an agent reads. It also confirms that
`netops_core.__version__` and the `pyproject.toml` version still agree. If it fails,
delete the residue rather than adding an exclusion.

If you have NetOps installed as a Skill and edited any satellite, also check the flat
copies. They live outside the repository, so no repository scoped test can reach them,
and the router loads the nested copy while direct triggering loads the flat one. Point
the checker at the directory holding the installation:

```bash
python3 scripts/check_install_tree.py . --install-root ~/.agents/skills
```

A mismatch means the two entry points would apply different safety rules. The failure
message prints the exact `cp` command that re-syncs the file.

`jsonschema` is only needed for the `--require-jsonschema` step, which validates the
schemas and their examples against Draft 2020-12. It is a checking tool, not a
runtime dependency, and it must never appear in `pyproject.toml`.

Release artefacts go through a separate double build gate. You do not need it for a
normal pull request, but run it before proposing a release, and note that the output
directory must not already exist:

```bash
python3 -m pip install "build==1.3.0" "setuptools==83.0.0"
python3 scripts/reproducible_build.py . --source-date-epoch 1720000000 --output-dir release-dist
python3 scripts/package_smoke.py . --dist-dir release-dist
```

`1720000000` is the stable reference epoch CI uses. A tagged release should use the
committer timestamp of the tag commit and record that value in the release notes.

CI runs the whole set on Python 3.10 through 3.14: every minor version on Linux, and
3.10, 3.12 and 3.14 additionally on macOS and Windows. Nothing in CI connects to a
real VPS or touches a scheduler; platform specific commands are verified through
fixtures and command generation tests.

## The safety review bar

Three areas carry real, immediate harm and are reviewed to a higher standard than the
rest of the codebase.

**The control channel gate** (`netops_core/control_channel.py`, the gate sections of
each Skill, and `references/control-channel-safety.md`). The agent's own traffic may
be flowing through the very proxy, TUN, node or VPS that a change is about to
restart, in which case the agent goes offline mid operation and can no longer verify
or roll back. Since 0.3.2 the gate's posture is warn plus informed consent, not
refusal: the decision is `allow` or `warn`, a `warn` requires the risk card to be
shown and the user to accept the residual risk explicitly before the executor
continues. Hard refusals remain only for two cases, a target the user does not own and
a feature this version has not released. Do not reintroduce a blanket refusal, and do
not quietly downgrade a `warn` into an `allow`.

**Change execution** (`netops_core/change.py`). `apply_plan` and `rollback_plan` must
reject an unauthorised call before touching anything, including a non boolean truthy
value passed as the authorisation argument, and must keep the backup, rollback timer
arm and disarm, and receipt writing bound together.
Enforced by the change execution gate in `scripts/release_check.py`, which calls both
functions with unauthorised and non boolean arguments and requires the authorisation
error to be raised first.

**Redaction and bundle export** (`netops_core/redaction.py`, `netops_core/bundle.py`,
`scripts/check_secrets.py`). Raw scanner output contains addresses, host names, node
share links and, in the worst case, credentials. Anything that widens what leaves the
operator's machine is a data exposure change.

If your pull request weakens any of these, say so plainly in the description, give
the rationale, and add tests that cover the newly reachable path. A weakening with no
stated rationale and no test for the new path will be closed. Never delete, skip or
loosen an existing test to make a gate pass, and never suppress an error instead of
fixing it.

## Language split

- Chinese for `references/`, for `README.zh-CN.md` and for every user facing report
  and prompt. The audience is a beginner operator reading in Chinese.
- English for `SKILL.md` bodies, code, comments, identifiers, schemas, `README.md`,
  commit messages and pull request descriptions. Skill frontmatter descriptions may
  carry a short Chinese trigger phrase list, since the router matches Chinese
  requests.
- `README.md` and `README.zh-CN.md` are the same document in two languages. Change
  both, or neither.
- British English spelling in English prose: behaviour, colour, licence, organisation.
- No em dashes and no en dashes anywhere. Do not put a hyphen between English words;
  write "read only", "byte identical", "machine readable". Hyphens are allowed only
  inside literal code identifiers, file paths, package names, command line flags and
  version strings.

## Commits and pull requests

- One logical change per commit. Write the subject in English, in the imperative
  mood, under about 72 characters, with no trailing full stop.
- Reference the release version in parentheses when the commit is part of a version
  bump, matching the existing history.
- Never commit a real host, a real node link, a diagnostic bundle or anything under
  `diagnostics/`. Run `python3 scripts/check_secrets.py .` before you push.
- In the pull request description, state what changed, which of the five workflows it
  affects, and paste the output of the local gate.
- Fill in every item of the pull request checklist honestly. An unchecked box with an
  explanation is far more useful than a checked box that is not true.

## Reporting problems

- Bugs and feature ideas: open an issue using one of the forms. The bug form asks for
  a redacted diagnostic bundle rather than raw output; please use it, because raw
  scanner output is not safe to paste into a public issue.
- Security issues: do not open a public issue. Follow
  [`SECURITY.md`](SECURITY.md).
- Behaviour towards other contributors: see
  [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md).
