# Contributing to NetOps

Thank you for considering a contribution. NetOps is a beginner first VPS networking
and proxy operations toolkit, so almost every change touches something a novice
operator will run against real infrastructure. The rules below exist because the
project executes remote changes and prints network evidence, not because the
maintainer enjoys process.

Read [`AGENTS.md`](AGENTS.md) first. It is the authoritative rule list. This
document explains the repository layout and contributor workflow.

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

## Rules and enforcement

[AGENTS.md](AGENTS.md) owns the normative project rules and points to each
authoritative safety reference. Do not copy that wording into another document.
Contributors need only know where the contract lives and which gate checks it.

| Concern | Authoritative source | Enforcement |
| --- | --- | --- |
| Skill topology and installed copies | [AGENTS.md](AGENTS.md) | `scripts/validate_skills.py`, `scripts/check_install_tree.py` |
| Control channel, recovery and execution | [AGENTS.md](AGENTS.md) and its reference table | focused tests and `scripts/release_check.py` |
| Security and redaction | [SECURITY.md](SECURITY.md) | focused tests and `scripts/check_secrets.py` |
| Data contracts | [schemas/](schemas) | stdlib validators, tests and `scripts/release_check.py` |
| Contribution language | [Language split](#language-split) | review |

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

A mismatch means the two entry points would apply different safety rules. Do not fix
only the reported `SKILL.md`: use the complete synchronizer below so companion files
and all six managed targets move together.

For a complete six-target refresh, preview the Git-tracked-only payload first, then
apply that exact source selection explicitly:

```bash
python3 scripts/sync_install_tree.py . --install-root ~/.agents/skills
# Copy the 64-character manifest_sha256 from the dry-run JSON above.
python3 scripts/sync_install_tree.py . --install-root ~/.agents/skills --apply \
  --confirm-manifest-sha256 "<manifest_sha256-from-dry-run>"
```

The synchronizer copies current working-tree bytes only for Git-tracked regular
files, so reviewed dirty edits are included while untracked files are not. Tracked
caches or diagnostics fail closed and must be removed from Git first. The apply
command stages the source again and refuses to move any live target unless the
staged payload's target-relative paths, normalised file modes and bytes reproduce
the confirmed dry-run digest. Apply mode moves every existing managed target into
a unique private directory below the sibling `skill-backups/` directory before
replacement. On POSIX, that backup directory is required to have mode `0700`, and
the synchronizer durably updates a mode-`0600` in-progress journal before and after
each move. On Windows, POSIX modes cannot prove privacy: the supported boundary is
an install tree below a private per-user directory with inherited private ACLs;
shared or broadly accessible ACL roots are outside this synchronizer's contract.
The final journal records the completed state. Keep that backup and receipt until
the refreshed installation has been checked.

If apply is interrupted and the JSON error or lock message says recovery is
required, do not start another apply. Recover the transaction named by its
persistent receipt; omit the explicit path only when the synchronizer reports a
single locked transaction for this installation root:

```bash
python3 scripts/sync_install_tree.py --install-root ~/.agents/skills --recover \
  --recovery-receipt ~/.agents/skill-backups/netops-install-.../sync-receipt.json
```

Recovery inspects the recorded directory identities and the actual
stage/live/backup topology, restores the pre-apply installation, and is safe to
run again after it reports completion. An identity mismatch or ambiguous receipt
fails closed for manual inspection instead of moving an unknown directory.

`jsonschema` is only needed for the `--require-jsonschema` step, which validates the
schemas and their examples against Draft 2020-12. It is a checking tool, not a
runtime dependency, and it must never appear in `pyproject.toml`.

After the clean release commit has its exact `v<version>` tag, run the
publication-only gate before creating any in-repository artefact directory:

```bash
python3 scripts/release_check.py . --require-jsonschema --release-mode
```

Unlike the ordinary developer check, `--release-mode` intentionally rejects a dirty
tree, an untagged commit, a tag that does not exactly match the package version,
reuse of a version tag from another commit, and a release without meaningful dated
Changelog evidence. Do not use this flag for normal branch or pull-request checks.

Only after that clean tagged-tree gate passes do release artefacts go through the
separate double build gate. The output directory must not already exist:

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

## Security sensitive changes

[SECURITY.md](SECURITY.md) defines the security surface. A pull request that
changes a trust boundary must explain the impact and leave a regression check
that reaches the changed path. Never loosen or skip an existing check merely to
make a gate pass.

## Language split

- Chinese for `references/`, for `README.zh-CN.md`, user facing prompts and
  conversations, and explicitly requested reports. The audience is a beginner
  operator reading in Chinese.
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
