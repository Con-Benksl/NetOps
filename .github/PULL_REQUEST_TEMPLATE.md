# Summary

<!-- What changed and why, in a sentence or two. Link the issue if there is one. -->

## Affected areas

<!-- Tick every one this change touches. -->

- [ ] Root router `SKILL.md`
- [ ] `netops-start`
- [ ] `netops-scan`
- [ ] `netops-build`
- [ ] `netops-fix`
- [ ] `netops-manage`
- [ ] `references/`
- [ ] `netops_core/`
- [ ] `schemas/`
- [ ] `scripts/` or CI
- [ ] `tests/`
- [ ] Documentation only

## Local gate

<!-- Paste the output, or the last line of each command. Do not tick these from memory. -->

- [ ] `python3 -m unittest discover -s tests -v`
- [ ] `python3 scripts/validate_skills.py .`
- [ ] `python3 scripts/check_secrets.py .`
- [ ] `python3 scripts/check_install_tree.py .`
- [ ] `python3 scripts/release_check.py . --require-jsonschema`

```text
<!-- gate output -->
```

- [ ] For a release change only: `python3 scripts/reproducible_build.py .` and
      `python3 scripts/package_smoke.py .` both pass.

## Project rules

- [ ] No new Skill. This change keeps exactly one root router and five workflow
      Skills; new protocols, providers, carriers, regions and incidents went into
      `references/`, not into a new entry point.
- [ ] The satellite Skills were edited only at their canonical nested source,
      `skills/<name>/SKILL.md`. I did not hand edit an installed flat copy, and the
      installed flat copy stays a byte identical copy produced by reinstalling. I did
      not add a second copy of any `SKILL.md` inside the repository.
- [ ] No hardcoded city, ISP, domain, IP address, credential path, node share link,
      UUID or API token anywhere, including tests, fixtures and examples.
- [ ] The scanner stays bounded and read only. Any external lookup or third party
      tool still requires an explicit flag.
- [ ] Every user facing diagnostic this change touches still renders both a Chinese
      beginner report and machine readable JSON. Neither was added without the other.
- [ ] Tests and schemas moved together with the contract. If the diagnostic, change
      plan or fleet contract changed, `schemas/` and `tests/` changed in this same
      pull request.
- [ ] Standard library only. No new runtime dependency, and `pyproject.toml` still
      declares `dependencies = []`.
- [ ] No test was deleted, skipped or weakened to make a gate pass, and no error was
      suppressed instead of fixed.
- [ ] Remote text stayed data. Nothing collected from a target can change a
      classification, skip a confirmation or trigger a command.
- [ ] Normative safety text was not duplicated. It lives at the single source named
      in the `AGENTS.md` table, and everything else points at it.
- [ ] Chinese for `references/`, `README.zh-CN.md` and user facing reports; English
      for `SKILL.md` bodies, code, `README.md` and commits. If one README changed,
      the other changed too. British English spelling in English prose. No em dashes,
      no en dashes, and no hyphens between English words.

## Safety review

<!-- Delete this section only if the change touches none of these three areas. -->

- [ ] This change touches the control channel gate, change execution, or redaction
      and bundle export.
- [ ] It does not weaken a gate.
- [ ] If it does weaken a gate, the rationale is written out below and there are new
      tests covering the newly reachable path.
- [ ] The gate's posture is unchanged: `allow` or `warn`, with a `warn` requiring the
      risk card and an explicit acceptance of the residual risk. No blanket refusal
      was reintroduced, and no `warn` was silently turned into an `allow`.
- [ ] Remote mutation still carries explicit authorisation, an affected state backup,
      pre apply validation, post apply verification and an executable rollback.
      Existing nodes and the host default route are preserved.

<!-- Rationale for any weakening, and which tests cover the new path: -->

## Notes for the reviewer

<!-- Anything that is hard to see from the diff: a behaviour change with no test
     signal, a decision you were unsure about, a follow up you deliberately left out. -->
