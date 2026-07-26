# Security Policy

NetOps drives real infrastructure. It can open an SSH session to a VPS, rewrite a
proxy configuration, restart a network service and export a diagnostic archive that
started life as raw scanner output. A defect in the wrong place does not produce a
stack trace, it produces a machine the operator can no longer reach, or a public issue
thread containing their credentials. Please report such defects privately.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting:

**https://github.com/Con-Benksl/NetOps/security/advisories/new**

That form creates a private advisory visible only to you and the maintainer. Do not
open a public issue, a public discussion or a pull request for a security defect, and
do not attach an unredacted diagnostic bundle, a real host name, a real node share
link or any credential to the report.

A useful report contains:

- The version, from `netopsctl --version`, and the Python version.
- Which subsystem is affected: the control channel gate, the change executor,
  redaction and bundle export, the secret scanner, remote command construction, the
  monitor review path or the fleet loader.
- The smallest input that reproduces it, with identifiers replaced by placeholders.
- What an attacker or an unlucky operator actually gets: disconnection, unauthorised
  remote write, a leaked secret, an unbounded scan.
- Whether the operator has to do anything unusual to hit it.

## Response timeline

This project is maintained by one person, so these are honest targets rather than a
service level agreement.

| Stage | Target |
| --- | --- |
| Acknowledgement that the report was received | within 5 working days |
| Initial triage, severity assessment and a decision on whether it is in scope | within 10 working days |
| Fix or documented mitigation for a defect that can disconnect an operator, execute an unauthorised remote write, or leak a credential | within 30 days of triage |
| Fix or documented mitigation for everything else | best effort, tracked in a private advisory until released |

Fixes ship in a normal tagged release with the advisory published at the same time.
If you would like credit, say so in the report and give the name you want used. If a
report is out of scope, you will get a reply explaining why rather than silence.

## Supported versions

Only the latest tagged release receives security fixes. There is no long term support
branch. Install from an exact reviewed tag, as `README.md` describes; do not point an
installer at a floating branch.

## In scope

- **Control channel gate decision logic.** `netops_core/control_channel.py`, in
  particular `assess_control_channel` and the normalisation helpers around it. A case
  where the gate returns `allow` for an operation that would in fact cut the agent's
  own network path, or where a `warn` can be bypassed without the operator explicitly
  accepting the residual risk, is a vulnerability.
- **The change executor's backup and rollback contract.** `netops_core/change.py`. In
  scope: `apply_plan` or `rollback_plan` performing any write before the
  authorisation check; a plan ID confirmation that can be forged or replayed; a
  backup that does not actually capture the affected state; a rollback timer that is
  reported as armed but is not, or that is disarmed before verification succeeds; a
  receipt that misrepresents what was applied.
- **Redaction and bundle export leaking secrets.** `netops_core/redaction.py` and
  `netops_core/bundle.py`. An input that survives export with an address, host name,
  home directory, node share link or credential intact, when
  `--include-network-identifiers` was not given, is in scope. So is any path that
  lets a caller reach the unredacted content through what is documented as the
  redacted output.
- **The secret scanner failing to catch a credential.** `scripts/check_secrets.py`. A
  realistic credential format that the patterns miss is in scope, and so is the skip
  list: the scanner exempts `scripts/check_secrets.py` and
  `netops_core/redaction.py` from its own scan, which is a real surface if a secret
  can be made to land in either file.
- **Remote command construction.** Anywhere an operator supplied value reaches an SSH
  invocation, a shell string or a remote path. Injection, path traversal outside the
  declared target, and quoting defects that change which file is written are all in
  scope.
- **Text collected from a target influencing control flow.** Banners, logs,
  configuration files and command output are data, never instruction. A case where
  content gathered from a scanned or managed host can change a classification, skip a
  confirmation, or cause a command to run is in scope, and is treated as a high
  severity defect because a compromised target could then drive the operator's own
  machine.
- **Fleet and schema loading.** A crafted fleet document or change plan that escapes
  the declared validation and reaches the executor.
- **Scan boundaries.** Any way to make the read only scan write to a host, install a
  scheduled task, or reach the network without the explicit `--external` or
  `--tool-external` authorisation.

## Out of scope

- **Anything that requires the reporter to already own the target VPS and act with
  authorisation.** Operating your own infrastructure is the entire purpose of this
  tool. "I authorised NetOps against my own server and it changed my own server" is
  the product working. This is the single most common invalid report, so please check
  it before writing.
- Anything that requires the attacker to already have local shell access, root, or
  the operator's SSH key on the machine running NetOps. At that point the attacker
  does not need NetOps.
- The absence of scheduled monitor installation. `monitor install` and
  `monitor remove` are review only and fail closed in this release; a non dry run
  call raises rather than executing. That is documented posture, not a defect. The
  release gate in `scripts/release_check.py` asserts it.
- The SHA-256 manifest inside an exported bundle not being a signature. It only shows
  that the three archive members are mutually consistent and were not silently
  rewritten after the check. It does not attest to the origin device or operator, and
  `README.md` says so.
- Redaction heuristics not proving that an arbitrary opaque string is safe. No
  heuristic can. `README.md` states that manual review of the archive is still
  required before sharing it, so a residual value that only a human could recognise
  as sensitive is a documented limitation rather than a vulnerability.
- Reports that carrier or provider internal network segments are not fully visible.
  NetOps deliberately reports those as unobservable.
- Findings against a third party tool that NetOps merely invokes, such as MTR,
  NextTrace, dnsdiag, testssl.sh or iperf3. Report those upstream. A defect in how
  NetOps invokes them is in scope.
- Missing hardening that has no exploit path, results from an automated scanner with
  no analysis attached, or applies to a dependency this project does not have.
  `netops_core/` and `scripts/` are standard library only and `pyproject.toml`
  declares no runtime dependencies.

## Authorised use only

Point NetOps only at infrastructure you own or are explicitly authorised to manage.
The scanner is bounded and read only by default and the tool performs no port
sweeping, no credential guessing and no unauthorised remote operation, but no tool can
supply permission you do not have. Running scans or changes against someone else's
host without their authorisation is likely to be illegal where you live, is against
the intent of this project, and is not a use the maintainer will help with. Reports
that depend on directing the tool at a third party's infrastructure will be closed.
