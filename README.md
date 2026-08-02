# NetOps

**English** · [简体中文](README.zh-CN.md)

Open-source community: [LINUX DO](https://linux.do)

[![test](https://github.com/Con-Benksl/NetOps/actions/workflows/test.yml/badge.svg)](https://github.com/Con-Benksl/NetOps/actions/workflows/test.yml)
[![licence](https://img.shields.io/badge/licence-MIT-blue.svg)](LICENSE)
[![python](https://img.shields.io/badge/python-3.10%20to%203.14-blue.svg)](https://www.python.org/)
[![dependencies](https://img.shields.io/badge/dependencies-none-brightgreen.svg)](pyproject.toml)

When a proxy or VPS breaks, the hard part is almost never the missing command. It is not knowing **which segment** is broken: your laptop, your local network, the VPS inbound, the proxy routing, the upstream exit, or the destination itself. NetOps finds the segment before it touches anything.

It ships as a set of Agent Skills for any coding or operations agent, Claude Code and Codex among them, plus a diagnostic CLI that uses only the Python standard library. You can describe a symptom in plain language, or run the scans yourself.

The working order is fixed: **scan first, conclude second; protect the agent's own network path before changing the network.**

## The segment model

A single proxied connection crosses roughly these positions:

```text
your computer -> local network -> VPS inbound -> proxy routing -> upstream exit -> destination
```

Every observation NetOps records carries a vantage point, a timestamp, a confidence level, and its limitations. Segments it cannot see are reported as unobservable rather than guessed. A traceroute or an ASN lookup is evidence from one vantage point, not a complete physical route, and NetOps says so in the report instead of drawing a confident line through a carrier's internals.

It also refuses to shortcut. A region name, an ISP name, or a destination site name never selects a conclusion on its own. Device, access type, address family, protocol, inbound, exit, and target are established first, then the evidence narrows the range.

## The control channel gate

This is the part worth your attention.

The agent fixing your network may be reaching the internet **through the very proxy it is about to restart**. Restart the wrong service and the agent disconnects along with you, mid transaction, with the verification step never run and the rollback never triggered. Most tooling in this space treats operator connectivity as the operator's problem. NetOps models it as a first class safety constraint that every workflow shares.

Before any action that can restart a proxy, take over TUN, or change DNS, routes, firewall rules, a node, or a VPS, the gate classifies the change and returns a machine readable decision. As of 0.3.2 the decision is only ever `allow` or `warn`. There is no unconditional block. The ladder is:

1. **Risk resolved** (`decision: allow`). The target is proven independent of the agent's current path, or a complete automatic rollback contract covers every declared target. Proceed under normal authorisation: show impact, backup, verification, and rollback, then get an explicit yes.
2. **Risk unresolved on a remote target** (`decision: warn`, `can_apply_with_acknowledgment: true`). The gate does not refuse. It presents a risk card: what breaks, the recovery path, the residual risks, and the safer alternatives. The change proceeds only after the user explicitly accepts the residual risk for that specific operation, via `--accept-residual-risk`, and the accepted risks are written into the receipt as `acknowledged_risks`.
3. **Local control plane** (`execution_mode: manual-local-control-plane`, `can_apply_with_acknowledgment: false`). Switching local TUN, the system proxy, an active proxy process, DNS, routes, or the firewall stays outside the remote executor no matter what the user consents to, because consent cannot keep a socket open. By default the user performs that one switch. If the user explicitly asks the agent to perform it and accepts the disconnection risk after seeing the recovery card, the agent may execute it locally, one action at a time; either way the agent confirms it is still online and then continues the remote work itself.

Consent is per operation and is recorded. It is not a mode you can leave switched on.

Two consequences worth stating plainly. A "backup node" inside the same proxy application is usually **not** an independent channel, because restarting that application or its TUN interface drops every node at once; a phone hotspot, a second device, a separate proxy process, or a provider console verified in advance is what actually qualifies. And if the connection is already lost, the fix is not to delete configuration or reinstall: shut down the TUN or system proxy under test, move to a known good independent network, confirm ordinary HTTPS works, restart the agent, and hand it the change summary or plan ID, the backup location, and the last completed step. Full procedure in [`references/control-channel-safety.md`](references/control-channel-safety.md).

## Quick start

No packages to install, no dependencies to resolve. Clone at the reviewed tag and run a bounded read only scan of the machine you are sitting at.

```bash
git clone --branch v0.5.1 --depth 1 https://github.com/Con-Benksl/NetOps.git
cd NetOps
python3 scripts/netopsctl.py scan client --output client.json
```

Requires Python 3.10 to 3.14. If the `v0.5.1` tag does not exist, that clone is meant to fail; do not fall back to `main` or to a floating version.

Optionally install it as a command:

```bash
python3 -m pip install .
netopsctl --help
```

### As an Agent Skill

Requires Node.js 22.20.0 or newer. Install from an exact reviewed release tag. Never hand a floating branch or a `latest` pipeline to a shell; both the installer version and the NetOps tag below are pinned. The installer may go non interactive inside an agent environment, so list first and confirm that exactly `netops` and its five sub Skills are discovered, then install as a separate step.

```bash
git clone --branch v0.5.1 --depth 1 https://github.com/Con-Benksl/NetOps.git
NPM_CONFIG_CACHE=/tmp/netops-npm-cache npx skills@1.5.19 add ./NetOps -l --full-depth
NPM_CONFIG_CACHE=/tmp/netops-npm-cache npx skills@1.5.19 add ./NetOps -g --agent codex --full-depth --skill '*'
```

For Claude Code, replace `--agent codex` with `--agent claude-code`; to install into every agent the CLI recognises on the machine, use `--agent '*'`. The Skill content itself is agent neutral: throughout these documents, "the agent" means whichever AI assistant is operating for you.

After that, describe the situation. The router picks one workflow and asks at most three questions per turn, two or three explained options each, recommended option first, and never asks you to guess something a read only scan can discover.

## A worked example

Symptom: a node connects, works for a while, then times out on everything.

**Step 1. Establish the local facts before blaming the server.** This is read only and stays on the machine.

```bash
python3 scripts/netopsctl.py scan client --output client.json
```

```json
{
  "bundle": "/home/you/client.json",
  "report": "/home/you/client.md",
  "run_id": "642dbb91-f43e-448f-a865-f45c312804f8"
}
```

Two files land: `client.json` for programs, `client.md` for humans. The Markdown report is written in Chinese and follows a fixed eight section order, so you always know where to look:

| # | Section | What it answers |
| --- | --- | --- |
| 1 | 一句话结论 | The one sentence conclusion |
| 2 | 检测到的环境 | Environment actually detected |
| 3 | 可观测链路 | Observable path, segment by segment |
| 4 | 异常区段 | Which segment is anomalous |
| 5 | 证据 | Evidence supporting the conclusion |
| 6 | 推荐下一步 | The single most useful next step |
| 7 | 无法观测的部分 | What could not be observed |
| 8 | 进阶解释 | Background for readers who want it |

Sections 4 and 6 are usually enough. High latency, loss at one hop, or a changed public IP are clues; none of them proves a cause on its own.

**Step 2. Probe the declared node.** Same output shape, this time with TLS and HTTP timings per step.

```bash
python3 scripts/netopsctl.py scan node \
  --target example.com --port 443 --tls --http --output node.json
```

**Step 3. Compare two machines** when the node behaves differently on each. The comparison only runs when target, protocol, and time window are compatible.

```bash
python3 scripts/netopsctl.py scan compare left.json right.json --output comparison.json
```

**Step 4. Check the control channel before changing anything.** Suppose the fix means restarting the proxy service on a VPS, and you have not yet proven your agent is not routed through it:

```bash
python3 scripts/netopsctl.py safety assess \
  --dependency shared --surface remote-proxy-service \
  --strategy automatic-rollback --rollback-delay 300 \
  --recovery-reviewed --evidence "rollback timer armed"
```

```json
{
  "guard": {
    "acknowledgment_required": true,
    "can_apply": false,
    "can_apply_with_acknowledgment": true,
    "decision": "warn",
    "execution_available": true,
    "execution_mode": "read-only",
    "reasons": ["尚未提供与本次变更目标绑定的自动回滚合同。"],
    "risk": "unresolved"
  },
  "rollback_timer": {"delay_seconds": 300, "enabled": true}
}
```

That is a reminder, not a dead end. `can_apply_with_acknowledgment: true` means the operation can still go ahead once the risk card has been shown and the user has explicitly accepted the residual risk for this operation. Had the change touched local TUN or the system proxy, `execution_mode` would read `manual-local-control-plane` and that flag would be `false`.

**Step 5. Plan, authorise, apply.** The reviewed plan and the execution are bound together by an ID, so what you approved is what runs.

```bash
netopsctl change plan --spec change-spec.json --fleet fleet.json --output change-plan.json
netopsctl change apply \
  --plan change-plan.json \
  --fleet fleet.json \
  --current-control-channel current-control-channel.json \
  --confirm-plan-id REVIEWED_PLAN_ID \
  --authorized \
  --receipt change-apply.receipt.json
```

`current-control-channel.json` holds only `observed_at` and a `control_channel` block identical to the plan's, observed no more than 15 minutes earlier. Working through the Skill, the agent generates it from the check it just ran; you do not hand write it. The executor stops before the first remote write if `--authorized` is missing, the plan ID does not match, the plan is older than 24 hours, the control channel evidence has expired or changed, the on host files have drifted, or the gate recomputes to `warn` without `--accept-residual-risk` for this run. Read the receipt before retrying: `rollback-pending` means an armed automatic rollback is still running and you should wait rather than reapply, and `consent-required` means the gate warned, consent was not supplied, and nothing was changed.

## Command reference

Once installed, every example below also works with the bare `netopsctl` entry point.

| Command | What it does |
| --- | --- |
| `netopsctl scan client` | Read only scan of the machine you are on |
| `netopsctl scan node` | Probe a declared node: resolution, TCP/UDP, TLS, HTTP, per step timings |
| `netopsctl scan server` | Local or authorised remote VPS state |
| `netopsctl scan compare` | Compare two bundles collected under matching conditions |
| `netopsctl tools status` | What curated tools are present and actually usable |
| `netopsctl safety assess` | Control channel decision before any change |
| `netopsctl change plan` / `apply` / `rollback` | The exact plan executor |
| `netopsctl monitor install --dry-run` | Non executable scheduling review material only |
| `netopsctl bundle export` / `inspect` | Redacted support archive, and its verification report |

`safety assess` reports a machine readable `execution_mode`, which is the boundary every workflow obeys:

| `execution_mode` | Meaning |
| --- | --- |
| `direct-ssh-or-plan` | The target is proven off the agent's path; direct SSH or the exact plan executor may proceed after authorisation |
| `exact-plan` | A shared path with a complete rollback contract; only the exact plan executor, with the timer armed before the first write |
| `manual-local-control-plane` | Touches the local TUN, system proxy, DNS, routes, or firewall; consent cannot hand it to the remote executor. The user performs the switch by default, or the agent does it locally one action at a time on explicit request |
| `read-only` | Path facts are still missing; establish them before changing anything |

## What it inspects

| Vantage point | What is collected |
| --- | --- |
| Client | OS, active interfaces, default route, DNS, TUN traces, IPv4/IPv6 |
| VPS | Resource use, system clock, routes, policy routing, firewall, listening ports, service state |
| Node | Name resolution, TCP/UDP reachability, TLS handshake, HTTP response, per step timings |
| 3x-ui / Xray | Version, service state, presence of the usual config files; inbounds, outbounds, and routing rechecked before any change |
| Curated tools | MTR, NextTrace, dnsdiag, testssl.sh, IPQuality, iperf3, chosen per question and never all run by default |
| Two device comparison | Two bundles compared when target, protocol, and time window match |

## The five workflows

Day to day you only need the router, `netops`. It selects exactly one primary workflow.

| Skill | Responsibility |
| --- | --- |
| `netops-start` | Explains terminology and helps a first time VPS user decide where to begin |
| `netops-scan` | Scans client, VPS, node, and the currently observable transport path |
| `netops-build` | Audits, plans, and after explicit authorisation executes 3x-ui, Xray, node, DNS, TLS, dedicated exit, or standards changes |
| `netops-fix` | Diagnoses disconnects, timeouts, TUN, DNS, IPv6, and destination refusals |
| `netops-manage` | Reviews monitoring plans and existing data; executes backup, upgrade, security, capacity, fleet standard and drift, and user lifecycle changes under the same gate. Still installs no scheduled tasks |

Protocol notes and individual incident write ups live in `references/`. A new destination site or a new carrier never earns a sixth Skill.

## Curated external tools

When the built in scans cannot answer the next question, NetOps can drive six actively maintained tools with parseable output. They are optional adapters, not trusted conclusions.

| Tool | Answers | Default bound |
| --- | --- | --- |
| MTR | Sustained latency, jitter, loss | 5 cycles, declared target only |
| NextTrace | TCP/UDP forward path snapshot | 3 samples, 30 hops, third party GeoIP off by default |
| dnsdiag | Latency and loss against a chosen resolver | Resolver must be stated explicitly |
| testssl.sh | TLS protocols, certificate, default parameters | Focused check, no bulk scanning |
| IPQuality | Reputation and classification clues for the current exit | Privacy mode, installs nothing, still queries several providers |
| iperf3 | Controlled performance sample between two endpoints you own | 5 second cap, separate consent for a load test |

Check what is present without sending a single probe:

```bash
python3 scripts/netopsctl.py tools list
python3 scripts/netopsctl.py tools status --versions
```

In that status, `detected` only means a local file was found. `usable` (and the compatibility field `available`) turns true only when version, argument capability, and the required checks all pass.

Consent is split deliberately. On a node scan, `--external` means you agree to let the selected tool talk to the target, resolver, or provider it declared:

```bash
python3 scripts/netopsctl.py scan node \
  --target example.com --port 443 --protocol tcp --tls \
  --tool mtr --external --output node-mtr.json
```

On a client or local server scan the flag is `--tool-external` instead, so that consenting to a tool is never mistaken for consenting to a public egress identity lookup. `--tool` accepts `{mtr,nexttrace,dnsdiag,testssl,iperf3}` on node scans and `{ipquality}` on client and server scans. iperf3 additionally requires `--allow-load`. Scripts such as IPQuality are never auto downloaded; when missing, NetOps prints the official source and how to point at your own copy. Compatibility rules are in [`references/curated-tools.md`](references/curated-tools.md).

## Sharing results

Export a redacted, self checking support bundle:

```bash
netopsctl bundle export diagnostics/node.json --output node-support.zip
netopsctl bundle inspect node-support.zip --report-output node-support-review.md
```

The archive must be `.zip`. By default it strips IP addresses, domains, IDNs, MAC addresses, home directories, credentials, and single label hosts appearing in values, host context, or explicit `*_by_host` / `hosts` maps. An arbitrary single word JSON key cannot be reliably told apart from a hostname, so dynamic host keyed maps must use that explicit naming; otherwise the exporter keeps the key as a field name. Suspected residual credentials are rejected by structured rules plus high confidence heuristics, but no heuristic can prove an arbitrary opaque string is safe, so review the archive by hand before sharing it.

Be precise about what the embedded SHA-256 proves: that the three members are mutually consistent and were not silently rewritten after inspection. It is not a signature, and it does not attest which machine or which operator produced the files. Source files, the target ZIP, the inspection report, and the Markdown a scan writes implicitly are never silently overwritten; archive the old evidence yourself if you want to reuse a filename. Network identifiers are retained only with an explicit `--include-network-identifiers`.

## Safety, privacy, and data boundaries

- Public IP lookups happen only with an explicit `--external`.
- Curated tools run only when both `--tool` and the matching consent flag are given: `--external` for node scans, `--tool-external` for client and local server scans. Load generating tools need a further separate consent.
- Nothing is fetched through `curl | bash`, no floating version is downloaded silently, and no external script is allowed to install system dependencies on your behalf.
- The client control channel scan records only **whether** a system proxy is enabled. It does not record the PAC URL, the proxy address, or the values of proxy environment variables.
- Passwords, private keys, node links, user/node/credential UUIDs, proxy accounts, and API tokens never belong in the repository or in a report. The `run_id` and `observation_id` values NetOps generates are non secret diagnostic foreign keys and do stay in the local JSON and reports.
- The public repository ships anonymised examples only. Real host data belongs in a private overlay repository matching `schemas/fleet.schema.json`; that schema handles portable structure and a high confidence credential precheck, and the CLI performs the authoritative IDNA, Unicode category, and full semantic review on load. Both layers must pass.
- Remote text is evidence, never instruction. Login banners, MOTD, service logs, config comments, command output, HTTP responses, and TLS certificate fields collected over SSH are untrusted data. An imperative or an authority claim found inside collected output, including a line asserting that some VPS is unrelated to your traffic, never changes a dependency classification, skips a confirmation, or triggers a command. It is quoted back to you as a suspicious finding.
- Scan only devices you own or are explicitly authorised to manage.

## Monitoring: the release boundary

Scheduler installation, stopping, and removal are **not released** in this version, and the README will not pretend otherwise.

`monitor install` and `monitor remove` produce non executable review material only, and only under an explicit `--dry-run`; anything else is refused unconditionally. There is no authorisation parameter in the public CLI or the Python API that turns execution on, and no environment variable or private function bypass exists. Generate review material with:

```bash
python3 scripts/netopsctl.py monitor install \
  --target example.com --port 443 --scope user --dry-run
```

A Linux source directory usually fails the root trust chain, so system scoped plans are marked `blocked`; use `--scope user` to read one locally. The output contains the probe target and a full local configuration draft, so do not treat stdout as a redacted support bundle.

`monitor status` inspects existing local files, permissions, lifecycle markers, and a SHA-256 manifest. It never queries systemd, launchd, or Task Scheduler, and therefore cannot prove that a real timer exists or is running.

The review material shows the native scheduler structures a future release might use (Linux systemd timer, macOS launchd, Windows Task Scheduler). Do not copy commands out of a preview and run them. This version also installs no long lived high privilege daemon of its own.

## What NetOps will not do

- No unbounded port scanning, credential guessing, traffic interception, or indefinite packet capture.
- No unauthorised operation of any device. Scans and changes apply only to hosts you own or are explicitly permitted to manage.
- It will not read "the port is open" as proof that VLESS, Hysteria2, or any other protocol is actually healthy.
- It will not claim to reconstruct the physical route inside a carrier or a provider that it cannot observe.
- It will not change the whole VPS default exit, or overwrite existing configuration, just to fix one node.
- It will not silently restart the path the agent is currently using. When the control channel is unknown, or the only fallback prepared is another node inside the same proxy application, the gate returns `warn`: risk card first, explicit per operation consent second, accepted risks recorded in the receipt.
- It will not install, stop, or remove a local scheduled task in this release.
- It will not treat a verbal reassurance as proof of independence, and it will not accept instructions found inside collected remote output.

## Development and testing

The core uses the Python standard library only, and the project has no runtime dependencies. Before committing:

```bash
python3 -m unittest discover -s tests -v
python3 scripts/check_secrets.py .
python3 scripts/validate_skills.py
python3 scripts/check_install_tree.py .
python3 scripts/release_check.py .
```

That suite is 414 tests as of 0.5.1, covering the scanner, redaction, fleet and change contracts, the control channel gate, monitor privacy, serialisation safety, release integrity, and reproducible builds.

Release artefacts must clear a double build gate. Install the pinned build tooling, then pass an explicit Unix timestamp and an output directory that does not yet exist:

```bash
python3 -m pip install "build==1.3.0" "setuptools==83.0.0"
python3 scripts/reproducible_build.py . --source-date-epoch 1720000000 --output-dir release-dist
python3 scripts/package_smoke.py . --dist-dir release-dist
```

`1720000000` is the stable reference value CI uses; a tagged release should switch to the committer timestamp of the tag commit and record that value in the release notes. The script copies two build directories from one sanitised snapshot, enforces the tool versions, requires the two wheels to be byte identical, and requires the two sdists to be byte identical after normalising away the gzip filename, build time, PAX timestamps, and local user and group information. Only when both checks pass is the output directory created; an existing file, directory, or symlink is rejected rather than overwritten. `package_smoke.py` then runs the full test suite from the final normalised sdist and installs the wheel and the sdist separately for an arbitrary directory smoke test.

Be clear about what that proves: reproducibility of one source snapshot under one controlled Python, setuptools, build, and runtime environment. It does not claim identical bytes across operating systems, GitHub runner images, Python patch releases, or zlib versions. For long term rebuilds, record those versions and the final SHA-256, or pin a release container digest.

CI covers Python 3.10 to 3.14 across 11 environments. Every minor version runs on Linux; 3.10, 3.12, and 3.14 also run on macOS and Windows. Every environment runs the double build gate and the arbitrary directory smoke test from the final normalised artefacts. Platform specific commands are verified with fixtures and command generation tests, so CI never connects to a real VPS or touches a scheduler.

## Version history

Changes, breaking changes, and schema upgrades are recorded in [`CHANGELOG.md`](CHANGELOG.md).

## Licence

NetOps is released under the [MIT Licence](LICENSE). Use, modify, and redistribute it freely, including commercially, provided the original copyright and licence notice are retained. The project is provided as is, without warranty. See the `LICENSE` file for the full terms.
