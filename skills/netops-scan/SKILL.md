---
name: "netops-scan"
description: "Read-only scanning of clients, authorized VPS hosts, proxy nodes, and observable paths. Use when the requested outcome is evidence, comparison, a baseline, or existing monitor data, and when netops-fix needs evidence for an unknown failing segment. Report confidence and blind spots rather than claiming a complete physical route. 典型中文请求：扫描本机和 VPS、比较两台电脑、保存正常基线、收集故障证据。"
---

# NetOps Scan

Collect only the evidence needed to distinguish the client, access network, VPS ingress, proxy core, upstream egress, and destination.

## Shared Reference Root

Before reading a shared reference, resolve `<reference-root>` once. Use `../../references` when `../../references/guided-dialogue.md` exists (repository or monolithic root installation); otherwise use `../netops/references` when `../netops/references/guided-dialogue.md` exists (flat installation beside the root `netops` Skill). If neither candidate exists, stop and report an incomplete installation. Do not reconstruct or bypass missing safety rules.

## Read-Only Boundary

This Skill does not change the configuration or service state of an observed client, server, or network. A formal scan may write only its declared local machine-readable JSON bundle by default. Authorized SSH here is for scanning only; hand proven changes to `netops-build`, `netops-fix`, or `netops-manage`. This workflow does not install scheduled tasks.

## Branches

- `client`: OS, time, active interfaces, routes, DNS, TUN clues, address families, and bounded connectivity.
- `server`: resources, listeners, services, routes, firewall summary, congestion control, and 3x-ui/Xray presence on a local or authorized SSH target.
- `node`: protocol-matched DNS/TCP/TLS/HTTP checks to the declared endpoint, optionally through a declared local proxy.
- `compare`: compare compatible versioned bundles; `monitor evidence`: inspect existing samples under `<reference-root>/monitoring.md`.
- `control channel`: collect dependency clues needed by `<reference-root>/control-channel-safety.md`; clues alone do not prove independence.

Follow `<reference-root>/guided-dialogue.md`. When the requested observation point is clear, scan it directly. Ask one question only if an unavailable choice would change the target or scope; detect OS, DNS, TUN, routes, and address families instead of asking the user to identify them.

## Execution and Output

1. Confirm ownership or authorization and the observation point.
2. Use an installed `netopsctl`, or resolve the root Skill and run `python3 <skill-root>/scripts/netopsctl.py scan ... --output <file>`; never assume the current directory. Remote SSH scanning requires the authorized fleet/host contract and must not expose credential references.
3. Read `<reference-root>/observable-path.md` before attribution. When combining live observations with software or provider documentation, version claims, or external labels, also read `<reference-root>/source-policy.md`. Use a bounded trace only when it tests the unresolved segment.
4. If built-in probes are insufficient, read `<reference-root>/curated-tools.md`, disclose data or load impact, obtain the separate consent, and select one tool capable of falsifying the leading hypothesis. External requests and iperf3 load require their own flags.
5. For a formal scan, persist machine-readable JSON only. Do not automatically create Markdown or another report file. Reply in the conversation with conclusion, key evidence, limitations, and next step under `<reference-root>/beginner-reporting.md`. Pure questions create no JSON; explicit export requests may create the requested artifact.

On mobile, collect only available OS/client, access type, TUN/VPN, address-family, log, and controlled A/B evidence; mark unavailable fields unknown.
