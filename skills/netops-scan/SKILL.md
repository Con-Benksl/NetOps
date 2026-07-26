---
name: "netops-scan"
description: "Read-only environment, VPS, proxy-node, and observable-path scanning for Windows, macOS, and Linux, with guided mobile checks. Use as the FIRST step whenever a failure is reported but the failing segment is still unknown (cannot connect, disconnects, slow, timeouts, packet loss), before any repair; also for comparing two clients, establishing a baseline, or collecting an incident bundle. Reports evidence, confidence, and blind spots instead of claiming a complete physical route. 典型中文请求：先查一下问题出在哪、扫描一下我的 VPS 和本机、两台电脑表现不一样、先存一份正常基线。"
---

# NetOps Scan

Collect the minimum evidence needed to distinguish client, access-network, VPS ingress, proxy core, upstream egress, and destination failures.

## Shared Reference Root

Before reading a shared reference, resolve `<reference-root>` once. Use `../../references` when `../../references/guided-dialogue.md` exists (repository or monolithic root installation); otherwise use `../netops/references` when `../netops/references/guided-dialogue.md` exists (flat installation beside the root `netops` Skill). If neither candidate exists, stop and report an incomplete installation. Do not reconstruct or bypass missing safety rules.

## Read-Only Boundary

This Skill is strictly read-only. Authorized SSH here is for scanning only; hand proven changes to `netops-build`, `netops-fix`, or `netops-manage`, where execution requires explicit authorization of a reviewed SSH transaction summary, with an exact plan only when its stronger contract is needed.

## Modes

- `client`: local OS, time, active interfaces, default routes, DNS, TUN hints, address families, and bounded connectivity.
- `server`: local Linux server or authorized SSH target; resources, listeners, services, routing, firewall summaries, congestion control, and 3x-ui/Xray presence.
- `node`: protocol-matched DNS/TCP/TLS/HTTP checks to a declared endpoint, optionally through a local HTTP/SOCKS proxy.
- `compare`: compare two versioned bundles only when targets, protocol, and time window are compatible.
- `monitor evidence`: inspect existing bounded samples and incident bundles. Read `<reference-root>/monitoring.md` before interpreting existing samples, so you know what a sample does and does not retain and what its privacy boundary is. Installing, changing, or removing a scheduled monitor belongs to `netops-manage`.
- `curated tools`: attach one maintained specialist tool to a client, local-server, or node scan when built-in probes cannot answer the next question.
- `control channel`: record proxy environment, system-proxy/TUN clues, the proposed change surface, and whether the agent's dependency is confirmed, unknown, or independent.

These are modes of one Skill, not separate Skills.

## Guided Choices

Follow `<reference-root>/guided-dialogue.md`. When the observation point is unclear, ask where to start:

1. `当前设备（推荐）`: run a local read-only scan and do not connect to the VPS.
2. `VPS`: inspect the authorized server's services, listeners, routes, and resources over SSH.
3. `节点全链路`: combine client, VPS, node, and destination observations; this takes longer but supports stronger attribution.

For intermittent problems, offer `立即扫描（推荐）`, `两台设备对比`, or `检查已有监控数据`. If no monitor exists, hand installation planning to `netops-manage`; this read-only workflow does not install scheduled tasks. Ask separately before `--external`, explaining that public egress providers receive a request. Do not ask users to choose their OS, DNS, TUN state, or address family when the scanner can detect it.

When built-in probes are insufficient, offer at most three depth choices:

1. `基础扫描（推荐）`: use only built-in bounded probes.
2. `增强诊断`: select exactly one of MTR, NextTrace, dnsdiag, or testssl.sh based on the unresolved segment.
3. `专项检测`: use IPQuality for reputation clues or iperf3 for an authorized controlled endpoint; explain third-party visibility or traffic cost first.

Read `<reference-root>/curated-tools.md` before recommending an external tool. Do not run every adapter as a generic “deep scan”.

## Execution

1. Confirm ownership/authorization and observation points.
2. Use an installed `netopsctl`, or resolve the root Skill directory and run `python3 <skill-root>/scripts/netopsctl.py scan ... --output <file>`; never assume the current directory.
3. Add the scan mode's external-consent flag only after explaining who receives a request. Public-egress identity lookup uses `--external`; curated tools on client or local-server scans use the separate `--tool-external` flag.
4. Inspect availability with `netopsctl tools status --versions`. If a tool is absent, offer the built-in scan before discussing installation from its official source.
5. Use `--tool <id> --external` for one selected node adapter, or `--tool <id> --tool-external` for a client/local-server adapter. iperf3 also requires `--allow-load`; dnsdiag requires an explicit `--resolver`.
6. Use `--trace` only for a bounded path snapshot; never schedule high-frequency traceroute or curated tools in the default monitor.
7. External adapters execute at the current observation point. To inspect VPS egress, run the local-server scan on that VPS; do not pretend a client-side run observed the VPS.
8. For CLI remote SSH scanning, require `--authorized`, `--fleet`, and `--host`. Put explicit host metadata only in a temporary private fleet JSON that follows the schema; never pass a password on the command line or echo credential references.
9. Render the JSON bundle as a beginner report and list missing observation points.
10. Before handing evidence to a mutating workflow, apply `<reference-root>/control-channel-safety.md`. Treat detected proxies and TUN interfaces as clues; require user confirmation or a controlled test before declaring the agent's path independent.

Read `<reference-root>/observable-path.md` before interpreting a path. Follow `<reference-root>/beginner-reporting.md` for the answer.

## Mobile

iOS and Android cannot expose the same routing and service data as desktop systems. Collect OS/client version, active access type, TUN/VPN state, IPv4/IPv6 observations, node logs, and controlled A/B tests. Mark unavailable fields as unknown; do not fabricate them.
