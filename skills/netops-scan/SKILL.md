---
name: netops-scan
description: Read-only environment, VPS, proxy-node, and observable-path scanning for Windows, macOS, and Linux, with guided mobile checks. Use before diagnosing uncertain network behavior, comparing two clients, establishing a baseline, or collecting an incident bundle. Reports evidence, confidence, and blind spots instead of claiming a complete physical route.
---

# NetOps Scan

Collect the minimum evidence needed to distinguish client, access-network, VPS ingress, proxy core, upstream egress, and destination failures.

## Modes

- `client`: local OS, time, active interfaces, default routes, DNS, TUN hints, address families, and bounded connectivity.
- `server`: local Linux server or authorized SSH target; resources, listeners, services, routing, firewall summaries, congestion control, and 3x-ui/Xray presence.
- `node`: protocol-matched DNS/TCP/TLS/HTTP checks to a declared endpoint, optionally through a local HTTP/SOCKS proxy.
- `compare`: compare two versioned bundles only when targets, protocol, and time window are compatible.
- `monitor`: install or inspect local scheduled sampling. VPS is the default location; desktop monitoring is opt-in.

These are modes of one Skill, not separate Skills.

## Execution

1. Confirm ownership/authorization and observation points.
2. Start with `python3 scripts/netopsctl.py scan ... --output <file>`.
3. Add `--external` only after explaining that public-IP providers receive a request.
4. Use `--trace` only for a bounded path snapshot; never schedule high-frequency traceroute.
5. For remote SSH scanning, require `--authorized` and a fleet entry or explicit host metadata without a password on the command line.
6. Render the JSON bundle as a beginner report and list missing observation points.

Read `../../references/observable-path.md` before interpreting a path. Follow `../../references/beginner-reporting.md` for the answer.

## Mobile

iOS and Android cannot expose the same routing and service data as desktop systems. Collect OS/client version, active access type, TUN/VPN state, IPv4/IPv6 observations, node logs, and controlled A/B tests. Mark unavailable fields as unknown; do not fabricate them.
