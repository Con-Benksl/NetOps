---
name: netops-build
description: Safely plan and implement VPS networking and proxy-node changes, including 3x-ui, Xray, VLESS Reality, Hysteria2, TLS, DNS, IPv4/IPv6 separation, firewall rules, and per-node SOCKS/HTTP upstream exits. Use when the user asks to install, add, change, or standardize nodes while preserving existing services.
---

# NetOps Build

Build against live evidence, not remembered topology.

## Change Gate

1. Run a server/node scan and inventory listeners, versions, routes, DNS records, inbounds, clients, outbounds, and current exits.
2. Classify every address as VPS-assigned, DNS answer, client ingress, or authenticated upstream proxy.
3. State invariants: existing nodes, panel access, SSH, default route, and unrelated exits remain unchanged.
4. Produce a reviewable change spec and `netopsctl change plan` output.
5. Obtain explicit authorization for the exact plan ID.
6. Back up affected state, apply the minimum change, validate with the installed binary, verify new and old paths end to end, and roll back on failure.

## Architecture Defaults

- Keep ingress and egress independent. Route a client/node to a unique outbound instead of changing the host default route.
- Put precise client/user rules before broad inbound/default rules.
- Split IPv4-only and IPv6-only node names when deterministic address-family selection matters.
- A separate panel-visible inbound needs its own listener identity and free port; a new outbound alone is not a new inbound.
- Never assume the newest Xray/3x-ui version is compatible. Record versions and test clients before upgrading.

Use `../../references/build-runbook.md`. Protocol details belong there, not in new Skills.
