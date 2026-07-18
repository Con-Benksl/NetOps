---
name: netops-fix
description: Evidence-led diagnosis for VPS and proxy network failures such as disconnects, timeouts, inaccessible panels or sites, TUN loops, IPv6 bypass, DNS issues, UDP/QUIC filtering, MTU problems, TLS errors, resource exhaustion, upstream restrictions, IP reputation, and destination risk controls. Use after or alongside netops-scan.
---

# NetOps Fix

Diagnose by segment and falsifiable evidence. Do not convert a plausible story into a confirmed root cause.

## Layer Order

1. Client process, proxy mode, TUN, routes, DNS, and IPv4/IPv6.
2. Local access network, gateway, ISP path, loss, jitter, MTU, and TCP/UDP differences.
3. VPS DNS answer, ingress listener, firewall, TLS/Reality/HY2 handshake, and service health.
4. Xray routing, client identity, outbound selection, resource pressure, and logs.
5. Upstream proxy authentication, port/policy limits, DNS strategy, and actual exit.
6. Destination response, WAF, IP reputation, account risk controls, and protocol-specific behavior.

## Answer Contract

- Lead with the most likely failing segment, confidence, and two or three supporting observations.
- Give one safe next action that can confirm or reject the hypothesis.
- Keep alternatives ranked. Do not list every possible cause equally.
- If two devices fail together, identify their shared dependencies before blaming both clients.
- If restarting or reimporting fixes the issue, treat that as a state reset clue, not proof of the underlying cause.
- A site's rejection through one exit while direct access works distinguishes paths; it does not by itself prove whether the upstream provider or destination policy is responsible.

Use `../../references/troubleshooting-model.md` and the generalized cases in `../../references/cases/`.
