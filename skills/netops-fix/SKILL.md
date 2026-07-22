---
name: "netops-fix"
description: "Evidence-led diagnosis for VPS and proxy network failures such as disconnects, timeouts, inaccessible panels or sites, TUN loops, IPv6 bypass, DNS issues, UDP/QUIC filtering, MTU problems, TLS errors, resource exhaustion, upstream restrictions, IP reputation, and destination risk controls. Offer explained incident-state and observation-scope choices when needed. Use after or alongside netops-scan."
---

# NetOps Fix

Diagnose by segment and falsifiable evidence. Do not convert a plausible story into a confirmed root cause.

## Shared Reference Root

Before reading a shared reference, resolve `<reference-root>` once. Use `../../references` when `../../references/guided-dialogue.md` exists (repository or monolithic root installation); otherwise use `../netops/references` when `../netops/references/guided-dialogue.md` exists (flat installation beside the root `netops` Skill). If neither candidate exists, stop and report an incomplete installation. Do not reconstruct or bypass missing safety rules.

## Direct-Invocation Safety

These rules apply even when this child Skill is invoked without the root router. This release stops at audit, plan, and review handoff. Do not call `change apply`, `change rollback`, SSH mutation, or any hidden execution path. A separately operated remote mutation still requires a reviewed exact plan ID, explicit authorization for that ID, affected-state backup, pre-apply validation, post-apply verification, an executable rollback, and an `allow` decision from `<reference-root>/control-channel-safety.md`. Preserve existing nodes and the host default route unless a separately reviewed exception explicitly changes either invariant. Diagnosis and read-only evidence collection do not imply mutation authorization.

## Guided Choices

Follow `<reference-root>/guided-dialogue.md`. If timing is unknown, ask which state best matches the problem:

1. `现在正在发生（推荐）`: capture client and server evidence before restarting or changing configuration.
2. `偶尔发生`: establish a baseline and use bounded monitoring to catch the next incident.
3. `已经恢复`: inspect retained logs and compare before/after state, while accepting that the root cause may remain unproven.

When more than one observation path is available, offer `当前设备（推荐）`, `两台设备对比`, or `客户端和 VPS 联合检查`. Explain what each option can and cannot prove. Do not ask the user to choose among DNS, MTU, routing, TLS, or risk control as a cause; rank those hypotheses from evidence.

## Layer Order

1. Client process, proxy mode, TUN, routes, DNS, and IPv4/IPv6.
2. Local access network, gateway, ISP path, loss, jitter, MTU, and TCP/UDP differences.
3. VPS DNS answer, ingress listener, firewall, TLS/Reality/HY2 handshake, and service health.
4. Xray routing, client identity, outbound selection, resource pressure, and logs.
5. Upstream proxy authentication, port/policy limits, DNS strategy, and actual exit.
6. Destination response, WAF, IP reputation, account risk controls, and protocol-specific behavior.

## Repair Safety

Before restarting a local proxy, replacing a configuration, toggling TUN, changing DNS/routes/firewall, or restarting a node used by Codex, apply `<reference-root>/control-channel-safety.md`. Capture incident evidence first. If Codex dependency is unknown, do not use a restart as a diagnostic experiment.

For manual recovery, give exactly one main action, its expected result, what to do if the screen differs, and how to undo it. When the user reports that Codex or all applications are offline, stop root-cause diagnosis and use the emergency recovery card to restore a known-good path first.

## Curated Evidence

Use `<reference-root>/curated-tools.md` only after built-in evidence identifies the unresolved segment:

- MTR for reproducible latency, jitter, or end-to-end loss; NextTrace for a bounded protocol-matched path snapshot.
- dnsdiag for one declared resolver; testssl.sh for a declared TCP TLS service.
- IPQuality only for reputation and service-policy clues after ordinary connectivity is established. It cannot explain a transient disconnect by itself.
- iperf3 only between authorized controlled endpoints and only when throughput is the unresolved question.

Select one tool that can falsify the leading hypothesis. Do not run a generic collection of every script and then rank whichever output looks alarming.

## Answer Contract

- Lead with the most likely failing segment, confidence, and two or three supporting observations.
- Give one safe next action that can confirm or reject the hypothesis.
- Keep alternatives ranked. Do not list every possible cause equally.
- If two devices fail together, identify their shared dependencies before blaming both clients.
- If restarting or reimporting fixes the issue, treat that as a state reset clue, not proof of the underlying cause.
- A successful restart is not proof that the repair was safe; confirm the control path, old path, and rollback state afterward.
- A site's rejection through one exit while direct access works distinguishes paths; it does not by itself prove whether the upstream provider or destination policy is responsible.

Use `<reference-root>/troubleshooting-model.md`, `<reference-root>/curated-tools.md`, and the generalized cases in `<reference-root>/cases/`.
