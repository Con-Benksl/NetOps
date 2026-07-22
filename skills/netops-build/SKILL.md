---
name: "netops-build"
description: "Safely audit and plan VPS networking and proxy-node changes, including 3x-ui, Xray, VLESS Reality, Hysteria2, TLS, DNS, IPv4/IPv6 separation, firewall rules, and per-node SOCKS/HTTP upstream exits. Use when the user asks to install, add, change, or apply an approved standard while preserving existing services. This release produces reviewable plans and handoff instructions but does not execute remote writes."
---

# NetOps Build

Build against live evidence, not remembered topology.

## Shared Reference Root

Before reading a shared reference, resolve `<reference-root>` once. Use `../../references` when `../../references/guided-dialogue.md` exists (repository or monolithic root installation); otherwise use `../netops/references` when `../netops/references/guided-dialogue.md` exists (flat installation beside the root `netops` Skill). If neither candidate exists, stop and report an incomplete installation. Do not reconstruct or bypass missing safety rules.

## Direct-Invocation Safety

These rules apply even when this child Skill is invoked without the root router. This release stops at audit, plan, and review handoff: `netopsctl change apply` and `netopsctl change rollback` are unconditionally unavailable and must not be bypassed. A separately operated remote mutation still requires a reviewed exact plan ID, explicit authorization, affected-state backup, pre-apply validation, post-apply verification, executable rollback, and an `allow` decision from `<reference-root>/control-channel-safety.md`. Preserve existing nodes and the host default route unless a separately reviewed exception explicitly changes either invariant.

## Guided Choices

Follow `<reference-root>/guided-dialogue.md`. Before any remote write, let the user choose the stopping point:

1. `只读审计（推荐）`: inspect the live state and report what would need to change.
2. `生成变更计划`: create a reviewable plan with invariants, validation, and rollback steps, but do not apply it.
3. `审核并交接`: prepare the same plan, review its exact plan ID, then stop before any remote write and hand the plan to a separately approved operator.

If the user wants a node but does not know which protocol fits, offer `根据扫描推荐（推荐）`, `优先 VLESS Reality`, or `优先 Hysteria2`, with a one-sentence explanation of TCP/UDP and network compatibility. Do not ask whether to preserve existing nodes, panel access, SSH, or the host default route; preserve them by default unless the user explicitly requests a reviewed exception.

## Change Gate

1. Apply `<reference-root>/control-channel-safety.md` and use `netopsctl safety assess` only for the preliminary dependency decision. Record whether Codex depends on the local proxy/TUN, target node, or VPS; a shared-path automatic rollback remains blocked until the final plan contains a target-bound rollback contract.
2. Run a server/node scan and inventory listeners, versions, routes, DNS records, inbounds, clients, outbounds, and current exits.
3. Classify every address as VPS-assigned, DNS answer, client ingress, or authenticated upstream proxy.
4. State invariants: the Codex management path, existing nodes, panel access, SSH, default route, and unrelated exits remain unchanged.
5. Produce a reviewable change spec and `netopsctl change plan` output, including `control_channel`, non-secret evidence, declared affected paths, covered backups, executable rollback/rollback verification, and `rollback_timer`. Treat the plan's recomputed `control_channel_guard` as the final decision.
6. Record whether the plan is ready for separate operator review. A blocked control-channel decision cannot be overridden by ordinary authorization.
7. Stop here in this release. Do not call `change apply`, `change rollback`, SSH mutation, or another hidden execution path.
8. Handoff notes may specify the required backup, independent recovery path, validation, and rollback evidence, but must not claim those actions have occurred.

If the user must switch a local proxy, TUN, or network manually, guide one step at a time using the purpose/operation/expected result/failure/undo format. If the user cannot recover, switch immediately to the emergency card in the shared reference; do not continue configuration work while control is unstable.

## Architecture Defaults

- Keep ingress and egress independent. Route a client/node to a unique outbound instead of changing the host default route.
- Put precise client/user rules before broad inbound/default rules.
- Split IPv4-only and IPv6-only node names when deterministic address-family selection matters.
- A separate panel-visible inbound needs its own listener identity and free port; a new outbound alone is not a new inbound.
- Never assume the newest Xray/3x-ui version is compatible. Record versions and test clients before upgrading.

Use `<reference-root>/build-runbook.md`. Protocol details belong there, not in new Skills.
