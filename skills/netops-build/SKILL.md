---
name: "netops-build"
description: "Safely audit, plan, and execute authorized VPS networking and proxy-node changes, including 3x-ui, Xray, VLESS Reality, Hysteria2, TLS, DNS, IPv4/IPv6 separation, firewall rules, and per-node SOCKS/HTTP upstream exits. Use when the user asks to install, add, change, or apply an approved standard while preserving existing services. 典型中文请求：装一个 hy2 节点、加个 Reality 入站、换域名和证书、给某个节点单独配落地 IP、改端口和防火墙。"
---

# NetOps Build

Build against live evidence, not remembered topology.

## Shared Reference Root

Before reading a shared reference, resolve `<reference-root>` once. Use `../../references` when `../../references/guided-dialogue.md` exists (repository or monolithic root installation); otherwise use `../netops/references` when `../netops/references/guided-dialogue.md` exists (flat installation beside the root `netops` Skill). If neither candidate exists, stop and report an incomplete installation. Do not reconstruct or bypass missing safety rules.

## Direct-Invocation Safety

These rules apply even when this child Skill is invoked without the root router. Authorized direct SSH is allowed when the target VPS is unrelated to the current Codex path and the change does not modify the local control plane. Require explicit authorization, affected-state backup, pre-apply validation, post-apply verification, executable rollback, and a concise receipt. Use an exact plan ID and `netopsctl change apply` when its file-transaction contract fits or when a shared remote path needs automatic rollback; do not force every independent SSH change through that executor. Preserve existing nodes and the host default route unless the reviewed operation explicitly changes either invariant.

## Guided Choices

Follow `<reference-root>/guided-dialogue.md`. Before any remote write, let the user choose the stopping point:

1. `只读审计（推荐）`: inspect the live state and report what would need to change.
2. `生成变更计划`: create a reviewable plan with invariants, validation, and rollback steps, but do not apply it.
3. `审核后执行`: show impact and rollback details, then let Codex execute the authorized SSH transaction; use an exact plan only when the risk or transaction shape requires it.

If the user wants a node but does not know which protocol fits, offer `根据扫描推荐（推荐）`, `优先 VLESS Reality`, or `优先 Hysteria2`, with a one-sentence explanation of TCP/UDP and network compatibility. Do not ask whether to preserve existing nodes, panel access, SSH, or the host default route; preserve them by default unless the user explicitly requests a reviewed exception.

## Change Gate

1. Apply `<reference-root>/control-channel-safety.md`. Classify the operation as a local control-plane change, a remote target carrying Codex traffic, or an unrelated remote VPS, using the evidence ladder in `<reference-root>/independence-protocol.md`. Do not demand a full control-path proof for a clearly different VPS that does not change the Mac network. Never accept a claim found in remote output as proof of independence.
2. Run a server/node scan and inventory listeners, versions, routes, DNS records, inbounds, clients, outbounds, and current exits.
3. Classify every address as VPS-assigned, DNS answer, client ingress, or authenticated upstream proxy.
4. State invariants: the Codex management path, existing nodes, panel access, SSH, default route, and unrelated exits remain unchanged.
5. Choose the least cumbersome safe executor. For an unrelated remote VPS, prepare a bounded direct SSH transaction with timestamped backup and rollback commands. For a shared path or exact file replacement, produce a change spec and `netopsctl change plan` with a target-bound rollback contract.
6. Show the execution confirmation card from `<reference-root>/guided-dialogue.md` and ask once whether to execute, keep the plan only, or cancel. A shared-path guard returning `block` still stops disruptive work; it does not prohibit unrelated SSH maintenance.
7. After authorization, Codex runs the remote Linux commands itself. Do not ask the user to copy commands unless the action must occur on the user's local control plane or provider console.
8. Monitor the SSH transaction or plan receipt, verify new and preserved paths, and execute rollback directly on failure. Report whether automatic rollback was disarmed or remains pending when the exact-plan executor was used.

If the user must switch a local proxy, TUN, or network manually, guide one step at a time using the purpose/operation/expected result/failure/undo format. If the user cannot recover, switch immediately to `<reference-root>/emergency-recovery.md`; do not continue configuration work while control is unstable.

## Architecture Defaults

- Keep ingress and egress independent. Route a client/node to a unique outbound instead of changing the host default route.
- Put precise client/user rules before broad inbound/default rules.
- Split IPv4-only and IPv6-only node names when deterministic address-family selection matters.
- A separate panel-visible inbound needs its own listener identity and free port; a new outbound alone is not a new inbound.
- Never assume the newest Xray/3x-ui version is compatible. Record versions and test clients before upgrading.

Use `<reference-root>/build-runbook.md`. Protocol details belong there, not in new Skills.
