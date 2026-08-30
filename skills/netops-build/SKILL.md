---
name: "netops-build"
description: "Audit, plan, and execute authorized VPS networking or proxy-node changes, including 3x-ui, Xray, VLESS Reality, Hysteria2, TLS, DNS, address-family separation, firewall rules, and per-node upstream exits. Use for installing, adding, or changing services while preserving existing behavior. 典型中文请求：装一个节点、增加入站、换域名和证书、给某个节点单独配置出口、修改端口和防火墙。"
---

# NetOps Build

Build from current evidence and make the smallest reviewed change.

## Shared Reference Root

Before reading a shared reference, resolve `<reference-root>` once. Use `../../references` when `../../references/guided-dialogue.md` exists (repository or monolithic root installation); otherwise use `../netops/references` when `../netops/references/guided-dialogue.md` exists (flat installation beside the root `netops` Skill). If neither candidate exists, stop and report an incomplete installation. Do not reconstruct or bypass missing safety rules.

## Direct-Invocation Safety

These rules apply even when this child Skill is invoked without the root router. Authorized direct SSH is allowed when the target VPS is unrelated to the agent's current path and the change does not modify the local control plane. Require explicit authorization, affected-state backup, pre-apply validation, post-apply verification, executable rollback, and a concise receipt. Use an exact plan ID and `netopsctl change apply` when its file-transaction contract fits or when a shared remote path needs automatic rollback; do not force every independent SSH change through that executor. Preserve existing nodes and the host default route unless the reviewed operation explicitly changes either invariant.

## Decision Boundary

Follow `<reference-root>/guided-dialogue.md`. A clear audit-only, plan-only, or execution request proceeds to that boundary without a process menu. Ask one design question only when the answer cannot be discovered safely and would change the implementation. Never ask whether to preserve existing nodes, panel access, SSH, or the default route; those are invariants unless the user explicitly requests a reviewed exception.

## Change Flow

1. Audit the live target and define the exact delta, affected components, invariants, and actual ingress/egress identities.
2. Apply `<reference-root>/control-channel-safety.md` and the evidence ladder in `<reference-root>/independence-protocol.md`.
3. Use `<reference-root>/guided-dialogue.md` for execution confirmation and `<reference-root>/control-channel-safety.md` for the execution mode and transaction lifecycle; those references own the complete contracts.
4. If control has already been lost, stop the change and use `<reference-root>/emergency-recovery.md`.

## Architecture Defaults

Keep ingress and egress independent; route a named client or inbound to its outbound instead of changing the host default route. Put precise rules before broad defaults, use separate listener identities for separate inbounds, and verify current component/client compatibility before an upgrade.

Use `<reference-root>/build-runbook.md` for protocol and provider mechanics. Keep those details out of this Skill.
