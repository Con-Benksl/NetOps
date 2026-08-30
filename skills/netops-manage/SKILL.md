---
name: "netops-manage"
description: "Long-term VPS and proxy operations: monitoring review, baselines, incident bundles, backups, upgrades, compatibility, security, capacity, fleet drift, user lifecycle, subscriptions, and read-only traffic portals. Use for ongoing reliability and multi-VPS management rather than a one-time repair. 典型中文请求：统一多台 VPS、定期备份和升级、管理用户和限流、订阅管理、长期监控方案。"
---

# NetOps Manage

Keep the fleet observable, reversible, and understandable.

## Shared Reference Root

Before reading a shared reference, resolve `<reference-root>` once. Use `../../references` when `../../references/guided-dialogue.md` exists (repository or monolithic root installation); otherwise use `../netops/references` when `../netops/references/guided-dialogue.md` exists (flat installation beside the root `netops` Skill). If neither candidate exists, stop and report an incomplete installation. Do not reconstruct or bypass missing safety rules.

## Direct-Invocation Safety

These rules apply even when this child Skill is invoked without the root router. Authorized direct SSH is allowed for maintenance on an unrelated remote VPS when the local control plane remains unchanged. Require explicit authorization, affected-state backup, pre-apply validation, post-apply verification, executable rollback, and a concise receipt. Use a reviewed exact plan ID and `netopsctl change apply` for shared-path or exact-file transactions, not as a blanket requirement for every SSH maintenance action. Preserve existing nodes and the host default route unless the reviewed operation explicitly changes either invariant. Scheduled monitor installation and removal remain unreleased: `netopsctl monitor install/remove` may only generate dry-run review material and never touch a scheduler.

## Decision Boundary

Follow `<reference-root>/guided-dialogue.md`. Infer the branch from a clear request; do not make the user select a maintenance category first. Ask one question only when an unresolved fleet target, retention, or risk choice would materially change the work. A broad standardization goal is not authorization for every host or operation.

## Branches

- Baseline and monitoring: record current versions, services, listeners, DNS, routes, proxy paths, exits, and normal performance. Read `<reference-root>/monitoring.md`; this release may only generate dry-run review material for monitor lifecycle operations.
- Backup and recovery: keep timestamped, integrity-checked backups outside active paths and test the rollback procedure.
- Upgrade and drift: compare current state first, separate version changes from unrelated work, and verify client compatibility.
- Security and capacity: inspect exposed management surfaces, SSH/firewall state, secrets handling, resources, conntrack, bandwidth, and per-client usage before changing limits.
- Users and subscriptions: use distinct identities for accounting and revocation; keep end-user portals read-only and hide VPS administration details.
- Tool lifecycle: use official pinned sources and record the installed version or commit; follow `<reference-root>/curated-tools.md`.

## Change Boundary

Before executable maintenance, use `<reference-root>/guided-dialogue.md` for execution confirmation and `<reference-root>/control-channel-safety.md` for the execution mode and transaction lifecycle; those references own the complete contracts.

Monitoring observations stay local and bounded; never capture packet payloads continuously. An independent recovery path requires a separate process, network, device, or provider console, not merely a second node in the same application.
