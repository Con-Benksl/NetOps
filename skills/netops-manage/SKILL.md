---
name: "netops-manage"
description: "Long-term VPS network and proxy operations: scheduled monitoring, baselines, incident bundles, backups, upgrades, compatibility checks, security, capacity, multi-VPS standards and drift, user lifecycle, subscriptions, and read-only traffic portals. Use for reliability and ongoing fleet management rather than a one-time repair. 典型中文请求：几台 VPS 统一标准、定期备份和升级、加或删用户和限流、订阅链接管理、长期监控方案。"
---

# NetOps Manage

Keep the fleet understandable, reversible, and observable.

## Shared Reference Root

Before reading a shared reference, resolve `<reference-root>` once. Use `../../references` when `../../references/guided-dialogue.md` exists (repository or monolithic root installation); otherwise use `../netops/references` when `../netops/references/guided-dialogue.md` exists (flat installation beside the root `netops` Skill). If neither candidate exists, stop and report an incomplete installation. Do not reconstruct or bypass missing safety rules.

## Direct-Invocation Safety

These rules apply even when this child Skill is invoked without the root router. Authorized direct SSH is allowed for maintenance on an unrelated remote VPS when the local control plane remains unchanged. Require explicit authorization, affected-state backup, pre-apply validation, post-apply verification, executable rollback, and a concise receipt. Use a reviewed exact plan ID and `netopsctl change apply` for shared-path or exact-file transactions, not as a blanket requirement for every SSH maintenance action. Preserve existing nodes and the host default route unless the reviewed operation explicitly changes either invariant. Scheduled monitor installation and removal remain unreleased: `netopsctl monitor install/remove` may only generate dry-run review material and never touch a scheduler.

## Guided Choices

Follow `<reference-root>/guided-dialogue.md`. If the long-term goal is broad, offer:

1. `稳定性监控（推荐）`: establish a baseline and save bounded incident evidence.
2. `备份与安全`: check recoverability, exposed services, SSH, firewall, and secret handling.
3. `升级与标准化`: compare versions and configuration drift before planning separate changes.

For monitoring review location, offer `VPS 计划（推荐）`, `当前电脑计划`, or `两端分别审查`, and explain the different observation points. Generate review material only with `--dry-run`; do not claim that either side is installed or active.

For an executable remote maintenance change, show the execution confirmation card from `<reference-root>/guided-dialogue.md` and wait for authorization of the exact operation. The agent then executes the remote SSH transaction; an exact plan ID is additionally required only when the plan executor is selected. A general request such as “standardize these servers” is not authorization for every host or operation.

## Operating Rhythm

- Baseline: record versions, services, listeners, DNS, routes, inbounds/outbounds, exits, and normal latency/loss.
- Monitoring: review a bounded sampling design with `netopsctl monitor install --dry-run`, and use `monitor status` only for existing owned-file integrity. Do not install, stop, delete, or claim scheduler state in this release.
- Backup: keep timestamped, integrity-checked backups outside active paths and test rollback procedures.
- Upgrade: make versions a separate change with compatibility tests; never bundle an upgrade into an unrelated node addition.
- Security: expose only required listeners, protect management interfaces, review SSH and firewall state, and keep secrets outside Git.
- Capacity: observe CPU, memory, disk, file descriptors, conntrack, bandwidth, and per-client usage before changing limits.
- Multi-user: use distinct client identities for meaningful per-user usage and revocation. Keep the end-user portal read-only and hide VPS administration details.
- Curated tools: record the official source, local version or reviewed commit, compatibility baseline, and last verification date. Run `netopsctl tools status --versions` after an upgrade and before publishing a new NetOps release.
- Control continuity: maintain a documented management path that is not changed in the same maintenance window, rehearse the emergency card, and verify provider-console access and automatic rollback support. Follow `<reference-root>/control-channel-safety.md`.

## Monitoring Defaults

VPS is the recommended observation point when reviewing a future monitoring design; desktop review is opt-in. A compatible pre-existing sampler keeps data locally for seven days or 200 MB, whichever is reached first. Never capture packet payloads continuously. Curated tools, traceroute, IP reputation queries, and bandwidth tests are not part of compatibility sampling. See `<reference-root>/monitoring.md` and `<reference-root>/curated-tools.md`.

Do not call a second node in the same application a disaster-recovery path. Long-term readiness requires an independent process, network, device, or provider console, plus a recovery information card that contains no secrets.
