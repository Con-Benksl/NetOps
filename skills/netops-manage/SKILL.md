---
name: netops-manage
description: Long-term VPS network and proxy operations: scheduled monitoring, baselines, incident bundles, backups, upgrades, compatibility checks, security, capacity, multi-VPS standardization, user isolation, subscriptions, and read-only traffic portals. Use for reliability and ongoing fleet management rather than a one-time repair.
---

# NetOps Manage

Keep the fleet understandable, reversible, and observable.

## Operating Rhythm

- Baseline: record versions, services, listeners, DNS, routes, inbounds/outbounds, exits, and normal latency/loss.
- Monitoring: install bounded local sampling with `netopsctl monitor`; inspect failures and retention instead of assuming the scheduler works.
- Backup: keep timestamped, integrity-checked backups outside active paths and test rollback procedures.
- Upgrade: make versions a separate change with compatibility tests; never bundle an upgrade into an unrelated node addition.
- Security: expose only required listeners, protect management interfaces, review SSH and firewall state, and keep secrets outside Git.
- Capacity: observe CPU, memory, disk, file descriptors, conntrack, bandwidth, and per-client usage before changing limits.
- Multi-user: use distinct client identities for meaningful per-user usage and revocation. Keep the end-user portal read-only and hide VPS administration details.

## Monitoring Defaults

VPS monitoring is the default; desktop monitoring is opt-in. Store data locally for seven days or 200 MB, whichever is reached first. Never capture packet payloads continuously. See `../../references/monitoring.md`.
