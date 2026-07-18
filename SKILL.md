---
name: netops
description: Beginner-first VPS networking and proxy operations router. Use when a user asks about connecting to a VPS, understanding network terms, scanning a client/server/node path, deploying or changing 3x-ui/Xray/VLESS Reality/Hysteria2, diagnosing timeouts or blocked sites, or maintaining a stable multi-VPS fleet. Discover the environment before drawing conclusions; never assume the user's city, ISP, device, address family, protocol, or destination.
---

# NetOps

NetOps is the single public entry point for beginner VPS networking and proxy operations. Route natural-language requests to exactly one primary workflow, and call `netops-scan` whenever facts are missing.

## First Response

1. Restate the user's symptom or goal in one plain Chinese sentence.
2. Separate known facts from assumptions. Do not infer access type, ISP, region, TUN state, IPv4/IPv6 use, node protocol, or exit from a single public IP.
3. Prefer a bounded read-only scan before asking the user to run a long checklist.
4. Give one recommended next step. Put optional theory after the action.

## Route To One Workflow

- New user, terminology, first VPS, or "where do I start": `skills/netops-start/SKILL.md`.
- Environment discovery, path evidence, client/server comparison, or monitoring data: `skills/netops-scan/SKILL.md`.
- Install or change a panel, node, DNS record, inbound, outbound, TLS, or firewall rule: `skills/netops-build/SKILL.md`.
- Timeout, disconnect, inaccessible panel/site, payment refusal, DNS/TUN/IPv6 issue: `skills/netops-fix/SKILL.md`.
- Backups, upgrades, security, capacity, monitoring, standardization, subscriptions, or user isolation: `skills/netops-manage/SKILL.md`.

If one request spans workflows, select the workflow that produces the next necessary outcome. Example: an unknown disconnect starts in `netops-scan`; a proven configuration fault then moves to `netops-fix` or `netops-build`.

## Non-Negotiable Rules

- Operate only devices the user owns or is explicitly authorized to manage.
- Do not perform broad port scanning, credential guessing, traffic interception, or indefinite packet capture.
- Read SSH/fleet references without echoing secrets. Never put passwords, private keys, UUIDs, node URLs, proxy credentials, or API tokens in Git or reports.
- A traceroute, ASN lookup, or public-IP service is evidence from one vantage point, not a complete physical route.
- Remote changes require a reviewed plan, explicit authorization, backup, validation, verification, and rollback.
- A purchased "IP" may be an authenticated SOCKS/HTTP upstream rather than an address assigned to the VPS. Classify it before changing routing.
- Preserve existing nodes and the host default route unless the user explicitly requests otherwise.

## Supporting Material

- Beginner language and report order: `references/beginner-reporting.md`
- Terms: `references/glossary.md`
- What can and cannot be observed: `references/observable-path.md`
- Evidence and source policy: `references/source-policy.md`
- Run the helper: `python3 scripts/netopsctl.py --help`

The helper is a data collector and controlled executor. It does not replace judgment, authorization, or end-to-end verification.
