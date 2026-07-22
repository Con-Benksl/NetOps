---
name: "netops"
description: "Beginner-first VPS networking and proxy operations router. Use when a user asks about connecting to a VPS, understanding network terms, scanning a client/server/node path, deploying or changing 3x-ui/Xray/VLESS Reality/Hysteria2, diagnosing timeouts or blocked sites, or maintaining a stable multi-VPS fleet. Offer brief explained choices when the goal or observation point is unclear, but do not force a menu when the request is already actionable. Discover the environment before drawing conclusions; never assume the user's city, ISP, device, address family, protocol, or destination."
---

# NetOps

NetOps is the single public entry point for beginner VPS networking and proxy operations. Route natural-language requests to exactly one primary workflow, and call `netops-scan` whenever facts are missing.

## First Response

1. Restate the user's symptom or goal in one plain Chinese sentence.
2. Separate known facts from assumptions. Do not infer access type, ISP, region, TUN state, IPv4/IPv6 use, node protocol, or exit from a single public IP.
3. If the next step depends on the user's goal or risk preference, offer 2–3 explained choices and put the recommended choice first.
4. Prefer a bounded read-only scan before asking the user to run a long checklist.
5. Give one recommended next step. Put optional theory after the action.

## Guided Choices

Follow `references/guided-dialogue.md` for every workflow.

- Ask only when the answer changes the next action. Do not ask the user to choose facts that a read-only scan can discover.
- Use `request_user_input` or another structured question tool when available so choices are clickable. Otherwise show a short numbered list in Chinese.
- Ask at most three questions per turn, with 2–3 mutually exclusive choices per question. Put the recommended choice first and explain the impact of every option.
- When the request is already clear, route or act without forcing the user through a menu.
- A menu choice can select `read-only scan`, `plan only`, or `review and execute`. Execution still requires one final confirmation of the exact remote operation after impact and rollback details are shown; the user is not asked to copy remote Linux commands that Codex can run safely over SSH.

For an ambiguous request such as “帮我看看这台 VPS”, offer a context-appropriate version of:

1. `先只读检查（推荐）`: collect environment facts without changing the device.
2. `排查当前故障`: collect evidence around a specific symptom and time window.
3. `搭建或修改`: audit the live state and prepare a reviewable SSH transaction or exact plan before any write.

After the user chooses, acknowledge the choice and its boundary in one sentence, then proceed. Explain unfamiliar terms just in time instead of giving a networking lecture first.

## Control-Channel Gate

Before any action that can restart a proxy, take over TUN, or change DNS, routes, firewall rules, a node, or a VPS carrying Codex traffic, follow `references/control-channel-safety.md`.

1. Determine whether the change touches the local Mac control plane, the node/VPS currently carrying Codex traffic, or an unrelated remote VPS. Scanner clues do not prove the dependency by themselves.
2. For an unrelated remote VPS with no local-network change, allow authorized direct SSH execution. Codex performs the backup, Linux commands, validation, verification, and rollback; do not hand those commands to the user merely because they are writes.
3. If a remote target may carry Codex traffic, resolve the dependency. A shared path needs a verified independent path or an automatic rollback contract before a disruptive restart or network change.
4. Local TUN, system proxy, active proxy process, DNS, route, or firewall switching that could cut off Codex remains a manual user action. Guide only that local switch one step at a time, then continue the remote work automatically.
5. Before any authorized remote write, show affected components, unchanged invariants, expected interruption, failure consequences, backup, rollback, and verification. Use a plan ID when the exact-plan executor is used; otherwise confirm the exact SSH transaction summary.
6. If connectivity is lost, prioritize the emergency steps that restore a known-good path and restart Codex before continuing diagnosis.

## Route To One Workflow

- New user, terminology, first VPS, or "where do I start": `skills/netops-start/SKILL.md`.
- Environment discovery, path evidence, client/server comparison, or inspection of monitoring data: `skills/netops-scan/SKILL.md`.
- Install or change a panel, node, DNS record, inbound, outbound, TLS, firewall rule, or an approved standard: `skills/netops-build/SKILL.md`.
- Timeout, disconnect, inaccessible panel/site, payment refusal, DNS/TUN/IPv6 issue: `skills/netops-fix/SKILL.md`.
- Backups, upgrades, security, capacity, monitoring plan/status review, fleet standards/drift, subscriptions, or user lifecycle and quotas: `skills/netops-manage/SKILL.md`.

If one request spans workflows, select the workflow that produces the next necessary outcome. Example: an unknown disconnect starts in `netops-scan`; a proven configuration fault then moves to `netops-fix` or `netops-build`.

## Non-Negotiable Rules

- Operate only devices the user owns or is explicitly authorized to manage.
- Do not perform broad port scanning, credential guessing, traffic interception, or indefinite packet capture.
- Read SSH/fleet references without echoing secrets. Never put passwords, private keys, user/node/credential UUIDs, node URLs, proxy credentials, or API tokens in Git or reports. NetOps-generated run/observation IDs are non-secret diagnostic foreign keys and may appear in validated reports.
- A traceroute, ASN lookup, or public-IP service is evidence from one vantage point, not a complete physical route.
- Curated external tools are optional adapters, not trusted conclusions. Inspect `netopsctl tools status`, explain what data leaves the device, and obtain separate consent for external queries and load tests.
- Never download or run an unpinned `latest` script through a shell pipeline. Prefer an installed package or a reviewed official release and record its version or commit.
- Authorized direct SSH is allowed for an unrelated remote VPS when the operation does not change the local control plane or a remote path carrying Codex traffic. Back up affected state, validate before apply, verify new and preserved behavior, roll back on failure, and keep a concise receipt of commands and results.
- Use the exact-plan executor when its file-transaction contract fits the change or when a shared remote path needs automatic rollback. It is a safety tool, not a blanket ban on direct SSH.
- Scheduled monitor installation/removal is also unreleased. Only dry-run review material and owned-file integrity status are available; do not copy scheduler commands from a preview.
- Never restart or rewrite the active Codex network path until the control-channel gate has returned an allow decision.
- A purchased "IP" may be an authenticated SOCKS/HTTP upstream rather than an address assigned to the VPS. Classify it before changing routing.
- Preserve existing nodes and the host default route unless the user explicitly requests otherwise.

## Supporting Material

- Guided choices and explanations: `references/guided-dialogue.md`
- Beginner language and report order: `references/beginner-reporting.md`
- Terms: `references/glossary.md`
- What can and cannot be observed: `references/observable-path.md`
- Evidence and source policy: `references/source-policy.md`
- Curated tool selection, permissions, and compatibility: `references/curated-tools.md`
- Codex control-channel safety and emergency recovery: `references/control-channel-safety.md`
- Run the helper without assuming the current directory: use an installed `netopsctl`, or resolve this Skill directory and run `python3 <skill-root>/scripts/netopsctl.py --help`.

The helper is a data collector and controlled-change executor. Codex may also perform authorized direct SSH transactions under the same backup and verification rules; neither path replaces judgment, authorization, or end-to-end verification.
