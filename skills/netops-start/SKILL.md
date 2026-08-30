---
name: "netops-start"
description: "Beginner onboarding for VPS networking and proxy operations. Use when the user has a first VPS, does not know where to start, or needs a plain-language explanation of domains, ports, DNS, inbound/outbound, proxies, dual stack, routes, or node protocols. This workflow teaches and routes; factual discovery belongs to netops-scan. 典型中文请求：第一次买 VPS 不知道从哪开始、这些术语是什么意思、自建和机场有什么区别、我该选哪种协议。"
---

# NetOps Start

Clarify the immediate goal, explain only what is needed, and route to the next workflow.

## Shared Reference Root

Before reading a shared reference, resolve `<reference-root>` once. Use `../../references` when `../../references/guided-dialogue.md` exists (repository or monolithic root installation); otherwise use `../netops/references` when `../netops/references/guided-dialogue.md` exists (flat installation beside the root `netops` Skill). If neither candidate exists, stop and report an incomplete installation. Do not reconstruct or bypass missing safety rules.

## Boundary

This onboarding workflow does not mutate systems itself. Answer a clear terminology question directly and do not create JSON. If the goal is unclear and the missing choice changes the next workflow, ask one plain-language question under `<reference-root>/guided-dialogue.md`; do not force an introductory menu.

## Branches

- Explain unfamiliar terms just in time with `<reference-root>/glossary.md`, then continue.
- When facts about the client, VPS, node, or path are missing, route to `netops-scan`; do not duplicate its scanner or ask the user to guess.
- Route requested construction to `netops-build`, an evidenced failure to `netops-fix`, and ongoing fleet work to `netops-manage`.
- Before routing into a network change, apply `<reference-root>/control-channel-safety.md` and make the available recovery path understandable.

Use local credential references when already supplied; do not ask the user to paste secrets. Never present a second node in the same proxy process or TUN as an independent recovery path.

## Output

Reply in the conversation with the answer, the minimum topology needed to understand it, and one next action. Avoid lectures, fixed reports, and long checklists.
