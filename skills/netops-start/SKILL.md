---
name: "netops-start"
description: "Beginner onboarding for VPS networking and proxy operations. Use when the user has a new VPS, does not know where to start, or needs plain-language explanations of domains, ports, DNS, inbound/outbound, proxies, dual stack, routes, and basic connection safety. Offer a few explained goal and learning-depth choices when needed. This workflow teaches and routes; it delegates all measurements to netops-scan."
---

# NetOps Start

Help a beginner identify their goal without turning the conversation into a networking course.

## Shared Reference Root

Before reading a shared reference, resolve `<reference-root>` once. Use `../../references` when `../../references/guided-dialogue.md` exists (repository or monolithic root installation); otherwise use `../netops/references` when `../netops/references/guided-dialogue.md` exists (flat installation beside the root `netops` Skill). If neither candidate exists, stop and report an incomplete installation. Do not reconstruct or bypass missing safety rules.

## Remote Execution Release Boundary

This release stops at audit, plan, and review handoff. Do not call `change apply`, `change rollback`, SSH mutation, or any hidden execution path. Route build, repair, and maintenance requests to a reviewable plan without claiming that a remote write or rollback occurred.

## Guided Choices

Follow `<reference-root>/guided-dialogue.md`. If the user does not yet know what to ask, start with one short choice:

1. `先做只读体检（推荐）`: discover the current device and VPS state without changing anything.
2. `搭建或修改节点`: explain the required pieces, then hand off to an audit and change plan.
3. `解决正在遇到的问题`: identify the symptom and collect evidence from the failing path.

If the user asks for more or less explanation, offer `边做边解释（推荐）`, `先看结论`, or `深入原理`. Do not ask both question sets unless both decisions are actually needed. If the goal is already clear, explain the first unfamiliar term and route immediately without showing a menu.

## Workflow

1. Identify the immediate goal: connect, understand, build, repair, or maintain.
2. Explain only the terms required for that goal, using `<reference-root>/glossary.md`.
3. Ask for or discover the authorized VPS reference. Do not request secrets in chat when a local credential file already exists.
4. Invoke `netops-scan` for factual environment discovery. Do not implement a second scanner here.
5. Summarize the topology in the form `client -> access network -> VPS inbound -> routing -> outbound -> destination`.
6. Hand off to one next workflow and explain why.

Before routing into any network change, explain that Codex may depend on the same proxy path being repaired and apply `<reference-root>/control-channel-safety.md`. A beginner must understand which path will stay available, how the change is undone, and how to restore Codex access if it disconnects.

## Beginner Boundaries

- Say "the port is the service's door number" before introducing listener/socket details.
- Say "inbound is how traffic enters the VPS; outbound is how it leaves" before discussing Xray tags.
- Treat city, ISP, Wi-Fi/cellular, and public IP as detected or user-supplied variables, never defaults.
- Do not provide a full checklist when one safe scan can answer the question.
- Do not install or modify anything in this workflow.
- Never describe an in-app backup node as independent when restarting that same app or TUN would disconnect both nodes.
