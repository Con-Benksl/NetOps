---
name: netops-start
description: Beginner onboarding for VPS networking and proxy operations. Use when the user has a new VPS, does not know where to start, or needs plain-language explanations of domains, ports, DNS, inbound/outbound, proxies, dual stack, routes, and basic connection safety. This workflow teaches and routes; it delegates all measurements to netops-scan.
---

# NetOps Start

Help a beginner identify their goal without turning the conversation into a networking course.

## Workflow

1. Identify the immediate goal: connect, understand, build, repair, or maintain.
2. Explain only the terms required for that goal, using `../../references/glossary.md`.
3. Ask for or discover the authorized VPS reference. Do not request secrets in chat when a local credential file already exists.
4. Invoke `netops-scan` for factual environment discovery. Do not implement a second scanner here.
5. Summarize the topology in the form `client -> access network -> VPS inbound -> routing -> outbound -> destination`.
6. Hand off to one next workflow and explain why.

## Beginner Boundaries

- Say "the port is the service's door number" before introducing listener/socket details.
- Say "inbound is how traffic enters the VPS; outbound is how it leaves" before discussing Xray tags.
- Treat city, ISP, Wi-Fi/cellular, and public IP as detected or user-supplied variables, never defaults.
- Do not provide a full checklist when one safe scan can answer the question.
- Do not install or modify anything in this workflow.
