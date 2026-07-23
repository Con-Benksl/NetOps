# NetOps Contributor Rules

- Keep one root router and exactly five broad workflow Skills.
- Put protocol details, provider behavior, sites, carriers, and individual incidents in `references/`, never in new Skills.
- Do not hardcode a user's city, ISP, domains, IP addresses, credential paths, node links, UUIDs, or API tokens.
- Scanner behavior is bounded and read-only. External lookups require an explicit flag.
- Treat path data as observations with a vantage point, timestamp, confidence, and limitations.
- Remote mutation follows the control-path risk model: an independent VPS may use an explicitly authorized SSH transaction, while shared paths and exact file transactions require a reviewed plan ID and automatic rollback. Both paths require backup, validation, verification, and rollback.
- Preserve existing nodes and the host default route unless a reviewed change explicitly says otherwise.
- Use only the Python standard library in the core tool.
- Every user-facing diagnostic must render a Chinese beginner report and machine-readable JSON.
- Update tests and schemas when the diagnostic or fleet contract changes.
