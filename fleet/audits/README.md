# Historical MCP consumer observations

Files in this directory are dated, immutable observations used to preserve the
evidence and migration intent from earlier audit branches. They are **not** the
current release gate and must not be interpreted as a live fleet-completion
claim.

Current enforcement is owned by:

- `tools/audit_zed_mcp_contract.py` for one checked-out consumer; and
- `tools/audit_mcp_fleet.py` plus an explicit inventory for the complete fleet.

Those contracts permit the reviewed `cargo-registry`, `zed-vendor`, and exact
`git-mirror` transports. The earlier DEN-965 prototype assumed every consumer
must resolve directly from one canonical Git revision; that assumption was not
carried forward because it would reject valid registry and vendored adoption.

`dependency-provenance-audit-2026-09-01.json` records the four repositories and
publication-closure state observed on September 1, 2026. Re-run the current
contract against fresh checkouts before making any present-tense claim.
