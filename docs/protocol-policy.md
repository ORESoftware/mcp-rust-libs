# MCP protocol and SDK policy

The fleet's production protocol baseline is the latest final MCP release, currently `2025-11-25`. The `2026-07-28` revision still appears as a release candidate in the upstream specification release feed as of August 2, 2026, so new lifecycle behavior remains opt-in until the final release is published and the fleet conformance matrix passes.

Rust servers should use the official `rmcp` SDK rather than hand-written JSON-RPC dispatch. The fleet migration must prove both the current legacy initialization lifecycle and the newer discovery/stateless lifecycle before any server advertises `2026-07-28` as production-ready.

A repository must not hard-code `2024-11-05` or silently select one protocol without negotiation. Exact supported versions, SDK major version, transport, output bounds, and test evidence belong in the server manifest and machine-readable fleet report.
