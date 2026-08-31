# Changelog

## Unreleased — DEN-965 client and provider parity

- define and validate the exact fleet evidence profile for six MCP clients, two transports, Shared Auth, eight infrastructure providers, org-specific catalogs, bounded outputs, and mutation gates;
- add hardened bounded HTTP reads plus scoped GitHub, AWS, GCP, Supabase, Neon, Cloudflare, Kubernetes, and NATS adapters;
- publish the deduplicated 51-repository authoritative fleet audit and its current migration findings;
- add `ore-mcp-remote` for exact-version Streamable HTTP, RFC 9728 discovery, pre-auth authority/origin checks, local ES256 Shared Auth verification, raw-token stripping, and bounded identity-bound sessions.

## Unreleased — DEN-957 telemetry remainder

- extract `ore-mcp-telemetry` with stderr-only JSON logging, snapshot-based secret-safe resources, validated credential-free OTLP endpoints, fail-open OpenTelemetry 0.32 exporters, and bounded-cardinality tool labels;
- keep endpoint/resource/tool policy available with `--no-default-features` so OpenTelemetry 0.27 product adapters can share the policy layer without a hidden SDK upgrade.

## Unreleased — August 2, 2026 fleet audit

- record 24 existing and five missing Rust MCP servers;
- add exact URL and bearer-host policies;
- add bounded incremental bytes and secret-safe external error shaping;
- add bounded subprocess capture to replace `wait_with_output`;
- add semantic JSON-RPC stdout conformance checks;
- add a static fleet audit with adversarial fixtures;
- set the production protocol baseline to MCP `2025-11-25` and keep the 2026 lifecycle preview opt-in.
