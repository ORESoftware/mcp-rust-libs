# Rust MCP hardening crates

This first reviewed extraction contains the cross-fleet primitives found to be duplicated or missing during the August 2, 2026 audit:

- `ore-mcp-safety`: bounded byte accumulation, UTF-8-safe truncation, exact secret redaction, and header-value validation;
- `ore-mcp-http`: exact URL parsing, loopback-only HTTP, bearer-host allowlists, and a concrete bounded read client that disables redirects and ambient proxies and marks credentials as sensitive;
- `ore-mcp-process`: concurrent bounded stdout/stderr capture with timeout, kill, and reap semantics;
- `ore-mcp-testkit`: semantic JSON-RPC 2.0 stdout auditing under byte and frame limits.

Product tools, authorization, mutations, and business API clients remain in their owning MCP repositories.
