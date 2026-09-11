# Shared MCP security boundary

This repository owns cross-cutting safety, transport policy, bounded process execution, conformance primitives, and narrowly fixed read adapters with bounded provider projections. Product tools, authorization, mutation gates, credentials, organization resource maps, upstream business clients, and business policy remain in their owning repositories.

Fleet invariants:

- stdout is reserved for MCP protocol frames; diagnostics use stderr;
- shared telemetry never logs tool arguments, result bodies, credentials, user identity, or unbounded payloads;
- HTTP bearer credentials are sent only to exact allowlisted hosts with redirects disabled;
- response and subprocess output are bounded before buffering;
- child processes use argv vectors, bounded deadlines, kill-on-overflow, and reap semantics;
- external errors are bounded, single-line, and scrubbed of exact known credentials;
- mutations remain fail-closed and repository-local.
