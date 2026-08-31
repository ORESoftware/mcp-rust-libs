# ore-mcp-remote

`ore-mcp-remote` exposes an existing Rust `rmcp` server through the final
MCP 2025-11-25 Streamable HTTP transport at an exact `/mcp` endpoint. It keeps
the server's stdio transport intact for local clients while making the same
org-specific tools, resources, and prompts available to authenticated remote
clients.

The runtime treats Shared Auth as the identity authority. It verifies ES256
access tokens locally with a bounded JWKS cache and enforces the configured
issuer, resource audience, OAuth client, realm, session, scopes, product roles,
and assurance level. Raw access tokens never enter MCP request extensions and
must never be reused as credentials for downstream providers.

## Security properties

- exact HTTPS resource and issuer URLs;
- RFC 9728 protected-resource metadata;
- bounded JWKS documents, request bodies, session identifiers, and stateful
  session bindings;
- exact `Host` and `Origin` allowlists at the MCP transport;
- redirects and ambient HTTP proxies disabled for JWKS retrieval;
- stable, value-free authentication errors and bearer challenges;
- fail-closed startup/readiness behavior when Shared Auth policy or keys are
  unavailable;
- optional stateless operation, with session headers rejected in stateless
  mode;
- one final protocol version rather than a compatibility version range.

Product tools still own their provider credentials. Use scoped service
credentials from the secret store for GitHub, cloud, database, Kubernetes, and
NATS calls; never forward the caller's Shared Auth token to those systems.

## Construction

Build a `RemoteAuthPolicy` and `RemoteMcpConfig`, construct a
`SharedAuthVerifier`, warm its JWKS cache during startup, and pass the same
product-owned `rmcp::Service` factory used by stdio into
`protected_mcp_router`. The returned Axum router owns liveness, readiness,
protected-resource metadata, and `/mcp`.

The caller remains responsible for binding TLS (normally through the
organization's Kubernetes ingress), graceful shutdown, telemetry, and keeping
the configured public resource URL consistent with the external route.
