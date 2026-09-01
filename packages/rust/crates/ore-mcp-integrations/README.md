# ore-mcp-integrations

This crate supplies real, read-first provider adapters for the Rust MCP fleet.
It is not an arbitrary HTTP, Kubernetes, cloud, or message-bus proxy. Every
operation has a fixed provider endpoint or SDK method, validates an immutable
organization scope, bounds returned collections, projects a small safe result,
and reports one of the shared states:

- `ready`
- `not_configured`
- `degraded`
- `unauthorized`
- `forbidden`

The default `http-providers` feature includes:

- GitHub organization and latest-workflow reads;
- Supabase Auth settings and Data API schema discovery;
- Neon project and branch reads;
- Cloudflare exact-zone and DNS-posture reads;
- Google Cloud project and enabled-service reads.

Opt-in features use official Rust clients:

- `aws`: STS caller identity plus allowlisted EKS cluster discovery;
- `kubernetes`: namespaced Deployment and selector-bound Pod readiness;
- `nats`: exact-subject request/reply using the closed
  `ore.mcp.read.v1` service/dependency snapshot envelope.

Consumer repositories remain responsible for loading credentials from the
environment or approved secret store, constructing AWS/Kubernetes/NATS clients,
declaring exact organization scopes, performing product authorization, mapping
operations into organization-specific MCP tools, composing results, and
applying the final MCP output ceiling. Inbound MCP OAuth tokens must never be
passed to these upstream adapters.

Run the complete adapter gate with:

```sh
cargo test --locked -p ore-mcp-integrations --all-features
cargo clippy --locked -p ore-mcp-integrations --all-targets --all-features -- -D warnings
cargo doc --locked -p ore-mcp-integrations --all-features --no-deps
```
