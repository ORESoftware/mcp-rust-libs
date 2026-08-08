# ore-mcp-runtime

`ore-mcp-runtime` provides a narrow, official-`rmcp` stdio lifecycle for the ORESoftware Rust MCP fleet.

## Owned by this crate

- validated stdio runtime metadata built on `ore-mcp-bootstrap::runtime::ServerIdentity`;
- explicit read-only versus mutation-capable access labels;
- configuration → telemetry → server-construction ordering;
- telemetry-guard retention through protocol shutdown;
- official `rmcp` stdio startup, wait, and error propagation;
- low-cardinality lifecycle spans that never include arguments, result bodies, credentials, or user identity data.

## Deliberately caller-owned

- product `ServerHandler` implementations and instructions;
- tool schemas, authorization, and business policy;
- startup configuration parsing and flag allowlists;
- tracing subscriber and OpenTelemetry provider construction;
- repository-specific router or tool-metadata normalization;
- HTTP/SSE transports and deployment configuration.

MCP owns stdout. Callers must install a stderr-only tracing subscriber before serving stdio.

## Ordered bootstrap

```rust,ignore
let spec = ore_mcp_runtime::RuntimeSpec::stdio(
    "example-mcp-server",
    "example",
    env!("CARGO_PKG_VERSION"),
    ore_mcp_runtime::AccessMode::ReadOnly,
)?;

ore_mcp_runtime::run_stdio(
    spec,
    parse_operational_config,
    initialize_stderr_telemetry,
    build_product_server,
)
.await?;
```

For a product hook after construction, call `prepare_stdio`, mutate only the product-owned server through `PreparedStdio::server_mut`, then call `serve`.

## Feature boundary

The default `rmcp-stdio` feature enables the transport and lifecycle span. With default features disabled, metadata, bootstrap ordering, and preparation remain available without `rmcp` or `tracing`.

## Migration cautions

Adopting this crate does not by itself prove protocol-version parity. Servers that currently hand-roll JSON-RPC or advertise MCP `2025-06-18` need separate golden server-info/tool-schema tests and a reviewed official-`rmcp` migration before claiming MCP `2025-11-25` conformance.
