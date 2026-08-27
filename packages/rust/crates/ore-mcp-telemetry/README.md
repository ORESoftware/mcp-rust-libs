# ore-mcp-telemetry

Shared, secret-safe telemetry lifecycle for Rust MCP servers.

The crate owns:

- validated service identity and version metadata;
- bounded HTTP(S) OTLP endpoint validation with no embedded credentials, query, or fragment;
- deterministic resource assembly from caller-supplied environment snapshots;
- canonical identity/runtime-field ownership and secret filtering through `ore-mcp-bootstrap` and `ore-mcp-safety`;
- JSON logs written only to stderr;
- optional OpenTelemetry 0.32 OTLP trace and metric providers;
- fail-open exporter construction with status-only diagnostics;
- deterministic provider shutdown through `TelemetryGuard`; and
- bounded-cardinality tool spans/metrics that never record arguments, results, credentials, or user identity.

The crate never reads or mutates the process environment. Callers capture their approved startup inputs and pass them explicitly.

```rust
use std::collections::BTreeMap;

use ore_mcp_bootstrap::runtime::ServerIdentity;
use ore_mcp_telemetry::{TelemetryConfig, init};

# fn main() -> Result<(), Box<dyn std::error::Error>> {
let identity = ServerIdentity::stdio("example-mcp-server", "example")?;
let snapshot = BTreeMap::from([
    ("DEPLOYMENT_ENV".to_string(), "production".to_string()),
    (
        "OTEL_RESOURCE_ATTRIBUTES".to_string(),
        "cloud.region=us-east-1,team=platform".to_string(),
    ),
]);

let config = TelemetryConfig::new(identity, env!("CARGO_PKG_VERSION"), Some("info,hyper=warn"))?
    .with_resource_snapshot(&snapshot)
    .with_otlp_endpoint(Some("https://collector.example:4317"))?;
let guard = init(config);

// Keep `guard` alive until MCP protocol shutdown.
let _ = guard;
# Ok(())
# }
```

## Feature boundary

The default `otlp` feature constructs OpenTelemetry 0.32 exporters. With default features disabled, endpoint validation, resource assembly, stderr JSON logging, and tool-span helpers remain available without an OpenTelemetry SDK. Product servers still on the 0.27 cohort can use that policy layer while keeping their local exporter adapter.

## Ownership boundary

Product repositories remain responsible for:

- capturing approved environment/configuration inputs;
- deciding whether OTLP export is enabled;
- OTLP authentication headers and secret storage;
- `rmcp`-version-specific tool-router wrapping;
- product spans beyond the shared `mcp.tool.name` / class / outcome labels; and
- deployment and collector configuration.

Tool arguments, result bodies, credentials, exporter error details, and raw configuration values do not belong in the shared layer.
