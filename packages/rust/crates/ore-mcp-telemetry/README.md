# ore-mcp-telemetry

Shared, secret-safe telemetry lifecycle for Rust MCP servers.

The crate owns:

- validated service identity and version metadata;
- bounded HTTP(S) OTLP endpoint validation with no embedded credentials, query, or fragment;
- deterministic resource assembly from caller-supplied environment snapshots;
- canonical identity/runtime-field ownership and secret filtering through `ore-mcp-bootstrap` and `ore-mcp-safety`;
- JSON logs written only to stderr;
- optional OTLP trace and metric providers;
- fail-open exporter construction with status-only diagnostics; and
- deterministic provider shutdown through `TelemetryGuard`.

The crate never reads or mutates the process environment. Callers capture their approved startup inputs and pass them explicitly.

```rust
use std::collections::BTreeMap;

use ore_mcp_bootstrap::runtime::ServerIdentity;
use ore_mcp_telemetry::{TelemetryConfig, init};

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
# let _ = guard;
# Ok::<(), Box<dyn std::error::Error>>(())
```

Product repositories remain responsible for:

- capturing approved environment/configuration inputs;
- deciding whether OTLP export is enabled;
- OTLP authentication headers and secret storage;
- product spans, metrics, tool names, and authorization attributes;
- `rmcp`-version-specific tool-router wrapping; and
- deployment and collector configuration.

Tool arguments, result bodies, credentials, exporter error details, and raw configuration values do not belong in the shared layer.