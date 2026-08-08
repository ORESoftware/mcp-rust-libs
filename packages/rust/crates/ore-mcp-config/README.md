# ore-mcp-config

`ore-mcp-config` is the fleet-wide strict adapter between MCP server startup code and the existing reviewed `flags2env` Rust client.

It does **not** parse command lines itself. The pinned flags2env revision owns `.cli-flags.toml` audit, argv parsing, dotenv channels, declared defaults, and typed coercion. This crate adds MCP-specific policy:

- reject parser errors, unknown options, and unexpected positionals;
- merge dotenv, caller environment, dotenv overrides, and argv values in the documented order;
- reject sensitive-looking argv keys so secrets remain environment-only;
- preserve command/subcommand/source-order metadata;
- validate log filters through `ore-mcp-bootstrap`;
- avoid process-environment mutation; and
- expose keys and counts, never values, in `Debug` or `Display` diagnostics.

## Basic use

```rust
use std::collections::BTreeMap;

use ore_mcp_config::StrictConfig;
use serde::Deserialize;

#[derive(Deserialize)]
struct StartupConfig {
    org_root: String,
    rust_log: String,
}

# fn example() -> Result<(), Box<dyn std::error::Error>> {
let contract = StrictConfig::new(".cli-flags.toml");
let argv = vec!["server".to_string(), "--org-root=/srv/org".to_string()];
let environment = BTreeMap::new();
let (resolved, typed): (_, StartupConfig) = contract.resolve_typed(&argv, &environment)?;
let filter = resolved.validated_log_filter("RUST_LOG", "info")?;
# let _ = (&typed.org_root, &typed.rust_log, filter);
# Ok(())
# }
```

Servers that want the current process environment can call `resolve_process(argv)`. Tests and embedded runtimes should prefer an explicit environment map for deterministic behavior.

## Environment-only policy

The default policy rejects command-line values for keys recognized by `ore-mcp-bootstrap` as sensitive and for common credential-bearing connection keys such as `DATABASE_URL`, `REDIS_URL`, `BROKER_URL`, `AMQP_URL`, `NATS_URL`, `KAFKA_URL`, OTLP header bundles, and passphrases.

Ordinary operational values such as `API_URL`, `ORG_ROOT`, `RUST_LOG`, and server identity remain product-controlled. Product contracts should still omit every credential from `[flags.*]` and place secret names in `[env].ignore`.

## Ownership boundary

This crate does not own:

- product-specific configuration structs;
- credentials or secret storage;
- process-environment mutation;
- SOPS/decryption workflows;
- dynamic-library loading policy;
- tracing subscriber or OTLP exporter construction;
- product tool registries; or
- authorization and mutation gates.

The exact flags2env Git revision is committed in the shared Rust lockfile. Consumers must adopt an immutable reviewed release or revision rather than a moving branch.
