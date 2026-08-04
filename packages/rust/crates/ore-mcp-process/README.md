# ore-mcp-process

Shared, bounded subprocess execution for ORESoftware Rust MCP servers.

The crate deliberately exposes two different overflow contracts instead of hiding policy in a generic helper:

- `run_bounded` is fail-fast. The first byte beyond either configured stream limit terminates and reaps the child and returns `StdoutTooLarge` or `StderrTooLarge`.
- `run_truncating` retains a bounded prefix for each stream, counts every discarded byte, and continues draining both pipes until the child exits. This avoids pipe deadlocks while allowing diagnostic tools to render explicit truncation markers.

Both APIs:

- execute a program directly with an argv vector rather than a product shell string;
- close stdin;
- drain stdout and stderr concurrently;
- validate a 1 KiB through 16 MiB per-stream limit;
- enforce one wall-clock deadline; and
- kill and reap a child on timeout or capture failure.

## Fail-fast example

```rust
use std::time::Duration;
use ore_mcp_process::{run_bounded, ProcessLimits};

let limits = ProcessLimits::new(
    Duration::from_secs(30),
    1024 * 1024,
    256 * 1024,
)?;
let output = run_bounded(None, "git", &["status", "--short"], limits).await?;
```

## Truncating example

```rust
use std::time::Duration;
use ore_mcp_process::{run_truncating, ProcessLimits};

let limits = ProcessLimits::new(
    Duration::from_secs(60),
    512 * 1024,
    512 * 1024,
)?;
let output = run_truncating(None, "cargo", &["test", "--all-targets"], limits).await?;
assert!(output.stdout.bytes.len() <= 512 * 1024);
let dropped = output.stdout.dropped_bytes;
```

## Pilot adoption rule

Consumer repositories must pin an immutable reviewed commit or release. A pilot must preserve its existing product-facing error strings, truncation markers, authorization gates, and final MCP response ceiling while replacing only the child-process capture implementation. Moving a product tool registry, credential, or business client into this crate is out of scope.

Product repositories remain responsible for:

- validating every program argument and working directory;
- deciding whether local code execution is independently authorized;
- redacting program names or diagnostics where necessary;
- rendering truncation markers and applying a final MCP response-size ceiling; and
- selecting fail-fast versus truncating behavior explicitly.

The crate contains no product tool registry, credentials, authorization policy, or business client code.