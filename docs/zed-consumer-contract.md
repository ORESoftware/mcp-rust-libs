# Zed-managed MCP Rust consumer contract

The canonical reusable MCP Rust implementation lives in `ORESoftware/mcp-rust-libs`. MCP servers in other GitHub organizations should consume released/pinned packages through the Zed package-management path rather than copying source, following a floating branch, or using an unreviewed path outside the consumer repository.

## Two layers of evidence

1. **Zed's native lock or resolution output** remains the package manager's source of truth.
2. **`.zed-pkg/mcp-rust-libs.json`** is a small companion attestation enforced by this repository. It binds each Cargo dependency to the consumer manifest, exact package version, selected Zed transport, and SHA-256 of the native lockfile.

The companion file does not replace or reinterpret the native Zed lock format. It makes adoption machine-verifiable across heterogeneous repositories without assuming every language client has the same manifest syntax.

## Supported Rust transports

### Cargo registry

Use an exact version and the reviewed Zed registry name:

```toml
[dependencies]
mcp-core = { version = "=1.2.3", registry = "zed-pkg" }
```

### Zed-managed vendor tree

Use an exact version and a path beneath `.zed-pkg/vendor/`:

```toml
[dependencies]
mcp-core = { version = "=1.2.3", path = ".zed-pkg/vendor/mcp-core" }
```

### Zed Git mirror

Use an HTTPS repository in `github.com/zed-pkg` and pin the exact 40- or 64-hex object revision. Branches and tags are not acceptable trust anchors:

```toml
[dependencies]
mcp-core = { version = "=1.2.3", git = "https://github.com/zed-pkg/mcp-core", rev = "0123456789abcdef0123456789abcdef01234567" }
```

## Companion evidence

```json
{
  "schema": "ores.mcp-rust-libs.consumer.v1",
  "package_manager": "https://github.com/zed-pkg",
  "consumer_repository": "example-org/example-mcp-server.rs",
  "lockfile": ".zed-pkg/zed.lock",
  "lockfile_integrity": "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
  "packages": [
    {
      "name": "mcp-core",
      "version": "=1.2.3",
      "manifest": "Cargo.toml",
      "transport": "cargo-registry",
      "registry": "zed-pkg"
    }
  ]
}
```

Declare every package imported from `mcp-rust-libs`, not only one representative crate. The lockfile must contain each package name and resolved version, and its digest must match the checked-in evidence.

## Consumer CI

After checking out the exact pull-request revision with persisted credentials disabled, pin the reusable action to a reviewed commit:

```yaml
- uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1
  with:
    persist-credentials: false
- uses: ORESoftware/mcp-rust-libs/.github/actions/audit-zed-mcp-contract@FULL_REVIEWED_COMMIT_SHA
```

The action rejects:

- Git dependencies without an exact object revision;
- branch and tag selectors;
- embedded Git credentials or non-HTTPS Git sources;
- path dependencies that escape the repository;
- missing/tampered Zed lock evidence;
- non-exact MCP package versions;
- a Cargo source that does not match the declared Zed transport;
- evidence whose `consumer_repository` does not match `GITHUB_REPOSITORY`.

## Fleet rollout

Adoption should be performed as one pull request per MCP server repository. Each PR should inventory the existing MCP crates, replace copied/floating sources with one supported Zed transport, add lock evidence, pin the reusable audit action, and run that server's protocol and integration tests. Private cross-organization discovery requires an authorized GitHub App installation; this library's CI intentionally does not request a broad token or silently enumerate private repositories.
