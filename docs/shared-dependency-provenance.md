# Shared MCP dependency provenance

Rust MCP servers in the fleet have two related but independent dependency
contracts:

1. **Cargo runtime adoption.** A consumer declares at least one `ore-mcp-*`
   runtime or policy crate from `https://github.com/ORESoftware/mcp-rust-libs`
   at one lowercase 40-hex commit reachable from canonical `main`. Branches,
   tags, local paths, short revisions, split revisions, and unmerged PR-head
   revisions are not acceptable fleet provenance.
2. **Zed package graph declaration.** The consumer's `.zpkg.toml` declares
   `"oresoftware/mcp-rust-libs" = "^0.1.0"` and uses `cargo build --locked`.
3. **Zed frozen resolution.** The consumer has a regular, parseable `.zpkg.lock`
   with a nonempty structured resolution payload. A missing lock or a
   metadata-only placeholder such as `version = 1` must not be described as a
   frozen install.

These states are deliberately separate. A server can correctly use a reviewed
Cargo revision while Zed publication remains blocked, or it can declare the Zed
edge before the registry can produce a lock. Reports and pull requests must say
which state was actually verified.

## Consumer check

From this repository:

```sh
python3 tooling/audit_shared_dependency_provenance.py \
  --repo-root /path/to/example-mcp-server.rs \
  --verify-revision-reachability \
  --report artifacts/mcp-dependency-provenance.json
```

Add `--require-zed-lock` only after the recursive publication closure is known to
be available. That switch turns a missing or metadata-only lock into a hard
failure. Without it, the audit still reports the state as medium severity so CI
and reviewers cannot silently promote it to a frozen-install claim.

## Migration order

A consumer migration should:

1. adopt the smallest applicable `ore-mcp-*` crate and preserve direct `rmcp`
   compatibility where required;
2. pin one commit that is reachable from canonical `main` and refresh
   `Cargo.lock` with `cargo update --precise` rather than hand editing it;
3. add or update the checked `mcp-fleet-profile.json` and repository-local
   conformance tests;
4. declare the Zed package edge and a locked Cargo build;
5. publish the complete recursive graph through Zed; and
6. generate and verify a non-placeholder `.zpkg.lock` before enabling the
   frozen-resolution gate.

Until step 6 succeeds, Git remains the immutable Cargo transport and Zed remains
a declared-but-unfrozen package graph. This is a truthful intermediate state,
not release parity.
