# MCP Rust fleet adoption audit

The per-consumer contract in `docs/zed-consumer-contract.md` proves that one checked-out repository imports `mcp-rust-libs` packages through a supported Zed path. `tools/audit_mcp_fleet.py` proves that a complete, explicitly inventoried set of checked-out MCP repositories satisfies that contract together.

The fleet tool is deliberately offline. It does not enumerate GitHub, request a personal access token, clone repositories, open pull requests, or print dependency bodies. A separately authorized GitHub App or operator materializes read-only checkouts under a deterministic directory layout:

```text
fleet-checkouts/
  owner-a/
    first-mcp-server/
  owner-b/
    second-mcp-gateway/
```

The inventory uses the same `OWNER/REPOSITORY` string as both `repository` and `checkout`. This prevents an inventory entry from silently pointing at a different working tree.

## Inventory states

- `adopted`: the checkout must contain `.zed-pkg/mcp-rust-libs.json`; all imported MCP packages must use an exact approved Zed transport and exact lock evidence; every `expected_packages` entry must be present.
- `pending`: requires a Linear issue and fails release mode. `--allow-pending` is an audit/reporting option only; it must not be used for a fleet-complete release gate.
- `waived`: requires a bounded reason, Linear issue, and expiry no more than 90 days away. Expired or overlong waivers fail.

The scanner also discovers likely MCP repositories from repository names and Cargo manifests. A discovered checkout absent from the inventory fails with `MCP-FLEET-018`. This makes “all consumers adopted” an inventory-completeness claim rather than a count of whichever repositories happened to be listed.

## Run locally or in an authorized inventory job

```bash
python3 tools/audit_mcp_fleet.py \
  --inventory /secure-workspace/mcp-consumers.json \
  --checkout-root /secure-workspace/fleet-checkouts
```

Reporting mode may temporarily allow pending entries while a migration batch is being planned:

```bash
python3 tools/audit_mcp_fleet.py \
  --inventory /secure-workspace/mcp-consumers.json \
  --checkout-root /secure-workspace/fleet-checkouts \
  --allow-pending
```

Do not pass a token on the command line or place one in the inventory. Repository discovery and checkout should use a least-privilege GitHub App installation token with read-only contents/metadata access, short expiry, installation scoping, and no access to unrelated organizations. The token must remain outside logs, artifacts, job summaries, and repository files.

## One pull request per consumer

An adopted consumer PR should:

1. inventory existing MCP crates and copied protocol code;
2. select `cargo-registry`, `zed-vendor`, or exact-revision `git-mirror` transport;
3. replace floating Git refs, copied sources, or escaping path dependencies;
4. add Zed native lock output and `.zed-pkg/mcp-rust-libs.json` companion evidence;
5. pin the reusable audit action to a reviewed commit;
6. run the consumer's protocol, transport, auth, cancellation, timeout, and integration tests;
7. update the fleet inventory from `pending` to `adopted` only after the exact consumer head passes.

A fleet report is not permission to merge consumer pull requests. Existing repository review, branch protection, and merge policies still apply.
