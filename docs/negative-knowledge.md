# Rejected approaches and reversed findings

This file records work that was tried and abandoned, and findings that were later
reversed. It exists because both kinds of knowledge are invisible in a green main
branch: an approach that failed leaves no trace once its branch is closed, and a
corrected finding looks identical to a finding that was never made. Without a record,
the next person re-derives the failure or, worse, restores the original mistake from a
stale branch that still contains it.

Each entry states what was attempted, how it failed, and what to do instead.

## N-1. Never generate or patch Rust source from a self-committing CI job

Attempted on `agent/den-3100-ore-mcp-telemetry` in
`.github/workflows/reconcile-den-3100.yml` (added in `3f5371699445`, extended in
`88cafbeb76ed`). The workflow ran with `permissions: contents: write` and
`persist-credentials: true`, triggered on pushes filtered to its own path, guarded by
`if: github.actor != 'github-actions[bot]'`. It executed an inline `python3` heredoc
that rewrote `crates/ore-mcp-telemetry/src/lib.rs` with a regular-expression
substitution, then ran `cargo fmt --all`, then committed and pushed the result back to
the branch it had just checked out.

It failed in three independent ways.

1. **The change never reached the branch.** `88cafbeb76ed` is titled
   "fix(DEN-3100): harden exporter construction outside Tokio" and has a one-file
   diffstat: the workflow. The Rust guard it describes existed only inside the CI
   script. No subsequent source commit was pushed, so the branch tip ships
   `build_tracer_provider` with no runtime check at all. A commit message asserted a
   fix that is not in the tree, and the git log is the only place a reviewer would
   look. Source changes belong in the commit that claims them.
2. **The substitution was a silent bomb.** The patch anchored on a regular expression
   spanning `fn build_tracer_provider` through `fn shutdown_providers`, and hard-coded
   both the single-file crate layout and the OpenTelemetry 0.27 call shape
   (`with_batch_exporter(exporter, runtime::Tokio)`,
   `PeriodicReader::builder(exporter, runtime::Tokio)`). The crate has since moved to
   0.32, which removed the explicit runtime argument, and has been split into five
   modules. The patch would now either fail to match or produce code that does not
   compile — and it would do so in CI, on a push, with no local reproduction.
3. **The formatting gate could not fail.** The job ran `cargo fmt --all`, which
   rewrites the tree in place, and then `cargo fmt --all -- --check`. The second
   command is evaluated against output the first command just normalised, so it is
   structurally incapable of reporting a violation. The job advertised a check it was
   not performing. Run `--check` alone; never pair it with a write-mode invocation.

There is a fourth, narrower trap in the same file worth stating separately, because it
is easy to reproduce anywhere: the workflow asserted two forbidden strings with
`! grep -R -F 'std::env::var' crates/ore-mcp-telemetry` under `set -euo pipefail`. Both
POSIX and bash specify that `set -e` is ignored for a pipeline beginning with `!`, so
this construct returns success whether or not the string is found. Those two assertions
never ran. Write the explicit form instead:

```sh
if grep -Rq --include='*.rs' -F 'std::env::var' "$crate"; then
  echo "violation"; exit 1
fi
```

**Instead:** write the change in the source file, commit it from a workstation, and let
CI *verify* with read-only assertions — `grep`, `cargo fmt --check`, `--locked`. The
read-only residue of this workflow was worth keeping and now lives as the
"Telemetry stderr-only and no-ambient-input invariants" step in
[`.github/workflows/ci.yml`](../.github/workflows/ci.yml); the generation and
self-commit machinery was not.

## N-2. `usa-acc` is not a migration-wave-1 candidate

`usa-acc/usa-acc-mcp-server.rs` was selected for the first ten-server modularization
wave on the strength of its having a `src/telemetry.rs`, and was removed after that
file was read: it is a Supabase product telemetry client, not process OpenTelemetry
bootstrap, so it shares none of the surface this repository factors out.
`3FA-app/3FA-mcp-server.rs` was substituted, because it carries the repeated stdio-safe
OTEL template and its open pull request changes only routing metadata. The corrected
roster is in [`fleet/modularization-wave-1.md`](../fleet/modularization-wave-1.md).

The generalised rule, already stated in that file, is that **source inspection is
authoritative over file names.** A path called `telemetry.rs` is a reason to read a
repository, not a reason to migrate it.

This entry exists because the finding is actively at risk. The branch
`agent/den-957-bootstrap-config-telemetry-rebased` predates the investigation: its copy
of `fleet/modularization-wave-1.md` deletes the paragraph recording the removal and
restores `usa-acc` as wave slot 7. That branch is 39 commits behind and is not being
merged, but it is a live ref, and the change presents as an innocuous documentation
edit. Reviving a stale branch can subtract knowledge as easily as it adds code; a
documentation hunk that *removes* an explanation deserves the same scrutiny as a
deleted test.

## Related

`agent/den-3100-ore-mcp-telemetry` is superseded in full by
`agent/den-957-mcp-runtime-remainder`, which re-derives the same crate against
OpenTelemetry 0.32 behind an `otlp` feature flag, keeps every one of the original unit
tests, and adds the Tokio-runtime regression test that N-1 describes as missing.
