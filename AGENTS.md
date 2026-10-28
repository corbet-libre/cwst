# cwst agent notes

Work in a lane (`~/agents/scratch/lane-new <lane>`); never edit `~/agents/scratch/ws`.
Run commands from the lane root (`<lane>/ws`); `<lane>` below is your lane name.

Build and test (quote the verdict line, never infer from a pipe):
- `cargo fmt -p cwst -- --check` — clean at HEAD, exit 0.
- `~/agents/scratch/cbuild <lane> test -p cwst --locked` — green, exit 0
  (all suites `ok`: 5 + 24 passed; native file vectors plus `Memory`;
  browser IndexedDB vectors run in CI only).
- `clippy --locked --all-targets -- -D warnings` is red at HEAD from upstream
  `ckmg` lints (unused import, dead field/method), not this crate.
  Full gate (locked deps, coverage, wasm exec) runs in CI only: `.ci/verify.sh`.

Land: `cargo fmt` in touched repos, rebase on main (never force-push),
`CMTY_PRIORITY=background ~/agents/scratch/cbuild <lane> xtask land --dry`,
then `xtask land`.

Invariants (rule -> enforcing test):
- Ciphertext-only persistence: no names, keys, values, paths, contents or
  upstream errors in Debug/error values; wrong key/scope fails closed
  -> `tests/store.rs::memory_round_trip`, `corruption_and_limits`
  (`docs/CONTRACT.md:7-12,34`).
- One atomic CAS per commit; competing writers fence, winner only
  -> `fence_competing_writers`, `native_process_kill_preserves_whole_checkpoint`.
- Uncertain/cancelled writes lock the handle: reopen and reconcile via the
  recorded `operation`; never regenerate domain effects
  -> `crash_and_cancel_reconcile_exact_outputs`,
  `live_owner_reads_revoke_during_uncertain_or_cancelled_writes`.
- Pending outputs are idempotent by ID; `ack_output` is itself a fenced commit
  -> `memory_round_trip`, `compound_limits_and_replacements`,
  `aggregate_checkpoint_bound_across_commits`.
- Bounds enforced: 8 MiB checkpoint, 1 MiB value/output, 256 B owner/key,
  1024 records, 64 outputs, 2 MiB aggregate plaintext
  -> `corruption_and_limits`, `compound_limits_and_replacements`.
- No reset to revision zero: `restore` uses `compare_exchange(None, wire)` only,
  existing checkpoints conflict with `AlreadyInitialized`
  -> `retained_compound_wire_restores_exact_owners_outputs_and_fences`,
  `restore_checked_enforces_keys_digest_before_destination_cas`.
- Rewrap keeps the data key and swaps the wrapper atomically in one CAS;
  cross-substituted wrappers are refused
  -> `tests/unit/internal.rs::rewrap_retains_data_key_and_rejects_authentic_wrapper_substitution`,
  `rewrap_commits_owner_changes_and_outbox_under_one_version`.
- Entropy failure refuses creation/encryption; no own crypto — XChaCha20-Poly1305
  via the MPL-2.0 `src/veilid_crypt.rs` (header kept), keyed by Keys' opaque
  `StoreCipher`; no `veilid-core` dependency
  -> `tests/unit/internal.rs::entropy_failures_refuse_creation_and_data_encryption`.

Pointers: `src/store.rs`, `src/veilid_crypt.rs`, `src/backend.rs`,
`src/native.rs`, `src/browser.rs`, `tests/store.rs`, `tests/unit/`,
`docs/CONTRACT.md`, `docs/COVERAGE.md`, `.ci/verify.sh`.
Commits: explicit paths, imperative, author per `~/agents/AGENT.md`; no AI trailers.
`publish=false`; LGPL-3.0-only WITH linking exception + MPL-2.0
(`src/veilid_crypt.rs`); no GPL-only/AGPL additions, no registry publication.
