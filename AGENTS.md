# Agent instructions

Write all code comments and documentation in English.

## Product boundary

- Encrypted key-value storage for the member vault (`cvlt`), one namespace per drawer.
- Built on `keyvaluedb` / `keyvaluedb-web` 0.2.4 (Veilid's pin) and Veilid's table-store
  encryption. Never depend on `veilid-core` (one Veilid stack only; it belongs to `cvln`).
- No network code, no policy, no knowledge of callers, passkeys or records.
- No export, backup or recovery path (no-recovery principle).
- Don't build security primitives: use the established crates (argon2, chacha20poly1305,
  blake3); our code is composition.
- `src/veilid_crypt.rs` is MPL-2.0 (derived from Veilid). Keep its header, keep it
  MPL-2.0, and record every modification there. Everything else is
  LGPL-3.0-only WITH LGPL-3.0-linking-exception. Do not add code available only under the
  full GPL or AGPL.
- Errors stay coarse: never include keys, values, names or passwords.

## Layout

- `src/veilid_crypt.rs`: protected tier (DEK under Argon2id) and data-tier AEAD.
- `src/store.rs`: `WebStore` (create, unlock, rotation, shredding) and `Namespace`.
- `tests/store.rs`: behaviour over the in-memory database.

## Quality boundary

- `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, `cargo test`, and
  `cargo clippy --lib --target wasm32-unknown-unknown -- -D warnings` — all green in CI
  (GitHub Actions). No local workstation builds.
