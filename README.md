# cwst

**Web store: the encrypted storage drawer of the member vault.**

`cwst` stores the vault's state on the member's device, encrypted, in named namespaces
(one per vault drawer). It is built from Veilid's building blocks, not from `veilid-core`
(one Veilid stack only: the single `veilid-core` instance belongs to `cvln`):

- storage: [`keyvaluedb-web`](https://crates.io/crates/keyvaluedb-web) 0.2.4, the version
  Veilid pins (IndexedDB in the browser), and `keyvaluedb-memorydb` for tests;
- encryption: Veilid's table-store logic, copied as one MPL-2.0 file
  ([`src/veilid_crypt.rs`](src/veilid_crypt.rs)) with the VLD0 primitives
  (Argon2id, XChaCha20-Poly1305, BLAKE3).

## Model

| Tier | What | Protected by |
|---|---|---|
| Protected | device encryption key (DEK) | Argon2id(password); Veilid's blob format `VLD0 ‖ AEAD(DEK) ‖ nonce` |
| Keys | index key, one key per namespace | the DEK (AEAD) |
| Data | entries: encrypted key → encrypted value | the namespace key (AEAD; key with keyed nonce, value bound to its key) |

The **password is supplied by the caller**. In the vault, `ckmg` derives it from the
passkey PRF output (HKDF); `cwst` knows nothing about passkeys.

Operations: create / unlock, namespaces (open-or-create, list), get / put / delete /
keys / entries / clear, atomic batches, **rotation** (new password: re-protect the DEK;
new DEK: re-wrap namespace keys; new namespace key: re-encrypt that namespace), and
**crypto-shredding** (a namespace, or the whole store).

## Deviations from Veilid (all in the MPL file's header)

- The data tier is **authenticated** (XChaCha20-Poly1305 with associated data) instead of
  Veilid's unauthenticated XChaCha20: a modified or swapped entry fails to decrypt.
- Three key levels instead of two (per-namespace keys), for cheap per-drawer rotation and
  shredding.
- The password is bytes and must not be empty (the DEK is always protected).
- No compression.

## Boundaries

What it does: encrypted storage on the device, rotation, shredding.

What it never does:

- no network code;
- no policy, no callers: `cvlt` decides who may open which namespace;
- no key hierarchy or passkeys (`ckmg`), no records or sync (`cdht`);
- no export, backup or recovery path (no recovery, invariant 6).

Known limits: storage reveals entry counts and sizes per namespace (pad above this layer
if that matters); `create` is not atomic across concurrent vault instances (the vault
runtime is a single iframe); authenticated encryption does not prevent a rollback to an
older copy of the whole database.

## Status and TODO

- Implemented and tested natively (in-memory database).
- TODO: browser test run (headless Chromium, `wasm-bindgen-test`) against real IndexedDB;
  CI currently only type-checks the wasm32 build.
- TODO: the queued vault prototype (architecture §6, item 27) measures this against a plain
  WebCrypto + IndexedDB baseline.

## License

Copyright 2026 Julian Y. Richard Corbet. Licensed under
[LGPL-3.0-only](LICENSES/LGPL-3.0-only.txt)
[WITH LGPL-3.0-linking-exception](LICENSES/LGPL-3.0-linking-exception.txt), except
`src/veilid_crypt.rs` ([MPL-2.0](LICENSES/MPL-2.0.txt), derived from Veilid). See
[LICENSE.md](LICENSE.md).
