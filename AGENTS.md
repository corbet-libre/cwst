# Agent instructions

Write code comments and documentation in English. Follow README Scope and
`docs/CONTRACT.md`. Storage owns only encrypted persistence, atomic owner checkpoints,
writer fencing and pending outputs. No WebAuthn, PRF, raw root, network, domain policy,
export or operator recovery. Keys supplies an opaque StoreCipher.

Use keyvaluedb/keyvaluedb-web and maintained native atomic-write/locking crates.
No own cryptographic primitives or veilid-core dependency. Preserve the MPL-2.0
header in src/veilid_crypt.rs and record every modification; other code is
LGPL-3.0-only WITH LGPL-3.0-linking-exception. No GPL-only/AGPL additions.

No local Cargo, including fmt/metadata. Public CI runs format, native and
wasm Clippy, real native/browser tests, and 100% reachable line/branch coverage.
First-party dependencies use branch main with one revision each in Cargo.lock.
No registry publication. Explicit-path staging, plain-English commits, no AI credit.
