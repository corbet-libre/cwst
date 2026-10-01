# cwst — Storage

## Scope

Encrypted device persistence with atomic, versioned checkpoints spanning opaque
owner records and pending outputs. Keys supplies an opaque `StoreCipher`; Storage
never receives a passkey, PRF, root, policy or domain authority. A successful commit
makes all records and outputs durable together. Failed or cancelled writes require
reopening and reconciling the recorded operation identifier.

`Store` wraps a random data key through `ckmg` and encrypts the whole checkpoint
with XChaCha20-Poly1305. The native adapter uses `atomicwrites` and `fs2`; Memory
uses `keyvaluedb-memorydb`. IndexedDB reads use `keyvaluedb-web` without caching.
A narrow transaction adapter extends its `col0` layout with strict atomic CAS,
because the upstream trait's separate get/write calls cannot fence browser tabs.
This preserves the commit-before-publication mechanism from the original member
IndexedDB adapter while moving every owner and output into encrypted storage.

See [the contract](docs/CONTRACT.md) and [coverage requirements](docs/COVERAGE.md).
Implementation is under CI validation and independent review, not accepted yet.
