# cwst — Storage

## Scope

**Purpose and home.** Encrypted device persistence under `cmsg → cvlt → cwst`,
using IndexedDB in browsers and files natively. Atomic versioned checkpoints span
opaque owner records and pending outputs.

**Owns.** A random data key wrapped by Keys' opaque `StoreCipher`, authenticated
checkpoint encryption, compare-and-swap commits, writer fencing, pending outputs
and acknowledgements. The IndexedDB adapter uses `keyvaluedb-web`; the data-tier
cryptography retains its Veilid-derived MPL file.

**Never.** Receives PRF, passkey material, roots or raw wrapping keys; writes
plaintext journals or backups; publishes before commit; invents owner merge rules;
resets a known checkpoint to revision zero; implements operator recovery.

**States and ports.** Closed/Locked → Open(version); commit → Committed, conflict →
Reload, uncertain outcome → Reconcile, corrupt or unauthenticated input → Refused.
`Store<B>` supplies `create`, `open`, `read`, `commit`, `load_pending`, `ack_output`,
`version`, `operation` and `lock`. Backends are native files, IndexedDB and Memory.

**Invariants and tests.** Member secrets stay on member devices and established
cryptographic crates implement primitives. Real file and IndexedDB reopen/decrypt,
wrong key/scope/tampering, process crashes and competing writers must leave the old
or complete new checkpoint. Pending outputs survive without repeated effects.
Native and actual browser tests cover bounds, cancellation, corruption and errors;
reachable source lines and branches must be fully covered.

## Implementation

`Store` wraps a random data key through `ckmg` and encrypts the whole checkpoint
with XChaCha20-Poly1305. The native adapter uses `atomicwrites` and `fs2`; Memory
uses `keyvaluedb-memorydb`. IndexedDB reads use `keyvaluedb-web` without caching.
A narrow transaction adapter extends its `col0` layout with strict atomic CAS,
because the upstream trait's separate get/write calls cannot fence browser tabs.
Every owner and output commits together. Failed or cancelled writes require
reopening and reconciling the recorded operation identifier.

See [the contract](docs/CONTRACT.md) and [coverage requirements](docs/COVERAGE.md).
Independent acceptance review remains required.
