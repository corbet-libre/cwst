# cwst — Storage

## Scope

### Purpose

Encrypted device persistence with atomic, versioned checkpoints spanning opaque owner records and pending outputs, using browser storage on the web and files natively.

### Owns

Checkpoint encryption under a random data key wrapped by an opaque store capability from `ckmg`; atomic compare-and-swap commit of several owners' records plus pending outputs in one transaction, with support for listing pending outputs and acknowledging them; native file, browser, and in-memory backends.

### Never

Receives passkey or PRF secrets or raw wrapping keys; writes plaintext or unencrypted journals or backups; publishes outputs before commit; invents merge rules for owner records; resets a known checkpoint to revision zero; provides operator backup.

### States

Closed and Locked before opening with a version; Prepared commits atomically; conflicts reload; uncertain outcomes reconcile; corrupt or unauthenticated data is refused.

### Test obligations

Real file and browser storage reopen and decrypt; wrong key, wrong scope, and tampering fail; a crash at every commit and publication boundary leaves the old or the complete new checkpoint; competing tabs or processes cannot mix revisions from different owners; pending outputs retry without repeating effects; resource bounds are refused; native and browser builds share identical test vectors with full line and branch coverage over real round trips and injected faults.

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
