# Storage contract

`Store<B>` provides `create`, `open`, `read`, `commit`, `load_pending`, `ack_output`,
`version`, `operation`, and consuming `lock`. Inputs are a backend, opaque Keys
wrapping capability and scope. No public raw wrapping key or password exists.

All owner records and output bytes are encrypted under a random data key. Its
wrapped form and the exact scope are authenticated as associated data. The wire is
`cwst.checkpoint.v2\0 || wrapped_key[72] || nonce[24] || ciphertext+tag`. The wrapped
key is Keys' independently derived storage wrapping domain; it cannot open Keys'
custody records. Names, record keys, revisions, operation identifiers and output
identifiers live inside the authenticated ciphertext.

A commit requires the loaded version and nonzero operation identifier. It replaces
records for any number of domain owners and appends bounded outputs together. A CAS
compares the exact encrypted predecessor. On success the new version is visible;
conflict/error/cancellation after attempting persistence locks the handle. Reopen
and inspect `operation` and `load_pending`; do not regenerate domain effects after
an unknown result. Publication is idempotent by output ID and acknowledgement is
itself a fenced commit. Storage assigns no meaning to an ACK beyond removal from
its outbox; recipient acceptance remains the domain owner's responsibility.

Native files use a persistent sibling lock inode, established OS advisory locks,
`atomicwrites` atomic replacement and fsync. All cooperating writers must use the
adapter and the enclosing directory must be private. IndexedDB uses a strict
readwrite transaction spanning comparison and replacement; unsupported durability
refuses writes. The real Memory adapter is ephemeral and is not a disk guarantee.
No delete/reset interface can turn a known checkpoint back into revision zero.

Limits: ciphertext 8 MiB; value/output 1 MiB; owner/key 256 bytes; 1024 records;
64 pending outputs; aggregate plaintext 2 MiB before JSON encoding. These are
resource ceilings, not profile or membership rules. Inputs and decrypted temporary
buffers are wiped on drop where owned by this library. Callers must wipe their
copies. Error/Debug values carry no identifiers, paths, contents or upstream errors.

Absence differs from unreadability, corruption and wrong wrapping capability.
Explicit `create` is a local storage operation, never a new membership or a restore
verdict. Trusted storage cannot detect an adversary replacing an entire device
filesystem with an old valid snapshot after all external revision anchors are lost.
Current authorization, revocation, remote floors, record verification and the
unavailable-versus-known-absent restore decision belong to their existing owners.
No operator backup or recovery surface exists here.

The former password-based development layout is intentionally replaced without a
migration path. `veilid_crypt.rs` retains its MPL-2.0 header and modification record.

## Compound commit receipts

`commit_with_receipt` performs the existing atomic commit and returns a constructor-private
`CommitReceipt`. `receipt(operation)` reconstitutes one only from the authenticated
current checkpoint after reopen. Locked, uncertain, or mismatched operations refuse.
The receipt has no Clone/serde and binds the encrypted store identity, scope, version,
operation, and final stored record/outbox bytes via BLAKE3. `is_commit(&store, &operation)`
refuses another store with the same scope or a newer in-memory checkpoint. It does not
claim that an independently changed backend is unchanged: the next write still needs
Storage's actual CAS. `contains_record`/`contains_output` compare exact owner candidate
digests, so transient mutations overwritten/deleted later in a batch cannot authorize
adoption. Wallet must require its exact operation, expected next version, and all
candidate/output digests, then consume the receipt when adopting. Storage proves
persistence only; issuer/domain acceptance remains the owner's obligation.

Records retention borrows only `Store::sealed_checkpoint`, the exact authenticated
ciphertext already durably held by the original Store. It exposes neither owner
plaintext nor a root/wrapping key and is not a user backup/export format.
`Store::restore` validates that same original framing, scope, wrapping AEAD,
checkpoint schema and expected version before its first write. It uses only
`Backend::compare_exchange(None, wire)`: an existing local checkpoint, even an
identical one, is never overwritten. A conflict is AlreadyInitialized. Interrupted
or uncertain CAS may have persisted the exact bytes, so the caller reopens the
original destination to reconcile. Storage never attests network freshness,
current passkey/lineage, available replicas or application readiness.
