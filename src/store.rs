//! One atomic publication chain; every owner remains opaque.
use crate::{
    Error, MAX_KEY_BYTES, MAX_OUTPUTS, MAX_RECORDS, MAX_VALUE_BYTES,
    backend::{Backend, check_size},
    veilid_crypt::{self, Secret},
};
use ckmg::passkey::StoreCipher;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex, Weak};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const HEADER: &[u8] = b"cwst.checkpoint.v2\0";
const WRAPPED_BYTES: usize = 72;

/// One owner mutation, applied with all other changes and outputs in the same commit.
pub enum Change<'a> {
    /// Replace an opaque record.
    Put {
        /// Domain owner, scoped by the enclosing vault.
        owner: &'a str,
        /// Owner-local record key.
        key: &'a [u8],
        /// Opaque record bytes.
        value: &'a [u8],
    },
    /// Remove a record; this does not remove the checkpoint's fencing state.
    Delete {
        /// Domain owner.
        owner: &'a str,
        /// Owner-local key.
        key: &'a [u8],
    },
}
/// Durable output, replayed unchanged until explicitly acknowledged.
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct Output {
    /// Opaque caller-assigned idempotency identifier.
    pub id: [u8; 32],
    /// Opaque payload; storage does not decide how it is published.
    pub bytes: Vec<u8>,
}
impl std::fmt::Debug for Output {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Output([redacted])")
    }
}
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
struct Record {
    owner: String,
    key: Vec<u8>,
    value: Vec<u8>,
}
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
struct Checkpoint {
    version: u64,
    operation: [u8; 32],
    records: Vec<Record>,
    pending: Vec<Output>,
}
struct Open {
    key: Secret,
    wrapped: Vec<u8>,
    wire: Vec<u8>,
    checkpoint: Arc<Checkpoint>,
}

type Readable = Mutex<Option<Arc<Checkpoint>>>;

/// Owner-scoped access to the original Store's current authenticated checkpoint.
/// This weak handle holds no wrapping key and cannot retain a snapshot. Lock,
/// pending or uncertain writes, cancellation and Store destruction revoke reads.
/// It never acquires a caller's outer async Store mutex.
pub struct ReadHandle {
    owner: String,
    context: Vec<u8>,
    readable: Weak<Readable>,
}
impl ReadHandle {
    /// Check the scope authenticated by the original Store.
    pub fn is_scope(&self, scope: &str) -> bool {
        self.context.strip_prefix(HEADER) == Some(scope.as_bytes())
    }
    /// Copy one committed opaque owner value, bounding its size before allocation.
    /// This is a read, never a lease or authorization to commit a candidate.
    pub fn read(&self, key: &[u8], maximum: usize) -> Result<Option<Vec<u8>>, Error> {
        identifier(&self.owner, key)?;
        let readable = self.readable.upgrade().ok_or(Error::Locked)?;
        let current = readable.lock().map_err(|_| Error::Locked)?;
        let checkpoint = current.as_ref().ok_or(Error::Locked)?;
        let value = checkpoint
            .records
            .iter()
            .find(|r| r.owner == self.owner && r.key == key)
            .map(|r| &r.value);
        if value.is_some_and(|v| v.len() > maximum) {
            return Err(Error::TooLarge);
        }
        Ok(value.cloned())
    }
}
impl std::fmt::Debug for ReadHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ReadHandle([redacted])")
    }
}

/// Proof of one actual authenticated durable checkpoint. Only Storage constructs
/// this receipt after CAS or reopening authenticated bytes; no serde/Clone exists.
/// Domain owners still verify their candidate and issuer acceptance independently.
pub struct CommitReceipt {
    scope: Vec<u8>,
    store_binding: [u8; 32],
    version: u64,
    operation: [u8; 32],
    records: Vec<(String, Vec<u8>, [u8; 32])>,
    outputs: Vec<([u8; 32], [u8; 32])>,
}
impl CommitReceipt {
    /// Actual committed checkpoint version.
    pub fn version(&self) -> u64 {
        self.version
    }
    /// Verify scope and exact operation before adopting any owner candidate.
    pub fn is_commit<B: Backend>(&self, store: &Store<B>, operation: &[u8; 32]) -> bool {
        let Ok(current) = store.current() else {
            return false;
        };
        self.scope == store.context
            && &self.operation == operation
            && self.operation == current.checkpoint.operation
            && self.version == current.checkpoint.version
            && self.store_binding == *blake3::keyed_hash(&current.key, &store.context).as_bytes()
    }
    /// Does the committed snapshot contain these exact owner bytes (BLAKE3 digest)?
    /// Repeated mutations are resolved by the actual committed final state.
    pub fn contains_record(&self, owner: &str, key: &[u8], digest: &[u8; 32]) -> bool {
        self.records
            .iter()
            .any(|(candidate_owner, candidate_key, candidate_digest)| {
                candidate_owner == owner && candidate_key == key && candidate_digest == digest
            })
    }
    /// Does the committed outbox contain this exact operation payload digest?
    pub fn contains_output(&self, id: &[u8; 32], digest: &[u8; 32]) -> bool {
        self.outputs.iter().any(|(candidate_id, candidate_digest)| {
            candidate_id == id && candidate_digest == digest
        })
    }
}
impl std::fmt::Debug for CommitReceipt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CommitReceipt([redacted])")
    }
}

/// An unlocked, scope-bound checkpoint. Lock consumes it and drops zeroizing secrets.
/// After any attempted write, a conflict/error/cancellation leaves this handle locked.
pub struct Store<B: Backend> {
    backend: B,
    context: Vec<u8>,
    open: Option<Open>,
    readable: Arc<Readable>,
}
impl<B: Backend> std::fmt::Debug for Store<B> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Store([redacted])")
    }
}
impl<B: Backend> Drop for Store<B> {
    fn drop(&mut self) {
        self.lock_in_place();
    }
}
impl<B: Backend> Store<B> {
    /// Explicitly create an empty checkpoint. Does not overwrite existing storage.
    pub async fn create(backend: B, cipher: &StoreCipher, scope: &str) -> Result<Self, Error> {
        Self::create_with_entropy(backend, cipher, scope, &mut ckmg::SystemEntropy).await
    }
    async fn create_with_entropy(
        backend: B,
        cipher: &StoreCipher,
        scope: &str,
        entropy: &mut impl ckmg::Entropy,
    ) -> Result<Self, Error> {
        let context = context(scope)?;
        let key = veilid_crypt::random_secret(entropy)?;
        let wrapped = cipher
            .seal(entropy, &context, key.as_slice())
            .map_err(|_| Error::Crypto)?;
        let checkpoint = Checkpoint {
            version: 0,
            operation: [0; 32],
            records: vec![],
            pending: vec![],
        };
        let wire = encode(&checkpoint, &key, &wrapped, &context)?;
        match backend.compare_exchange(None, &wire).await {
            Err(Error::Conflict) => return Err(Error::AlreadyInitialized),
            result => result?,
        }
        let checkpoint = Arc::new(checkpoint);
        let readable = Arc::new(Mutex::new(Some(checkpoint.clone())));
        Ok(Self {
            backend,
            context,
            readable,
            open: Some(Open {
                key,
                wrapped,
                wire,
                checkpoint,
            }),
        })
    }
    /// Open an existing checkpoint. Wrong scope/key and corruption never create state.
    pub async fn open(backend: B, cipher: &StoreCipher, scope: &str) -> Result<Self, Error> {
        context(scope)?;
        let wire = backend.read().await?.ok_or(Error::NotInitialized)?;
        Self::from_wire(backend, cipher, scope, wire)
    }
    /// Borrow the exact authenticated encrypted checkpoint for private Records
    /// retention. This is not a domain export: no decrypted owner bytes or keys
    /// are exposed, and the borrow ends when this Store is mutated or locked.
    pub fn sealed_checkpoint(&self) -> Result<&[u8], Error> {
        Ok(&self.current()?.wire)
    }
    /// Restore exact retained ciphertext into an empty local destination only.
    /// Original scope, wrapping and checkpoint authentication complete before any
    /// write. Existing local state is never replaced. Cancellation/uncertainty
    /// may have persisted the bytes; reopen the destination to reconcile it.
    /// This verifies Storage, not network freshness, membership or lineage.
    pub async fn restore(
        backend: B,
        cipher: &StoreCipher,
        scope: &str,
        expected_version: u64,
        wire: &[u8],
    ) -> Result<Self, Error> {
        Self::restore_checked(backend, cipher, scope, expected_version, wire, |_| Ok(())).await
    }

    /// Restore with one synchronous enclosing-owner consistency check before
    /// the empty-destination CAS. The callback borrows this exact authenticated
    /// Store; it cannot publish a candidate or retain a second plaintext owner.
    pub async fn restore_checked(
        backend: B,
        cipher: &StoreCipher,
        scope: &str,
        expected_version: u64,
        wire: &[u8],
        check: impl FnOnce(&Self) -> Result<(), Error>,
    ) -> Result<Self, Error> {
        check_size(wire)?;
        let store = Self::from_wire(backend, cipher, scope, wire.to_vec())?;
        store.expect(expected_version)?;
        check(&store)?;
        match store.backend.compare_exchange(None, wire).await {
            Err(Error::Conflict) => Err(Error::AlreadyInitialized),
            Err(error) => Err(error),
            Ok(()) => Ok(store),
        }
    }
    fn from_wire(
        backend: B,
        cipher: &StoreCipher,
        scope: &str,
        wire: Vec<u8>,
    ) -> Result<Self, Error> {
        let context = context(scope)?;
        check_size(&wire)?;
        if !wire.starts_with(HEADER) || wire.len() < HEADER.len() + WRAPPED_BYTES + 40 {
            return Err(Error::Corrupt);
        }
        let wrapped = wire[HEADER.len()..HEADER.len() + WRAPPED_BYTES].to_vec();
        let secret = cipher.open(&context, &wrapped).map_err(|_| Error::Unlock)?;
        let key: [u8; 32] = secret.as_slice().try_into().map_err(|_| Error::Corrupt)?;
        let key = Zeroizing::new(key);
        let plaintext = veilid_crypt::decrypt(
            &wire[HEADER.len() + WRAPPED_BYTES..],
            &key,
            &aad(&context, &wrapped),
        )?;
        let checkpoint: Checkpoint =
            serde_json::from_slice(&plaintext).map_err(|_| Error::Corrupt)?;
        validate(&checkpoint)?;
        let checkpoint = Arc::new(checkpoint);
        let readable = Arc::new(Mutex::new(Some(checkpoint.clone())));
        Ok(Self {
            backend,
            context,
            readable,
            open: Some(Open {
                key,
                wrapped,
                wire,
                checkpoint,
            }),
        })
    }
    /// Check the scope selected when this checkpoint was authenticated. A new,
    /// empty checkpoint has the same binding; owner loaders must check it too.
    pub fn is_scope(&self, scope: &str) -> bool {
        self.context.strip_prefix(HEADER) == Some(scope.as_bytes())
    }
    /// Lend reads of exactly one owner's committed records. The handle is valid
    /// only while this exact Store remains unlocked; reopening requires a new one.
    pub fn read_handle(&self, owner: &str) -> Result<ReadHandle, Error> {
        identifier(owner, b"owner")?;
        Ok(ReadHandle {
            owner: owner.into(),
            context: self.context.clone(),
            readable: Arc::downgrade(&self.readable),
        })
    }
    /// Current committed version; compare this at every publication boundary.
    pub fn version(&self) -> Result<u64, Error> {
        Ok(self.current()?.checkpoint.version)
    }
    /// Last committed operation, for unknown-outcome reconciliation; zero means initial creation.
    pub fn operation(&self) -> Result<[u8; 32], Error> {
        Ok(self.current()?.checkpoint.operation)
    }
    /// Read a domain-owned record from this committed snapshot.
    pub fn read(&self, owner: &str, key: &[u8]) -> Result<Option<&[u8]>, Error> {
        identifier(owner, key)?;
        Ok(self
            .current()?
            .checkpoint
            .records
            .iter()
            .find(|r| r.owner == owner && r.key == key)
            .map(|r| r.value.as_slice()))
    }
    /// Outputs are available only from a committed snapshot; retransmit the same bytes.
    pub fn load_pending(&self) -> Result<&[Output], Error> {
        Ok(&self.current()?.checkpoint.pending)
    }
    /// Recover a receipt only from the currently authenticated committed operation.
    /// After an unknown write the handle is locked; reopen actual backend bytes first.
    pub fn receipt(&self, operation: &[u8; 32]) -> Result<CommitReceipt, Error> {
        let checkpoint = &self.current()?.checkpoint;
        if operation == &[0; 32] || &checkpoint.operation != operation {
            return Err(Error::Invalid);
        }
        Ok(CommitReceipt {
            scope: self.context.clone(),
            version: checkpoint.version,
            operation: checkpoint.operation,
            store_binding: *blake3::keyed_hash(&self.current()?.key, &self.context).as_bytes(),
            records: checkpoint
                .records
                .iter()
                .map(|record| {
                    (
                        record.owner.clone(),
                        record.key.clone(),
                        *blake3::hash(&record.value).as_bytes(),
                    )
                })
                .collect(),
            outputs: checkpoint
                .pending
                .iter()
                .map(|output| (output.id, *blake3::hash(&output.bytes).as_bytes()))
                .collect(),
        })
    }
    /// Commit the entire compound mutation and return its unforgeable receipt.
    /// Conflict, cancellation and uncertain writes never yield a receipt.
    pub async fn commit_with_receipt(
        &mut self,
        expected: u64,
        operation: [u8; 32],
        changes: &[Change<'_>],
        outputs: &[Output],
    ) -> Result<CommitReceipt, Error> {
        self.commit(expected, operation, changes, outputs).await?;
        self.receipt(&operation)
    }
    /// Commit several domain owners and their pending outputs under one version fence.
    pub async fn commit(
        &mut self,
        expected: u64,
        operation: [u8; 32],
        changes: &[Change<'_>],
        outputs: &[Output],
    ) -> Result<u64, Error> {
        self.commit_wrapping(expected, operation, changes, outputs, None)
            .await
    }
    /// Commit owner changes and rewrap the same random data key in one CAS.
    /// The new wrapper is authenticated with the entire replacement checkpoint.
    /// This is also the explicit migration primitive; it never retries another
    /// cipher on open, resets a version, or publishes a partial root transition.
    pub async fn commit_rewrapped(
        &mut self,
        expected: u64,
        operation: [u8; 32],
        changes: &[Change<'_>],
        outputs: &[Output],
        cipher: &StoreCipher,
    ) -> Result<u64, Error> {
        self.commit_wrapping(expected, operation, changes, outputs, Some(cipher))
            .await
    }
    async fn commit_wrapping(
        &mut self,
        expected: u64,
        operation: [u8; 32],
        changes: &[Change<'_>],
        outputs: &[Output],
        cipher: Option<&StoreCipher>,
    ) -> Result<u64, Error> {
        self.expect(expected)?;
        if changes.len() > MAX_RECORDS || outputs.len() > MAX_OUTPUTS || operation == [0; 32] {
            return Err(Error::Invalid);
        }
        // Bound caller-owned input before cloning values into a candidate.
        let input_bytes = changes.iter().try_fold(0usize, |total, change| {
            let amount = match change {
                Change::Put { owner, key, value } => owner
                    .len()
                    .checked_add(key.len())
                    .and_then(|n| n.checked_add(value.len())),
                Change::Delete { owner, key } => owner.len().checked_add(key.len()),
            }
            .ok_or(Error::TooLarge)?;
            total.checked_add(amount).ok_or(Error::TooLarge)
        })?;
        let input_bytes = outputs.iter().try_fold(input_bytes, |total, output| {
            total.checked_add(output.bytes.len()).ok_or(Error::TooLarge)
        })?;
        if input_bytes > crate::MAX_CHECKPOINT_BYTES / 4 {
            return Err(Error::TooLarge);
        }
        let mut candidate = self.current()?.checkpoint.as_ref().clone();
        for change in changes {
            let (owner, key) = match change {
                Change::Put { owner, key, .. } | Change::Delete { owner, key } => (*owner, *key),
            };
            identifier(owner, key)?;
            if let Change::Put { value, .. } = change
                && value.len() > MAX_VALUE_BYTES
            {
                return Err(Error::TooLarge);
            }
            candidate
                .records
                .retain(|r| r.owner != owner || r.key != key);
            if let Change::Put { value, .. } = change {
                candidate.records.push(Record {
                    owner: owner.into(),
                    key: key.to_vec(),
                    value: value.to_vec(),
                });
            }
        }
        candidate.pending.extend_from_slice(outputs);
        self.save_wrapping(candidate, operation, cipher).await
    }
    /// Acknowledge one exact output after its idempotent publication.
    pub async fn ack_output(
        &mut self,
        expected: u64,
        operation: [u8; 32],
        id: [u8; 32],
    ) -> Result<u64, Error> {
        self.expect(expected)?;
        let mut candidate = self.current()?.checkpoint.as_ref().clone();
        if !candidate.pending.iter().any(|o| o.id == id) || operation == [0; 32] {
            return Err(Error::Invalid);
        }
        candidate.pending.retain(|o| o.id != id);
        self.save(candidate, operation).await
    }
    /// Wipe decrypted state. The backend remains independently reopenable.
    pub fn lock(mut self) {
        self.lock_in_place();
    }
    /// Wipe a shared checkpoint without consuming its synchronization container.
    pub fn lock_in_place(&mut self) {
        self.open = None;
        // A poisoned mutex still owns the shared checkpoint: wipe it regardless.
        *self
            .readable
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
    }
    fn current(&self) -> Result<&Open, Error> {
        self.open.as_ref().ok_or(Error::Locked)
    }
    fn expect(&self, expected: u64) -> Result<(), Error> {
        if self.version()? != expected {
            Err(Error::Conflict)
        } else {
            Ok(())
        }
    }
    async fn save(&mut self, candidate: Checkpoint, operation: [u8; 32]) -> Result<u64, Error> {
        self.save_wrapping(candidate, operation, None).await
    }
    async fn save_wrapping(
        &mut self,
        mut candidate: Checkpoint,
        operation: [u8; 32],
        cipher: Option<&StoreCipher>,
    ) -> Result<u64, Error> {
        candidate.version = candidate.version.checked_add(1).ok_or(Error::TooLarge)?;
        candidate.operation = operation;
        validate(&candidate)?;
        let current = self.current()?;
        let wrapped = match cipher {
            Some(cipher) => cipher
                .seal(
                    &mut ckmg::SystemEntropy,
                    &self.context,
                    current.key.as_slice(),
                )
                .map_err(|_| Error::Crypto)?,
            None => current.wrapped.clone(),
        };
        let wire = encode(&candidate, &current.key, &wrapped, &self.context)?;
        // Remove decrypted state before yielding: cancellation cannot reuse stale authority.
        let old = self.open.take().ok_or(Error::Locked)?;
        *self.readable.lock().map_err(|_| Error::Locked)? = None;
        self.backend
            .compare_exchange(Some(&old.wire), &wire)
            .await?;
        let version = candidate.version;
        let checkpoint = Arc::new(candidate);
        // Only the completed backend CAS publishes the one authenticated snapshot.
        *self.readable.lock().map_err(|_| Error::Locked)? = Some(checkpoint.clone());
        self.open = Some(Open {
            key: old.key,
            wrapped,
            wire,
            checkpoint,
        });
        Ok(version)
    }
}
fn context(scope: &str) -> Result<Vec<u8>, Error> {
    identifier(scope, b"scope")?;
    Ok([HEADER, scope.as_bytes()].concat())
}
fn identifier(owner: &str, key: &[u8]) -> Result<(), Error> {
    if owner.is_empty()
        || owner.len() > MAX_KEY_BYTES
        || key.is_empty()
        || key.len() > MAX_KEY_BYTES
    {
        Err(Error::Invalid)
    } else {
        Ok(())
    }
}
fn validate(c: &Checkpoint) -> Result<(), Error> {
    if c.records.len() > MAX_RECORDS || c.pending.len() > MAX_OUTPUTS {
        return Err(Error::TooLarge);
    }
    let aggregate: usize = c
        .records
        .iter()
        .map(|r| r.owner.len() + r.key.len() + r.value.len())
        .sum::<usize>()
        + c.pending.iter().map(|o| o.bytes.len()).sum::<usize>();
    if aggregate > crate::MAX_CHECKPOINT_BYTES / 4 {
        return Err(Error::TooLarge);
    }
    let mut records = std::collections::BTreeSet::new();
    for r in &c.records {
        identifier(&r.owner, &r.key)?;
        if r.value.len() > MAX_VALUE_BYTES {
            return Err(Error::TooLarge);
        }
        if !records.insert((&r.owner, &r.key)) {
            return Err(Error::Corrupt);
        }
    }
    let mut outputs = std::collections::BTreeSet::new();
    for o in &c.pending {
        if o.bytes.len() > MAX_VALUE_BYTES {
            return Err(Error::TooLarge);
        }
        if !outputs.insert(o.id) {
            return Err(Error::Invalid);
        }
    }
    Ok(())
}
fn aad(context: &[u8], wrapped: &[u8]) -> Vec<u8> {
    [context, wrapped].concat()
}
fn encode(
    checkpoint: &Checkpoint,
    key: &Secret,
    wrapped: &[u8],
    context: &[u8],
) -> Result<Vec<u8>, Error> {
    let plaintext = Zeroizing::new(serde_json::to_vec(checkpoint).map_err(|_| Error::Corrupt)?);
    let encrypted = veilid_crypt::encrypt(&plaintext, key, &aad(context, wrapped))?;
    let wire = [HEADER, wrapped, &encrypted].concat();
    check_size(&wire)?;
    Ok(wire)
}

#[cfg(test)]
#[path = "../tests/unit/internal.rs"]
mod internal;
