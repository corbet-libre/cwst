//! One atomic publication chain; every owner remains opaque.
use crate::{
    Error, MAX_KEY_BYTES, MAX_OUTPUTS, MAX_RECORDS, MAX_VALUE_BYTES,
    backend::{Backend, check_size},
    veilid_crypt::{self, Secret},
};
use ckmg::passkey::StoreCipher;
use serde::{Deserialize, Serialize};
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
    checkpoint: Checkpoint,
}

/// An unlocked, scope-bound checkpoint. Lock consumes it and drops zeroizing secrets.
/// After any attempted write, a conflict/error/cancellation leaves this handle locked.
pub struct Store<B: Backend> {
    backend: B,
    context: Vec<u8>,
    open: Option<Open>,
}
impl<B: Backend> std::fmt::Debug for Store<B> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Store([redacted])")
    }
}
impl<B: Backend> Store<B> {
    /// Explicitly create an empty checkpoint. Does not overwrite existing storage.
    pub async fn create(backend: B, cipher: &StoreCipher, scope: &str) -> Result<Self, Error> {
        let context = context(scope)?;
        let key = veilid_crypt::random_secret()?;
        let wrapped = cipher
            .seal(&mut ckmg::SystemEntropy, &context, key.as_slice())
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
        Ok(Self {
            backend,
            context,
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
        let context = context(scope)?;
        let wire = backend.read().await?.ok_or(Error::NotInitialized)?;
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
        Ok(Self {
            backend,
            context,
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
    /// Commit several domain owners and their pending outputs under one version fence.
    pub async fn commit(
        &mut self,
        expected: u64,
        operation: [u8; 32],
        changes: &[Change<'_>],
        outputs: &[Output],
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
        let mut candidate = self.current()?.checkpoint.clone();
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
        self.save(candidate, operation).await
    }
    /// Acknowledge one exact output after its idempotent publication.
    pub async fn ack_output(
        &mut self,
        expected: u64,
        operation: [u8; 32],
        id: [u8; 32],
    ) -> Result<u64, Error> {
        self.expect(expected)?;
        let mut candidate = self.current()?.checkpoint.clone();
        if !candidate.pending.iter().any(|o| o.id == id) || operation == [0; 32] {
            return Err(Error::Invalid);
        }
        candidate.pending.retain(|o| o.id != id);
        self.save(candidate, operation).await
    }
    /// Wipe decrypted state. The backend remains independently reopenable.
    pub fn lock(mut self) {
        self.open = None;
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
    async fn save(&mut self, mut candidate: Checkpoint, operation: [u8; 32]) -> Result<u64, Error> {
        candidate.version = candidate.version.checked_add(1).ok_or(Error::TooLarge)?;
        candidate.operation = operation;
        validate(&candidate)?;
        let current = self.current()?;
        let wire = encode(&candidate, &current.key, &current.wrapped, &self.context)?;
        // Remove decrypted state before yielding: cancellation cannot reuse stale authority.
        let old = self.open.take().ok_or(Error::Locked)?;
        self.backend
            .compare_exchange(Some(&old.wire), &wire)
            .await?;
        let version = candidate.version;
        self.open = Some(Open {
            key: old.key,
            wrapped: old.wrapped,
            wire,
            checkpoint: candidate,
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
