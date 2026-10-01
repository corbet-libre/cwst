//! Atomic ciphertext persistence. Adapters must never report volatile writes as durable.
use crate::{Error, MAX_CHECKPOINT_BYTES};
use keyvaluedb::KeyValueDB;
use std::sync::Arc;

/// A bounded read and compare/exchange port. No delete/reset operation is exposed.
#[allow(async_fn_in_trait)]
pub trait Backend {
    /// Authoritative absence is `None`; inability to read is an error.
    async fn read(&self) -> Result<Option<Vec<u8>>, Error>;
    /// Compare exact previous ciphertext and durably replace it atomically.
    /// A mismatch returns Conflict. Any ambiguous write returns Uncertain.
    async fn compare_exchange(&self, expected: Option<&[u8]>, next: &[u8]) -> Result<(), Error>;
}

/// Real keyvaluedb in-memory adapter, serialized across cloned handles.
/// It is intentionally ephemeral and makes no disk durability claim.
#[derive(Clone, Default)]
pub struct Memory {
    inner: Arc<futures::lock::Mutex<Option<keyvaluedb_memorydb::InMemory>>>,
}
impl Memory {
    /// An empty isolated database.
    pub fn new() -> Self {
        Self::default()
    }
}
impl Backend for Memory {
    async fn read(&self) -> Result<Option<Vec<u8>>, Error> {
        let mut guard = self.inner.lock().await;
        let db = guard.get_or_insert_with(|| keyvaluedb_memorydb::create(1));
        db.get(0, b"checkpoint").await.map_err(|_| Error::Storage)
    }
    async fn compare_exchange(&self, expected: Option<&[u8]>, next: &[u8]) -> Result<(), Error> {
        check_size(next)?;
        let mut guard = self.inner.lock().await;
        let db = guard.get_or_insert_with(|| keyvaluedb_memorydb::create(1));
        let current = db.get(0, b"checkpoint").await.map_err(|_| Error::Storage)?;
        if current.as_deref() != expected {
            return Err(Error::Conflict);
        }
        let mut tx = db.transaction();
        tx.put(0, b"checkpoint", next);
        db.write(tx).await.map_err(|_| Error::Uncertain)
    }
}
pub(crate) fn check_size(bytes: &[u8]) -> Result<(), Error> {
    if bytes.is_empty() || bytes.len() > MAX_CHECKPOINT_BYTES {
        Err(Error::TooLarge)
    } else {
        Ok(())
    }
}
