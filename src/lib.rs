//! `cwst`: the web store of the member vault.
//!
//! An encrypted key-value store with named namespaces ("drawers") over any
//! [`keyvaluedb::KeyValueDB`]: IndexedDB through `keyvaluedb-web` in the browser, the
//! in-memory database in tests. The encryption follows Veilid's table store (copied under
//! MPL-2.0 in `veilid_crypt.rs`):
//!
//! - **Protected tier:** a random device encryption key (DEK), stored protected by
//!   Argon2id(password). The password is supplied by the caller; in the vault it is a
//!   secret derived from the passkey PRF output (`ckmg` does that).
//! - **Data tier:** each namespace has its own random key, wrapped by the DEK. Keys and
//!   values are encrypted with XChaCha20-Poly1305; lookup keys use a keyed nonce so they
//!   can be found again, values are bound to their key through associated data.
//!
//! Envelope encryption makes rotation cheap: a new password re-protects only the DEK, a
//! new DEK re-wraps only the namespace keys, and a new namespace key re-encrypts only that
//! namespace. Deleting a wrapped key shreds everything encrypted under it.
//!
//! The store never talks to a network, holds no policy and knows no callers: `cvlt`
//! decides who may open which namespace.

mod error;
mod store;
mod veilid_crypt;

pub use error::Error;
pub use keyvaluedb::KeyValueDB;
pub use store::{Namespace, Op, WebStore};

/// Number of columns a database handed to [`WebStore`] must have.
pub const COLUMNS: u32 = 2;
/// Maximum namespace name length in bytes.
pub const MAX_NAME_BYTES: usize = 128;
/// Maximum key length in bytes.
pub const MAX_KEY_BYTES: usize = 4 * 1024;
/// Maximum value length in bytes.
pub const MAX_VALUE_BYTES: usize = 64 * 1024 * 1024;

/// An empty in-memory database with the right column count, for tests and for
/// ephemeral stores that must not touch persistent storage.
pub fn memory_database() -> keyvaluedb_memorydb::InMemory {
    keyvaluedb_memorydb::create(COLUMNS)
}

/// Browser persistence through IndexedDB (`keyvaluedb-web`).
#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
pub mod browser {
    use crate::{COLUMNS, Error};
    pub use keyvaluedb_web::Database;

    /// Open (or create) the IndexedDB database `name` with the columns the store needs.
    /// Data is read on demand, not cached in memory.
    pub async fn open_database(name: &str) -> Result<Database, Error> {
        Database::open(name, COLUMNS, false)
            .await
            .map_err(|_| Error::Storage)
    }

    /// Delete the IndexedDB database `name`. Returns whether one existed.
    ///
    /// Use after [`crate::WebStore::shred`] to drop the (already unreadable) ciphertext
    /// as well.
    pub async fn delete_database(name: &str) -> Result<bool, Error> {
        Database::delete(name).await.map_err(|_| Error::Storage)
    }
}
