use std::fmt;

/// Coarse errors never carry identifiers, data, paths or upstream messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Creation found a checkpoint.
    AlreadyInitialized,
    /// No checkpoint exists; this is distinct from unavailable storage.
    NotInitialized,
    /// Wrapped key could not be opened.
    Unlock,
    /// Ciphertext or serialized data is invalid.
    Corrupt,
    /// Invalid scope, identifier or transaction shape.
    Invalid,
    /// Resource bound exceeded.
    TooLarge,
    /// A concurrent writer won; reopen and reconcile before retrying.
    Conflict,
    /// A write may have committed; reopen and inspect the operation identifier.
    Uncertain,
    /// Storage could not be read or opened.
    Storage,
    /// No unlocked checkpoint; a cancelled commit also enters this state.
    Locked,
    /// Randomness unavailable.
    Randomness,
    /// Cryptographic operation failed.
    Crypto,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "storage: {self:?}")
    }
}
impl std::error::Error for Error {}
