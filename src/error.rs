use std::fmt;

/// Store errors. Deliberately coarse: they never carry keys, values or names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// `create` found an existing store.
    AlreadyInitialized,
    /// `unlock` found no store.
    NotInitialized,
    /// Wrong password, or the protected key was modified.
    Unlock,
    /// Stored data failed to decrypt or has the wrong shape.
    Corrupt,
    /// The protected key uses a cryptosystem other than VLD0.
    UnsupportedKind,
    /// Empty or oversized password.
    InvalidPassword,
    /// Empty or oversized namespace name.
    InvalidName,
    /// Empty or oversized key.
    InvalidKey,
    /// Oversized value.
    TooLarge,
    /// The namespace does not exist.
    UnknownNamespace,
    /// The backing database failed.
    Storage,
    /// The platform random number generator failed.
    Randomness,
    /// A cryptographic operation failed unexpectedly.
    Crypto,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Error::AlreadyInitialized => "store already initialized",
            Error::NotInitialized => "store not initialized",
            Error::Unlock => "store unlock failed",
            Error::Corrupt => "stored data is corrupt",
            Error::UnsupportedKind => "unsupported cryptosystem",
            Error::InvalidPassword => "invalid password",
            Error::InvalidName => "invalid namespace name",
            Error::InvalidKey => "invalid key",
            Error::TooLarge => "value too large",
            Error::UnknownNamespace => "unknown namespace",
            Error::Storage => "storage failure",
            Error::Randomness => "randomness unavailable",
            Error::Crypto => "cryptographic failure",
        })
    }
}

impl std::error::Error for Error {}
