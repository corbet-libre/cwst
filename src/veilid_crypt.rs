// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// SPDX-License-Identifier: MPL-2.0
//
// Derived from Veilid (https://gitlab.com/veilid/veilid), commit
// 4e48b92445dfb3cf4cd0eae9e57e81e8cba36c8d:
// - veilid-core/src/table_store/mod.rs: maybe_protect_device_encryption_key,
//   maybe_unprotect_device_encryption_key (the protected tier);
// - veilid-core/src/table_store/table_db.rs: maybe_encrypt, maybe_decrypt
//   (the data tier, including the keyed nonce for lookup keys);
// - veilid-core/src/crypto/crypto_system/vld0/mod.rs and
//   veilid-core-optimized/src/kdf.rs: the VLD0 derive_shared_secret (Argon2id with
//   default parameters), random nonce and AEAD calls those functions rely on.
// Original work: the Veilid Team <contact@veilid.com>, MPL-2.0.
//
// Modifications (Julian Y. Richard Corbet, 2026; this file stays MPL-2.0):
// - synchronous functions over byte slices instead of Veilid's async component registry;
// - the password is raw bytes, because the caller feeds a passkey-PRF-derived secret;
// - an empty password is rejected: the device encryption key is always protected;
// - the data tier uses XChaCha20-Poly1305 with associated data instead of Veilid's
//   unauthenticated XChaCha20 (`crypt_b2b_no_auth`), so a modified, truncated or swapped
//   entry fails to decrypt instead of yielding altered plaintext;
// - no compression before encryption.

//! Veilid's two-tier table-store encryption, adapted for `cwst`.
//!
//! Protected tier: the device encryption key (DEK) is stored as
//! `"VLD0" || AEAD(password-derived key, DEK) || nonce`, where the key comes from
//! Argon2id(password, salt = nonce). Data tier: every stored item is `nonce || AEAD(...)`;
//! lookup keys use a keyed nonce (a hash of content and secret) so that equal keys map to
//! equal ciphertexts, values use random nonces.

use crate::Error;
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use zeroize::Zeroizing;

/// FourCC of the VLD0 cryptosystem, the only one supported.
pub(crate) const CRYPTO_KIND_VLD0: [u8; 4] = *b"VLD0";
/// VLD0 shared secret length.
pub(crate) const SHARED_SECRET_LENGTH: usize = 32;
/// VLD0 (XChaCha20) nonce length.
pub(crate) const NONCE_LENGTH: usize = 24;
/// VLD0 (Poly1305) AEAD tag length.
pub(crate) const AEAD_OVERHEAD: usize = 16;
/// Length of a protected device encryption key blob.
pub(crate) const PROTECTED_KEY_LENGTH: usize =
    4 + SHARED_SECRET_LENGTH + AEAD_OVERHEAD + NONCE_LENGTH;
/// Upper bound for a password; the expected input is a 32-byte derived secret.
pub(crate) const MAX_PASSWORD_LENGTH: usize = 1024;

/// A 32-byte symmetric secret that is wiped on drop.
pub(crate) type Secret = Zeroizing<[u8; SHARED_SECRET_LENGTH]>;

pub(crate) fn random_bytes<const N: usize>() -> Result<[u8; N], Error> {
    let mut out = [0u8; N];
    getrandom::fill(&mut out).map_err(|_| Error::Randomness)?;
    Ok(out)
}

/// VLD0 `random_shared_secret`.
pub(crate) fn random_secret() -> Result<Secret, Error> {
    let mut out = Zeroizing::new([0u8; SHARED_SECRET_LENGTH]);
    getrandom::fill(out.as_mut()).map_err(|_| Error::Randomness)?;
    Ok(out)
}

fn check_password(password: &[u8]) -> Result<(), Error> {
    if password.is_empty() || password.len() > MAX_PASSWORD_LENGTH {
        return Err(Error::InvalidPassword);
    }
    Ok(())
}

/// VLD0 `derive_shared_secret`: Argon2id (v19, default parameters) of the password under
/// the salt, 32 bytes of output.
fn derive_shared_secret(password: &[u8], salt: &[u8]) -> Result<Secret, Error> {
    let mut out = Zeroizing::new([0u8; SHARED_SECRET_LENGTH]);
    argon2::Argon2::default()
        .hash_password_into(password, salt, out.as_mut())
        .map_err(|_| Error::Crypto)?;
    Ok(out)
}

fn cipher(secret: &[u8; SHARED_SECRET_LENGTH]) -> Result<XChaCha20Poly1305, Error> {
    XChaCha20Poly1305::new_from_slice(secret).map_err(|_| Error::Crypto)
}

fn nonce(bytes: &[u8]) -> Result<XNonce, Error> {
    XNonce::try_from(bytes).map_err(|_| Error::Corrupt)
}

/// Protect the device encryption key with a password
/// (Veilid: `maybe_protect_device_encryption_key`).
pub(crate) fn protect_device_encryption_key(
    dek: &Secret,
    password: &[u8],
) -> Result<Vec<u8>, Error> {
    check_password(password)?;
    let nonce_bytes = random_bytes::<NONCE_LENGTH>()?;
    let shared_secret = derive_shared_secret(password, &nonce_bytes)?;
    let protected_key = cipher(&shared_secret)?
        .encrypt(&nonce(&nonce_bytes)?, dek.as_slice())
        .map_err(|_| Error::Crypto)?;
    let mut out = Vec::with_capacity(PROTECTED_KEY_LENGTH);
    out.extend_from_slice(&CRYPTO_KIND_VLD0);
    out.extend_from_slice(&protected_key);
    out.extend_from_slice(&nonce_bytes);
    debug_assert_eq!(out.len(), PROTECTED_KEY_LENGTH);
    Ok(out)
}

/// Recover the device encryption key with the password
/// (Veilid: `maybe_unprotect_device_encryption_key`).
///
/// A wrong password and a modified blob are indistinguishable: both yield
/// [`Error::Unlock`].
pub(crate) fn unprotect_device_encryption_key(
    dek_bytes: &[u8],
    password: &[u8],
) -> Result<Secret, Error> {
    check_password(password)?;
    if dek_bytes.len() < 4 {
        return Err(Error::Corrupt);
    }
    if dek_bytes[0..4] != CRYPTO_KIND_VLD0 {
        return Err(Error::UnsupportedKind);
    }
    if dek_bytes.len() != PROTECTED_KEY_LENGTH {
        return Err(Error::Corrupt);
    }
    let protected_key = &dek_bytes[4..4 + SHARED_SECRET_LENGTH + AEAD_OVERHEAD];
    let nonce_bytes = &dek_bytes[4 + SHARED_SECRET_LENGTH + AEAD_OVERHEAD..];
    let shared_secret = derive_shared_secret(password, nonce_bytes)?;
    let unprotected = Zeroizing::new(
        cipher(&shared_secret)?
            .decrypt(&nonce(nonce_bytes)?, protected_key)
            .map_err(|_| Error::Unlock)?,
    );
    let mut out = Zeroizing::new([0u8; SHARED_SECRET_LENGTH]);
    if unprotected.len() != SHARED_SECRET_LENGTH {
        return Err(Error::Corrupt);
    }
    out.copy_from_slice(&unprotected);
    Ok(out)
}

/// Encrypt and prepend the nonce (Veilid: `maybe_encrypt`).
///
/// Keyed nonces are unique because lookup keys are unique: the nonce is the first
/// 24 bytes of BLAKE3(data || secret), so equal inputs produce equal outputs and a
/// stored key can be found again. All other data uses a random nonce.
pub(crate) fn encrypt(
    data: &[u8],
    secret: &Secret,
    keyed_nonce: bool,
    associated_data: &[u8],
) -> Result<Vec<u8>, Error> {
    let nonce_bytes: [u8; NONCE_LENGTH] = if keyed_nonce {
        let mut hasher = blake3::Hasher::new();
        hasher.update(data);
        hasher.update(secret.as_slice());
        let hash = hasher.finalize();
        let mut out = [0u8; NONCE_LENGTH];
        out.copy_from_slice(&hash.as_bytes()[..NONCE_LENGTH]);
        out
    } else {
        random_bytes::<NONCE_LENGTH>()?
    };
    let ciphertext = cipher(secret)?
        .encrypt(
            &nonce(&nonce_bytes)?,
            Payload {
                msg: data,
                aad: associated_data,
            },
        )
        .map_err(|_| Error::Crypto)?;
    let mut out = Vec::with_capacity(NONCE_LENGTH + ciphertext.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypt data with its nonce prepended (Veilid: `maybe_decrypt`).
pub(crate) fn decrypt(
    data: &[u8],
    secret: &Secret,
    associated_data: &[u8],
) -> Result<Zeroizing<Vec<u8>>, Error> {
    if data.len() < NONCE_LENGTH + AEAD_OVERHEAD {
        return Err(Error::Corrupt);
    }
    let (nonce_bytes, ciphertext) = data.split_at(NONCE_LENGTH);
    let plaintext = cipher(secret)?
        .decrypt(
            &nonce(nonce_bytes)?,
            Payload {
                msg: ciphertext,
                aad: associated_data,
            },
        )
        .map_err(|_| Error::Corrupt)?;
    Ok(Zeroizing::new(plaintext))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protected_key_round_trip_and_wrong_password() {
        let dek = random_secret().unwrap();
        let blob = protect_device_encryption_key(&dek, b"correct horse battery staple").unwrap();
        assert_eq!(blob.len(), PROTECTED_KEY_LENGTH);
        assert_eq!(&blob[..4], b"VLD0");
        let back = unprotect_device_encryption_key(&blob, b"correct horse battery staple").unwrap();
        assert_eq!(*back, *dek);
        assert_eq!(
            unprotect_device_encryption_key(&blob, b"wrong").unwrap_err(),
            Error::Unlock
        );
    }

    #[test]
    fn empty_password_is_rejected() {
        let dek = random_secret().unwrap();
        assert_eq!(
            protect_device_encryption_key(&dek, b"").unwrap_err(),
            Error::InvalidPassword
        );
    }

    #[test]
    fn unknown_kind_is_rejected() {
        let dek = random_secret().unwrap();
        let mut blob = protect_device_encryption_key(&dek, b"password").unwrap();
        blob[..4].copy_from_slice(b"VLD1");
        assert_eq!(
            unprotect_device_encryption_key(&blob, b"password").unwrap_err(),
            Error::UnsupportedKind
        );
    }

    #[test]
    fn keyed_nonce_is_deterministic_and_random_nonce_is_not() {
        let secret = random_secret().unwrap();
        let a = encrypt(b"key", &secret, true, b"aad").unwrap();
        let b = encrypt(b"key", &secret, true, b"aad").unwrap();
        assert_eq!(a, b);
        let c = encrypt(b"value", &secret, false, b"aad").unwrap();
        let d = encrypt(b"value", &secret, false, b"aad").unwrap();
        assert_ne!(c, d);
        assert_eq!(decrypt(&c, &secret, b"aad").unwrap().as_slice(), b"value");
    }

    #[test]
    fn associated_data_and_tampering_are_authenticated() {
        let secret = random_secret().unwrap();
        let mut sealed = encrypt(b"value", &secret, false, b"one").unwrap();
        assert_eq!(
            decrypt(&sealed, &secret, b"two").unwrap_err(),
            Error::Corrupt
        );
        let last = sealed.len() - 1;
        sealed[last] ^= 1;
        assert_eq!(
            decrypt(&sealed, &secret, b"one").unwrap_err(),
            Error::Corrupt
        );
    }
}
