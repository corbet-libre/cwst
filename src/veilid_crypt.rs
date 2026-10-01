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
// - no compression before encryption;
// - 2026-10-01: protected tier moved to ckmg StoreCipher, removing password/Argon2;
// - 2026-10-01: whole-checkpoint encryption uses random nonces and scoped AAD;
//   deterministic lookup encryption was removed because names now stay inside it.

//! Veilid data-tier AEAD composition; protected-key wrapping belongs to ckmg.

use crate::Error;
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use zeroize::Zeroizing;

pub(crate) type Secret = Zeroizing<[u8; 32]>;

pub(crate) fn random_secret() -> Result<Secret, Error> {
    let mut key = Zeroizing::new([0; 32]);
    getrandom::fill(key.as_mut()).map_err(|_| Error::Randomness)?;
    Ok(key)
}

pub(crate) fn encrypt(data: &[u8], key: &Secret, aad: &[u8]) -> Result<Vec<u8>, Error> {
    let mut nonce = [0; 24];
    getrandom::fill(&mut nonce).map_err(|_| Error::Randomness)?;
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_slice()).map_err(|_| Error::Crypto)?;
    let encrypted = cipher
        .encrypt(&XNonce::from(nonce), Payload { msg: data, aad })
        .map_err(|_| Error::Crypto)?;
    let mut out = nonce.to_vec();
    out.extend_from_slice(&encrypted);
    Ok(out)
}

pub(crate) fn decrypt(data: &[u8], key: &Secret, aad: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
    if data.len() < 40 {
        return Err(Error::Corrupt);
    }
    let nonce: [u8; 24] = data[..24].try_into().map_err(|_| Error::Corrupt)?;
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_slice()).map_err(|_| Error::Crypto)?;
    cipher
        .decrypt(
            &XNonce::from(nonce),
            Payload {
                msg: &data[24..],
                aad,
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| Error::Corrupt)
}
