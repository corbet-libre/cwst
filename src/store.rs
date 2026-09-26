//! The store: protected device key, wrapped namespace keys, encrypted entries.
//!
//! Layout of the backing database (two columns):
//!
//! | Column | Key | Value |
//! |---|---|---|
//! | meta | `cwst.dek` | protected device encryption key (Veilid format) |
//! | meta | `cwst.index` | index key, encrypted under the DEK |
//! | meta | `cwst.ns:` + tag | namespace key and name, encrypted under the DEK |
//! | data | tag + encrypted key | encrypted value |
//!
//! The tag is a keyed hash of the namespace name (16 bytes), so neither names nor keys
//! are visible in storage. The database does reveal how many entries each namespace has
//! and their sizes; callers that must hide sizes pad before storing.

use crate::veilid_crypt::{self, SHARED_SECRET_LENGTH, Secret};
use crate::{Error, MAX_KEY_BYTES, MAX_NAME_BYTES, MAX_VALUE_BYTES};
use keyvaluedb::{DBTransaction, KeyValueDB};
use zeroize::Zeroizing;

const META: u32 = 0;
const DATA: u32 = 1;

const DEK_KEY: &[u8] = b"cwst.dek";
const INDEX_KEY: &[u8] = b"cwst.index";
const NAMESPACE_PREFIX: &[u8] = b"cwst.ns:";
const TAG_LENGTH: usize = 16;

const AAD_INDEX: &[u8] = b"cwst.index.v1";
const AAD_NAMESPACE: &[u8] = b"cwst.namespace.v1";
const AAD_KEY: &[u8] = b"cwst.key.v1";
const AAD_VALUE: &[u8] = b"cwst.value.v1";
const TAG_CONTEXT: &[u8] = b"cwst.namespace-tag.v1";

type Tag = [u8; TAG_LENGTH];

/// One write in an atomic [`Namespace::write`] batch.
#[derive(Clone, Copy)]
pub enum Op<'a> {
    /// Insert or replace `key` with `value`.
    Put {
        /// Plaintext key.
        key: &'a [u8],
        /// Plaintext value.
        value: &'a [u8],
    },
    /// Remove `key` if present.
    Delete {
        /// Plaintext key.
        key: &'a [u8],
    },
}

impl std::fmt::Debug for Op<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Op::Put { .. } => "Op::Put([redacted])",
            Op::Delete { .. } => "Op::Delete([redacted])",
        })
    }
}

/// An unlocked store. The device encryption key lives only in this value (wiped on
/// drop) and never leaves the crate.
pub struct WebStore<D: KeyValueDB> {
    db: D,
    dek: Secret,
    index: Secret,
}

impl<D: KeyValueDB> std::fmt::Debug for WebStore<D> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("WebStore([redacted])")
    }
}

struct NamespaceEntry {
    key: Secret,
    name: String,
}

impl<D: KeyValueDB> WebStore<D> {
    /// Whether `db` already holds a store.
    pub async fn is_initialized(db: &D) -> Result<bool, Error> {
        Ok(db
            .get(META, DEK_KEY)
            .await
            .map_err(|_| Error::Storage)?
            .is_some())
    }

    /// Create a new store in an empty database, protected by `password`.
    ///
    /// Only one vault instance may own a database: the check for an existing store and
    /// the first write are not atomic across concurrent callers.
    pub async fn create(db: D, password: &[u8]) -> Result<Self, Error> {
        if Self::is_initialized(&db).await? {
            return Err(Error::AlreadyInitialized);
        }
        let dek = veilid_crypt::random_secret()?;
        let index = veilid_crypt::random_secret()?;
        let mut tx = DBTransaction::new();
        tx.put_owned(
            META,
            DEK_KEY.to_vec(),
            veilid_crypt::protect_device_encryption_key(&dek, password)?,
        );
        tx.put_owned(
            META,
            INDEX_KEY.to_vec(),
            veilid_crypt::encrypt(index.as_slice(), &dek, false, AAD_INDEX)?,
        );
        write(&db, tx).await?;
        Ok(Self { db, dek, index })
    }

    /// Unlock an existing store with `password`.
    pub async fn unlock(db: D, password: &[u8]) -> Result<Self, Error> {
        let protected = db
            .get(META, DEK_KEY)
            .await
            .map_err(|_| Error::Storage)?
            .ok_or(Error::NotInitialized)?;
        let dek = veilid_crypt::unprotect_device_encryption_key(&protected, password)?;
        let wrapped_index = db
            .get(META, INDEX_KEY)
            .await
            .map_err(|_| Error::Storage)?
            .ok_or(Error::Corrupt)?;
        let index = to_secret(&veilid_crypt::decrypt(&wrapped_index, &dek, AAD_INDEX)?)?;
        Ok(Self { db, dek, index })
    }

    /// Protect the device encryption key with a new password. Nothing else is
    /// re-encrypted; the old password stops working once this returns.
    pub async fn change_password(&self, new_password: &[u8]) -> Result<(), Error> {
        let mut tx = DBTransaction::new();
        tx.put_owned(
            META,
            DEK_KEY.to_vec(),
            veilid_crypt::protect_device_encryption_key(&self.dek, new_password)?,
        );
        write(&self.db, tx).await
    }

    /// Replace the device encryption key and protect the new one with `password`.
    /// Re-wraps the index key and every namespace key in one transaction; entries are
    /// untouched.
    pub async fn rotate_device_key(&mut self, password: &[u8]) -> Result<(), Error> {
        let new_dek = veilid_crypt::random_secret()?;
        let mut tx = DBTransaction::new();
        tx.put_owned(
            META,
            DEK_KEY.to_vec(),
            veilid_crypt::protect_device_encryption_key(&new_dek, password)?,
        );
        tx.put_owned(
            META,
            INDEX_KEY.to_vec(),
            veilid_crypt::encrypt(self.index.as_slice(), &new_dek, false, AAD_INDEX)?,
        );
        for (tag, entry) in self.namespace_entries().await? {
            tx.put_owned(
                META,
                namespace_meta_key(&tag),
                seal_namespace(&new_dek, &tag, &entry)?,
            );
        }
        write(&self.db, tx).await?;
        self.dek = new_dek;
        Ok(())
    }

    /// Open the namespace `name`, creating it if it does not exist.
    pub async fn namespace(&self, name: &str) -> Result<Namespace<'_, D>, Error> {
        match self.existing_namespace(name).await {
            Err(Error::UnknownNamespace) => {}
            other => return other,
        }
        let tag = self.tag(name);
        let entry = NamespaceEntry {
            key: veilid_crypt::random_secret()?,
            name: name.to_owned(),
        };
        let mut tx = DBTransaction::new();
        tx.put_owned(
            META,
            namespace_meta_key(&tag),
            seal_namespace(&self.dek, &tag, &entry)?,
        );
        write(&self.db, tx).await?;
        Ok(Namespace {
            store: self,
            tag,
            key: entry.key,
        })
    }

    /// Open the namespace `name`; [`Error::UnknownNamespace`] if it does not exist.
    pub async fn existing_namespace(&self, name: &str) -> Result<Namespace<'_, D>, Error> {
        let tag = self.tag(name);
        let entry = self.load_namespace(name, &tag).await?;
        Ok(Namespace {
            store: self,
            tag,
            key: entry.key,
        })
    }

    /// Names of all namespaces, sorted.
    pub async fn namespaces(&self) -> Result<Vec<String>, Error> {
        let mut names: Vec<String> = self
            .namespace_entries()
            .await?
            .into_iter()
            .map(|(_, entry)| entry.name)
            .collect();
        names.sort();
        Ok(names)
    }

    /// Give the namespace a new key and re-encrypt all of its entries in one
    /// transaction. Afterwards the old namespace key decrypts nothing that is stored.
    pub async fn rotate_namespace_key(&mut self, name: &str) -> Result<(), Error> {
        let tag = self.tag(name);
        let old = self.load_namespace(name, &tag).await?;
        let new = NamespaceEntry {
            key: veilid_crypt::random_secret()?,
            name: old.name.clone(),
        };
        let mut tx = DBTransaction::new();
        for (stored_key, stored_value) in raw_entries(&self.db, DATA, &tag).await? {
            let key = open_key(&old.key, &tag, &stored_key)?;
            let value = open_value(&old.key, &stored_key, &stored_value)?;
            let new_stored_key = seal_key(&new.key, &tag, &key)?;
            let new_stored_value = seal_value(&new.key, &new_stored_key, &value)?;
            tx.delete_owned(DATA, stored_key);
            tx.put_owned(DATA, new_stored_key, new_stored_value);
        }
        tx.put_owned(
            META,
            namespace_meta_key(&tag),
            seal_namespace(&self.dek, &tag, &new)?,
        );
        write(&self.db, tx).await
    }

    /// Crypto-shred the namespace: delete its wrapped key and all of its entries.
    /// Returns whether it existed. Opening it again creates a new, empty namespace.
    pub async fn shred_namespace(&mut self, name: &str) -> Result<bool, Error> {
        let tag = self.tag(name);
        match self.load_namespace(name, &tag).await {
            Ok(_) => {}
            Err(Error::UnknownNamespace) => return Ok(false),
            Err(error) => return Err(error),
        }
        let mut tx = DBTransaction::new();
        tx.delete_owned(META, namespace_meta_key(&tag));
        tx.delete_prefix(DATA, tag);
        write(&self.db, tx).await?;
        Ok(true)
    }

    /// Crypto-shred the whole store: the protected device key, all wrapped keys and all
    /// entries. The database is left empty and uninitialized.
    pub async fn shred(self) -> Result<(), Error> {
        let mut tx = DBTransaction::new();
        tx.delete_prefix(META, b"");
        tx.delete_prefix(DATA, b"");
        write(&self.db, tx).await
    }

    fn tag(&self, name: &str) -> Tag {
        let mut input = Vec::with_capacity(TAG_CONTEXT.len() + name.len());
        input.extend_from_slice(TAG_CONTEXT);
        input.extend_from_slice(name.as_bytes());
        let hash = blake3::keyed_hash(&self.index, &input);
        let mut tag = [0u8; TAG_LENGTH];
        tag.copy_from_slice(&hash.as_bytes()[..TAG_LENGTH]);
        tag
    }

    async fn load_namespace(&self, name: &str, tag: &Tag) -> Result<NamespaceEntry, Error> {
        validate_name(name)?;
        let meta_key = namespace_meta_key(tag);
        let sealed = self
            .db
            .get(META, &meta_key)
            .await
            .map_err(|_| Error::Storage)?
            .ok_or(Error::UnknownNamespace)?;
        let entry = open_namespace(&self.dek, tag, &sealed)?;
        if entry.name != name {
            return Err(Error::Corrupt);
        }
        Ok(entry)
    }

    async fn namespace_entries(&self) -> Result<Vec<(Tag, NamespaceEntry)>, Error> {
        let mut out = Vec::new();
        for (meta_key, sealed) in raw_entries(&self.db, META, NAMESPACE_PREFIX).await? {
            let tag: Tag = meta_key[NAMESPACE_PREFIX.len()..]
                .try_into()
                .map_err(|_| Error::Corrupt)?;
            let entry = open_namespace(&self.dek, &tag, &sealed)?;
            out.push((tag, entry));
        }
        Ok(out)
    }
}

/// An open namespace (drawer). Borrows the store, so it cannot outlive a key rotation
/// or a shred.
pub struct Namespace<'s, D: KeyValueDB> {
    store: &'s WebStore<D>,
    tag: Tag,
    key: Secret,
}

impl<D: KeyValueDB> std::fmt::Debug for Namespace<'_, D> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Namespace([redacted])")
    }
}

impl<D: KeyValueDB> Namespace<'_, D> {
    /// Read the value stored under `key`.
    pub async fn get(&self, key: &[u8]) -> Result<Option<Zeroizing<Vec<u8>>>, Error> {
        validate_key(key)?;
        let stored_key = seal_key(&self.key, &self.tag, key)?;
        match self
            .store
            .db
            .get(DATA, &stored_key)
            .await
            .map_err(|_| Error::Storage)?
        {
            None => Ok(None),
            Some(stored_value) => Ok(Some(open_value(&self.key, &stored_key, &stored_value)?)),
        }
    }

    /// Store `value` under `key`.
    pub async fn put(&self, key: &[u8], value: &[u8]) -> Result<(), Error> {
        self.write(&[Op::Put { key, value }]).await
    }

    /// Delete `key`. Returns whether it existed.
    pub async fn delete(&self, key: &[u8]) -> Result<bool, Error> {
        validate_key(key)?;
        let stored_key = seal_key(&self.key, &self.tag, key)?;
        Ok(self
            .store
            .db
            .delete(DATA, &stored_key)
            .await
            .map_err(|_| Error::Storage)?
            .is_some())
    }

    /// Apply several puts and deletes atomically.
    pub async fn write(&self, ops: &[Op<'_>]) -> Result<(), Error> {
        let mut tx = DBTransaction::with_capacity(ops.len());
        for op in ops {
            match *op {
                Op::Put { key, value } => {
                    validate_key(key)?;
                    if value.len() > MAX_VALUE_BYTES {
                        return Err(Error::TooLarge);
                    }
                    let stored_key = seal_key(&self.key, &self.tag, key)?;
                    let stored_value = seal_value(&self.key, &stored_key, value)?;
                    tx.put_owned(DATA, stored_key, stored_value);
                }
                Op::Delete { key } => {
                    validate_key(key)?;
                    tx.delete_owned(DATA, seal_key(&self.key, &self.tag, key)?);
                }
            }
        }
        write(&self.store.db, tx).await
    }

    /// All keys in this namespace (in storage order, which is not key order).
    pub async fn keys(&self) -> Result<Vec<Vec<u8>>, Error> {
        let tag = self.tag;
        let (stored, _) = self
            .store
            .db
            .iter_keys(
                DATA,
                Some(&tag[..]),
                Vec::new(),
                |acc: &mut Vec<Vec<u8>>, key| {
                    acc.push(key.clone());
                    Ok(None::<()>)
                },
            )
            .await
            .map_err(|_| Error::Storage)?;
        stored
            .iter()
            .map(|stored_key| open_key(&self.key, &self.tag, stored_key).map(|k| k.to_vec()))
            .collect()
    }

    /// All entries in this namespace.
    pub async fn entries(&self) -> Result<Vec<(Vec<u8>, Zeroizing<Vec<u8>>)>, Error> {
        raw_entries(&self.store.db, DATA, &self.tag)
            .await?
            .into_iter()
            .map(|(stored_key, stored_value)| {
                Ok((
                    open_key(&self.key, &self.tag, &stored_key)?.to_vec(),
                    open_value(&self.key, &stored_key, &stored_value)?,
                ))
            })
            .collect()
    }

    /// Delete every entry in this namespace, keeping the namespace and its key.
    pub async fn clear(&self) -> Result<(), Error> {
        let mut tx = DBTransaction::new();
        tx.delete_prefix(DATA, self.tag);
        write(&self.store.db, tx).await
    }
}

async fn write<D: KeyValueDB>(db: &D, tx: DBTransaction) -> Result<(), Error> {
    db.write(tx).await.map_err(|_| Error::Storage)
}

async fn raw_entries<D: KeyValueDB>(
    db: &D,
    col: u32,
    prefix: &[u8],
) -> Result<Vec<(Vec<u8>, Vec<u8>)>, Error> {
    let (entries, _) = db
        .iter(
            col,
            Some(prefix),
            Vec::new(),
            |acc: &mut Vec<(Vec<u8>, Vec<u8>)>, (key, value)| {
                acc.push((key.clone(), value.clone()));
                Ok(None::<()>)
            },
        )
        .await
        .map_err(|_| Error::Storage)?;
    Ok(entries)
}

fn validate_name(name: &str) -> Result<(), Error> {
    if name.is_empty() || name.len() > MAX_NAME_BYTES {
        return Err(Error::InvalidName);
    }
    Ok(())
}

fn validate_key(key: &[u8]) -> Result<(), Error> {
    if key.is_empty() || key.len() > MAX_KEY_BYTES {
        return Err(Error::InvalidKey);
    }
    Ok(())
}

fn to_secret(bytes: &[u8]) -> Result<Secret, Error> {
    let mut out = Zeroizing::new([0u8; SHARED_SECRET_LENGTH]);
    if bytes.len() != SHARED_SECRET_LENGTH {
        return Err(Error::Corrupt);
    }
    out.copy_from_slice(bytes);
    Ok(out)
}

fn concat(parts: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::with_capacity(parts.iter().map(|p| p.len()).sum());
    for part in parts {
        out.extend_from_slice(part);
    }
    out
}

fn namespace_meta_key(tag: &Tag) -> Vec<u8> {
    concat(&[NAMESPACE_PREFIX, &tag[..]])
}

fn seal_namespace(dek: &Secret, tag: &Tag, entry: &NamespaceEntry) -> Result<Vec<u8>, Error> {
    let plaintext = Zeroizing::new(concat(&[entry.key.as_slice(), entry.name.as_bytes()]));
    veilid_crypt::encrypt(&plaintext, dek, false, &concat(&[AAD_NAMESPACE, &tag[..]]))
}

fn open_namespace(dek: &Secret, tag: &Tag, sealed: &[u8]) -> Result<NamespaceEntry, Error> {
    let plaintext = veilid_crypt::decrypt(sealed, dek, &concat(&[AAD_NAMESPACE, &tag[..]]))?;
    if plaintext.len() <= SHARED_SECRET_LENGTH {
        return Err(Error::Corrupt);
    }
    let (key, name) = plaintext.split_at(SHARED_SECRET_LENGTH);
    Ok(NamespaceEntry {
        key: to_secret(key)?,
        name: String::from_utf8(name.to_vec()).map_err(|_| Error::Corrupt)?,
    })
}

fn seal_key(namespace_key: &Secret, tag: &Tag, key: &[u8]) -> Result<Vec<u8>, Error> {
    let sealed = veilid_crypt::encrypt(key, namespace_key, true, &concat(&[AAD_KEY, &tag[..]]))?;
    Ok(concat(&[&tag[..], &sealed[..]]))
}

fn open_key(
    namespace_key: &Secret,
    tag: &Tag,
    stored_key: &[u8],
) -> Result<Zeroizing<Vec<u8>>, Error> {
    if stored_key.len() < TAG_LENGTH || stored_key[..TAG_LENGTH] != tag[..] {
        return Err(Error::Corrupt);
    }
    veilid_crypt::decrypt(
        &stored_key[TAG_LENGTH..],
        namespace_key,
        &concat(&[AAD_KEY, &tag[..]]),
    )
}

fn seal_value(namespace_key: &Secret, stored_key: &[u8], value: &[u8]) -> Result<Vec<u8>, Error> {
    veilid_crypt::encrypt(
        value,
        namespace_key,
        false,
        &concat(&[AAD_VALUE, stored_key]),
    )
}

fn open_value(
    namespace_key: &Secret,
    stored_key: &[u8],
    stored_value: &[u8],
) -> Result<Zeroizing<Vec<u8>>, Error> {
    veilid_crypt::decrypt(
        stored_value,
        namespace_key,
        &concat(&[AAD_VALUE, stored_key]),
    )
}
