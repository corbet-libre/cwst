//! Behaviour of the encrypted store over the in-memory database.

use cwst::{Error, KeyValueDB, Op, WebStore, memory_database};
use futures_executor::block_on;
use keyvaluedb_memorydb::InMemory;

const PASSWORD: &[u8] = b"a 32-byte secret derived from PRF";

async fn raw_dump(db: &InMemory) -> Vec<(u32, Vec<u8>, Vec<u8>)> {
    let mut out = Vec::new();
    for col in 0..cwst::COLUMNS {
        let (entries, _) = db
            .iter(
                col,
                None,
                Vec::new(),
                |acc: &mut Vec<(Vec<u8>, Vec<u8>)>, (k, v)| {
                    acc.push((k.clone(), v.clone()));
                    Ok(None::<()>)
                },
            )
            .await
            .unwrap();
        out.extend(entries.into_iter().map(|(k, v)| (col, k, v)));
    }
    out
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

#[test]
fn create_put_get_and_unlock_again() {
    block_on(async {
        let db = memory_database();
        assert!(!WebStore::is_initialized(&db).await.unwrap());
        let store = WebStore::create(db.clone(), PASSWORD).await.unwrap();
        let drawer = store.namespace("contacts").await.unwrap();
        drawer.put(b"alice", b"onion address").await.unwrap();
        assert_eq!(
            drawer.get(b"alice").await.unwrap().unwrap().as_slice(),
            b"onion address"
        );
        assert!(drawer.get(b"bob").await.unwrap().is_none());
        drop(drawer);
        drop(store);

        assert!(WebStore::is_initialized(&db).await.unwrap());
        let store = WebStore::unlock(db, PASSWORD).await.unwrap();
        let drawer = store.existing_namespace("contacts").await.unwrap();
        assert_eq!(
            drawer.get(b"alice").await.unwrap().unwrap().as_slice(),
            b"onion address"
        );
    });
}

#[test]
fn lifecycle_errors() {
    block_on(async {
        let db = memory_database();
        assert_eq!(
            WebStore::unlock(db.clone(), PASSWORD).await.unwrap_err(),
            Error::NotInitialized
        );
        WebStore::create(db.clone(), PASSWORD).await.unwrap();
        assert_eq!(
            WebStore::create(db.clone(), PASSWORD).await.unwrap_err(),
            Error::AlreadyInitialized
        );
        assert_eq!(
            WebStore::unlock(db.clone(), b"wrong password")
                .await
                .unwrap_err(),
            Error::Unlock
        );
        assert_eq!(
            WebStore::unlock(db, b"").await.unwrap_err(),
            Error::InvalidPassword
        );
    });
}

#[test]
fn nothing_is_stored_in_plaintext() {
    block_on(async {
        let db = memory_database();
        let store = WebStore::create(db.clone(), PASSWORD).await.unwrap();
        let drawer = store.namespace("very-visible-drawer").await.unwrap();
        drawer
            .put(b"very-visible-key", b"very-visible-value")
            .await
            .unwrap();
        for (_, key, value) in raw_dump(&db).await {
            for needle in [
                &b"very-visible"[..],
                PASSWORD,
                &b"very-visible-key"[..],
                &b"very-visible-value"[..],
            ] {
                assert!(!contains(&key, needle));
                assert!(!contains(&value, needle));
            }
        }
    });
}

#[test]
fn namespaces_are_isolated_and_listed() {
    block_on(async {
        let store = WebStore::create(memory_database(), PASSWORD).await.unwrap();
        let a = store.namespace("a").await.unwrap();
        let b = store.namespace("b").await.unwrap();
        a.put(b"k", b"from a").await.unwrap();
        b.put(b"k", b"from b").await.unwrap();
        a.put(b"only-a", b"x").await.unwrap();
        assert_eq!(a.get(b"k").await.unwrap().unwrap().as_slice(), b"from a");
        assert_eq!(b.get(b"k").await.unwrap().unwrap().as_slice(), b"from b");
        let mut keys = a.keys().await.unwrap();
        keys.sort();
        assert_eq!(keys, vec![b"k".to_vec(), b"only-a".to_vec()]);
        assert_eq!(b.keys().await.unwrap(), vec![b"k".to_vec()]);
        assert_eq!(store.namespaces().await.unwrap(), vec!["a", "b"]);
        assert_eq!(
            store.existing_namespace("c").await.unwrap_err(),
            Error::UnknownNamespace
        );
    });
}

#[test]
fn delete_batch_entries_and_clear() {
    block_on(async {
        let store = WebStore::create(memory_database(), PASSWORD).await.unwrap();
        let drawer = store.namespace("state").await.unwrap();
        drawer
            .write(&[
                Op::Put {
                    key: b"one",
                    value: b"1",
                },
                Op::Put {
                    key: b"two",
                    value: b"2",
                },
                Op::Put {
                    key: b"three",
                    value: b"3",
                },
            ])
            .await
            .unwrap();
        assert!(drawer.delete(b"two").await.unwrap());
        assert!(!drawer.delete(b"two").await.unwrap());
        drawer
            .write(&[
                Op::Delete { key: b"one" },
                Op::Put {
                    key: b"four",
                    value: b"4",
                },
            ])
            .await
            .unwrap();
        let mut entries: Vec<(Vec<u8>, Vec<u8>)> = drawer
            .entries()
            .await
            .unwrap()
            .into_iter()
            .map(|(k, v)| (k, v.to_vec()))
            .collect();
        entries.sort();
        assert_eq!(
            entries,
            vec![
                (b"four".to_vec(), b"4".to_vec()),
                (b"three".to_vec(), b"3".to_vec())
            ]
        );
        drawer.clear().await.unwrap();
        assert!(drawer.keys().await.unwrap().is_empty());
        assert_eq!(store.namespaces().await.unwrap(), vec!["state"]);
    });
}

#[test]
fn invalid_inputs() {
    block_on(async {
        let store = WebStore::create(memory_database(), PASSWORD).await.unwrap();
        assert_eq!(store.namespace("").await.unwrap_err(), Error::InvalidName);
        let long = "n".repeat(cwst::MAX_NAME_BYTES + 1);
        assert_eq!(
            store.namespace(&long).await.unwrap_err(),
            Error::InvalidName
        );
        let drawer = store.namespace("d").await.unwrap();
        assert_eq!(drawer.put(b"", b"v").await.unwrap_err(), Error::InvalidKey);
        assert_eq!(drawer.get(b"").await.unwrap_err(), Error::InvalidKey);
    });
}

#[test]
fn change_password() {
    block_on(async {
        let db = memory_database();
        let store = WebStore::create(db.clone(), PASSWORD).await.unwrap();
        store
            .namespace("d")
            .await
            .unwrap()
            .put(b"k", b"v")
            .await
            .unwrap();
        store.change_password(b"new secret").await.unwrap();
        drop(store);
        assert_eq!(
            WebStore::unlock(db.clone(), PASSWORD).await.unwrap_err(),
            Error::Unlock
        );
        let store = WebStore::unlock(db, b"new secret").await.unwrap();
        let drawer = store.existing_namespace("d").await.unwrap();
        assert_eq!(drawer.get(b"k").await.unwrap().unwrap().as_slice(), b"v");
    });
}

#[test]
fn rotate_device_key_keeps_entries_and_rewraps_keys() {
    block_on(async {
        let db = memory_database();
        let mut store = WebStore::create(db.clone(), PASSWORD).await.unwrap();
        store
            .namespace("d")
            .await
            .unwrap()
            .put(b"k", b"v")
            .await
            .unwrap();
        let before = raw_dump(&db).await;
        store.rotate_device_key(PASSWORD).await.unwrap();
        let after = raw_dump(&db).await;
        let meta = |dump: &[(u32, Vec<u8>, Vec<u8>)]| {
            dump.iter()
                .filter(|(col, _, _)| *col == 0)
                .map(|(_, _, v)| v.clone())
                .collect::<Vec<_>>()
        };
        let data = |dump: &[(u32, Vec<u8>, Vec<u8>)]| {
            dump.iter()
                .filter(|(col, _, _)| *col == 1)
                .cloned()
                .collect::<Vec<_>>()
        };
        // Every wrapped key changed, no entry was re-encrypted.
        for value in meta(&after) {
            assert!(!meta(&before).contains(&value));
        }
        assert_eq!(data(&before), data(&after));
        drop(store);
        let store = WebStore::unlock(db, PASSWORD).await.unwrap();
        let drawer = store.existing_namespace("d").await.unwrap();
        assert_eq!(drawer.get(b"k").await.unwrap().unwrap().as_slice(), b"v");
    });
}

#[test]
fn rotate_namespace_key_reencrypts_only_that_namespace() {
    block_on(async {
        let db = memory_database();
        let mut store = WebStore::create(db.clone(), PASSWORD).await.unwrap();
        store
            .namespace("a")
            .await
            .unwrap()
            .put(b"k", b"va")
            .await
            .unwrap();
        store
            .namespace("b")
            .await
            .unwrap()
            .put(b"k", b"vb")
            .await
            .unwrap();
        let before = raw_dump(&db).await;
        store.rotate_namespace_key("a").await.unwrap();
        let after = raw_dump(&db).await;
        let data_before: Vec<_> = before.iter().filter(|e| e.0 == 1).collect();
        let data_after: Vec<_> = after.iter().filter(|e| e.0 == 1).collect();
        assert_eq!(data_before.len(), 2);
        assert_eq!(data_after.len(), 2);
        // Exactly one entry (namespace b) survived unchanged.
        assert_eq!(
            data_after
                .iter()
                .filter(|e| data_before.contains(*e))
                .count(),
            1
        );
        assert_eq!(
            store
                .existing_namespace("a")
                .await
                .unwrap()
                .get(b"k")
                .await
                .unwrap()
                .unwrap()
                .as_slice(),
            b"va"
        );
        assert_eq!(
            store
                .existing_namespace("b")
                .await
                .unwrap()
                .get(b"k")
                .await
                .unwrap()
                .unwrap()
                .as_slice(),
            b"vb"
        );
    });
}

#[test]
fn shred_namespace_removes_key_and_entries() {
    block_on(async {
        let db = memory_database();
        let mut store = WebStore::create(db.clone(), PASSWORD).await.unwrap();
        store
            .namespace("gone")
            .await
            .unwrap()
            .put(b"k", b"v")
            .await
            .unwrap();
        store
            .namespace("kept")
            .await
            .unwrap()
            .put(b"k", b"v")
            .await
            .unwrap();
        let meta_before = raw_dump(&db).await.iter().filter(|e| e.0 == 0).count();
        assert!(store.shred_namespace("gone").await.unwrap());
        assert!(!store.shred_namespace("gone").await.unwrap());
        let dump = raw_dump(&db).await;
        assert_eq!(dump.iter().filter(|e| e.0 == 0).count(), meta_before - 1);
        assert_eq!(dump.iter().filter(|e| e.0 == 1).count(), 1);
        assert_eq!(store.namespaces().await.unwrap(), vec!["kept"]);
        let fresh = store.namespace("gone").await.unwrap();
        assert!(fresh.get(b"k").await.unwrap().is_none());
    });
}

#[test]
fn shred_store_leaves_nothing() {
    block_on(async {
        let db = memory_database();
        let store = WebStore::create(db.clone(), PASSWORD).await.unwrap();
        store
            .namespace("d")
            .await
            .unwrap()
            .put(b"k", b"v")
            .await
            .unwrap();
        store.shred().await.unwrap();
        assert!(raw_dump(&db).await.is_empty());
        assert!(!WebStore::is_initialized(&db).await.unwrap());
        assert_eq!(
            WebStore::unlock(db, PASSWORD).await.unwrap_err(),
            Error::NotInitialized
        );
    });
}

#[test]
fn tampered_or_swapped_values_are_rejected() {
    block_on(async {
        let db = memory_database();
        let store = WebStore::create(db.clone(), PASSWORD).await.unwrap();
        let drawer = store.namespace("d").await.unwrap();
        drawer.put(b"one", b"1").await.unwrap();
        drawer.put(b"two", b"2").await.unwrap();
        let data: Vec<_> = raw_dump(&db)
            .await
            .into_iter()
            .filter(|e| e.0 == 1)
            .collect();
        assert_eq!(data.len(), 2);

        // Swap the two values: each value is bound to its key.
        let mut tx = db.transaction();
        tx.put(1, &data[0].1, &data[1].2);
        tx.put(1, &data[1].1, &data[0].2);
        db.write(tx).await.unwrap();
        assert_eq!(drawer.get(b"one").await.unwrap_err(), Error::Corrupt);
        assert_eq!(drawer.get(b"two").await.unwrap_err(), Error::Corrupt);

        // Flip one bit of a value.
        let mut flipped = data[0].2.clone();
        let last = flipped.len() - 1;
        flipped[last] ^= 1;
        let mut tx = db.transaction();
        tx.put(1, &data[0].1, &flipped);
        db.write(tx).await.unwrap();
        assert!(drawer.entries().await.is_err());
    });
}
