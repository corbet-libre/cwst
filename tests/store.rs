//! Shared real encryption/transaction vectors on native and browser Wasm.
use ckmg::passkey::{PrfOutput, StoreCipher, store_cipher};
use cwst::{
    Change, Error, Output, Store,
    backend::{Backend, Memory},
};

#[cfg(target_arch = "wasm32")]
wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);
macro_rules! test_async {
    ($name:ident, $body:block) => {
        #[cfg(not(target_arch = "wasm32"))]
        #[test]
        fn $name() { futures_executor::block_on(async $body); }
        #[cfg(target_arch = "wasm32")]
        #[wasm_bindgen_test::wasm_bindgen_test]
        async fn $name() $body
    }
}
fn cipher(byte: u8) -> StoreCipher {
    store_cipher(
        &PrfOutput::from_bytes(&[byte; 32]).unwrap(),
        "test-community",
    )
    .unwrap()
}
fn changes<'a>(a: &'a [u8], b: &'a [u8]) -> [Change<'a>; 2] {
    [
        Change::Put {
            owner: "wallet",
            key: b"state",
            value: a,
        },
        Change::Put {
            owner: "threads",
            key: b"state",
            value: b,
        },
    ]
}
async fn round_trip<B: Backend + Clone>(backend: B) {
    let key = cipher(1);
    assert_eq!(
        Store::open(backend.clone(), &key, "community")
            .await
            .unwrap_err(),
        Error::NotInitialized
    );
    let mut store = Store::create(backend.clone(), &key, "community")
        .await
        .unwrap();
    assert_eq!(
        Store::create(backend.clone(), &key, "community")
            .await
            .unwrap_err(),
        Error::AlreadyInitialized
    );
    let output = Output {
        id: [8; 32],
        bytes: b"exact pending ciphertext".to_vec(),
    };
    store
        .commit(
            0,
            [1; 32],
            &changes(b"accepted opening", b"MLS and history"),
            &[output],
        )
        .await
        .unwrap();
    assert!(store.is_scope("community"));
    assert!(!store.is_scope("other"));
    assert_eq!(store.version().unwrap(), 1);
    assert_eq!(store.operation().unwrap(), [1; 32]);
    let bytes = backend.read().await.unwrap().unwrap();
    for plaintext in [
        b"accepted opening".as_slice(),
        b"MLS and history",
        b"wallet",
        b"exact pending ciphertext",
    ] {
        assert!(!bytes.windows(plaintext.len()).any(|s| s == plaintext));
    }
    store.lock();
    let mut reopened = Store::open(backend.clone(), &key, "community")
        .await
        .unwrap();
    assert_eq!(
        reopened.read("wallet", b"state").unwrap(),
        Some(b"accepted opening".as_slice())
    );
    assert_eq!(
        reopened.read("threads", b"state").unwrap(),
        Some(b"MLS and history".as_slice())
    );
    assert!(reopened.read("contacts", b"state").unwrap().is_none());
    assert_eq!(
        reopened.load_pending().unwrap()[0].bytes,
        b"exact pending ciphertext"
    );
    reopened.ack_output(1, [2; 32], [8; 32]).await.unwrap();
    assert!(reopened.load_pending().unwrap().is_empty());
    assert_eq!(
        reopened.ack_output(2, [3; 32], [8; 32]).await.unwrap_err(),
        Error::Invalid
    );
    reopened
        .commit(
            2,
            [3; 32],
            &[Change::Delete {
                owner: "wallet",
                key: b"state",
            }],
            &[],
        )
        .await
        .unwrap();
    assert!(reopened.read("wallet", b"state").unwrap().is_none());
    assert_eq!(
        Store::open(backend.clone(), &cipher(2), "community")
            .await
            .unwrap_err(),
        Error::Unlock
    );
    assert_eq!(
        Store::open(backend.clone(), &key, "another-scope")
            .await
            .unwrap_err(),
        Error::Unlock
    );
}
test_async!(memory_round_trip, {
    round_trip(Memory::new()).await;
});

test_async!(fence_competing_writers, {
    let backend = Memory::new();
    let key = cipher(1);
    let mut left = Store::create(backend.clone(), &key, "s").await.unwrap();
    let mut right = Store::open(backend.clone(), &key, "s").await.unwrap();
    left.commit(0, [1; 32], &changes(b"left-wallet", b"left-MLS"), &[])
        .await
        .unwrap();
    assert_eq!(
        right
            .commit(0, [2; 32], &changes(b"right-wallet", b"right-MLS"), &[])
            .await
            .unwrap_err(),
        Error::Conflict
    );
    assert_eq!(right.version().unwrap_err(), Error::Locked);
    let winner = Store::open(backend, &key, "s").await.unwrap();
    assert_eq!(
        winner.read("wallet", b"state").unwrap().unwrap(),
        b"left-wallet"
    );
    assert_eq!(
        winner.read("threads", b"state").unwrap().unwrap(),
        b"left-MLS"
    );
    assert_eq!(
        left.commit(0, [3; 32], &[], &[]).await.unwrap_err(),
        Error::Conflict
    );
});

test_async!(corruption_and_limits, {
    let backend = Memory::new();
    let key = cipher(1);
    assert_eq!(
        Store::create(backend.clone(), &key, "").await.unwrap_err(),
        Error::Invalid
    );
    let mut store = Store::create(backend.clone(), &key, "s").await.unwrap();
    assert_eq!(
        store.commit(0, [0; 32], &[], &[]).await.unwrap_err(),
        Error::Invalid
    );
    assert_eq!(store.read("", b"k").unwrap_err(), Error::Invalid);
    assert_eq!(store.read("a", b"").unwrap_err(), Error::Invalid);
    assert_eq!(
        store.read(&"a".repeat(257), b"k").unwrap_err(),
        Error::Invalid
    );
    assert_eq!(store.read("a", &[0; 257]).unwrap_err(), Error::Invalid);
    let big = vec![0; cwst::MAX_VALUE_BYTES + 1];
    assert_eq!(
        store
            .commit(
                0,
                [1; 32],
                &[Change::Put {
                    owner: "a",
                    key: b"k",
                    value: &big
                }],
                &[]
            )
            .await
            .unwrap_err(),
        Error::TooLarge
    );
    assert_eq!(
        store
            .commit(
                0,
                [1; 32],
                &[],
                &[Output {
                    id: [1; 32],
                    bytes: big
                }]
            )
            .await
            .unwrap_err(),
        Error::TooLarge
    );
    let duplicate = Output {
        id: [1; 32],
        bytes: vec![],
    };
    assert_eq!(
        store
            .commit(0, [1; 32], &[], &[duplicate.clone(), duplicate])
            .await
            .unwrap_err(),
        Error::Invalid
    );
    assert_eq!(store.version().unwrap(), 0);
    let original = backend.read().await.unwrap().unwrap();
    for pos in [0, 20, original.len() - 1] {
        let mut changed = original.clone();
        changed[pos] ^= 1;
        backend
            .compare_exchange(Some(&original), &changed)
            .await
            .unwrap();
        assert!(Store::open(backend.clone(), &key, "s").await.is_err());
        backend
            .compare_exchange(Some(&changed), &original)
            .await
            .unwrap();
    }
    backend
        .compare_exchange(Some(&original), b"truncated")
        .await
        .unwrap();
    assert_eq!(
        Store::open(backend.clone(), &key, "s").await.unwrap_err(),
        Error::Corrupt
    );
    assert_eq!(
        backend.compare_exchange(None, b"").await.unwrap_err(),
        Error::TooLarge
    );
    assert_eq!(
        backend
            .compare_exchange(None, &vec![0; cwst::MAX_CHECKPOINT_BYTES + 1])
            .await
            .unwrap_err(),
        Error::TooLarge
    );
    assert_eq!(format!("{store:?}"), "Store([redacted])");
    assert_eq!(format!("{}", Error::Storage), "storage: Storage");
});

// Faults wrap a real database, never replacing encryption or transaction logic.
#[derive(Clone)]
struct Faults {
    inner: Memory,
    mode: std::rc::Rc<std::cell::Cell<u8>>,
}
impl Backend for Faults {
    async fn read(&self) -> Result<Option<Vec<u8>>, Error> {
        if self.mode.get() == 1 {
            return Err(Error::Storage);
        }
        self.inner.read().await
    }
    async fn compare_exchange(&self, expected: Option<&[u8]>, next: &[u8]) -> Result<(), Error> {
        if self.mode.get() == 2 {
            return Err(Error::Storage);
        }
        self.inner.compare_exchange(expected, next).await?;
        if self.mode.get() == 3 {
            return Err(Error::Uncertain);
        }
        if self.mode.get() == 4 {
            futures::future::pending::<()>().await;
        }
        Ok(())
    }
}
test_async!(crash_and_cancel_reconcile_exact_outputs, {
    use futures::FutureExt;
    let mode = std::rc::Rc::new(std::cell::Cell::new(0));
    let backend = Faults {
        inner: Memory::new(),
        mode: mode.clone(),
    };
    let key = cipher(1);
    let mut store = Store::create(backend.clone(), &key, "s").await.unwrap();
    mode.set(1);
    assert_eq!(
        Store::open(backend.clone(), &key, "s").await.unwrap_err(),
        Error::Storage
    );
    mode.set(2);
    assert_eq!(
        store
            .commit(0, [2; 32], &changes(b"no", b"no"), &[])
            .await
            .unwrap_err(),
        Error::Storage
    );
    mode.set(0);
    store = Store::open(backend.clone(), &key, "s").await.unwrap();
    assert_eq!(store.version().unwrap(), 0);
    mode.set(3);
    assert_eq!(
        store
            .commit(
                0,
                [3; 32],
                &changes(b"yes", b"yes"),
                &[Output {
                    id: [3; 32],
                    bytes: vec![9]
                }]
            )
            .await
            .unwrap_err(),
        Error::Uncertain
    );
    assert_eq!(store.read("wallet", b"state").unwrap_err(), Error::Locked);
    mode.set(0);
    store = Store::open(backend.clone(), &key, "s").await.unwrap();
    assert_eq!(store.operation().unwrap(), [3; 32]);
    assert_eq!(store.load_pending().unwrap()[0].bytes, vec![9]);
    mode.set(4);
    assert!(
        store
            .ack_output(1, [4; 32], [3; 32])
            .now_or_never()
            .is_none()
    );
    assert_eq!(store.version().unwrap_err(), Error::Locked);
    mode.set(0);
    store = Store::open(backend, &key, "s").await.unwrap();
    assert_eq!(store.operation().unwrap(), [4; 32]);
    assert!(store.load_pending().unwrap().is_empty());
});

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn native_round_trip_and_process_safe_fence() {
    futures_executor::block_on(async {
        let dir = tempfile::tempdir().unwrap();
        let backend = cwst::native::FileBackend::new(dir.path());
        round_trip(backend.clone()).await;
        let original = backend.read().await.unwrap().unwrap();
        let threads: Vec<_> = (0..4)
            .map(|n| {
                let backend = backend.clone();
                let original = original.clone();
                std::thread::spawn(move || {
                    futures_executor::block_on(backend.compare_exchange(Some(&original), &[n + 1]))
                })
            })
            .collect();
        assert_eq!(
            threads
                .into_iter()
                .filter_map(|t| t.join().unwrap().ok())
                .count(),
            1
        );
        assert_eq!(
            Store::open(backend, &cipher(1), "community")
                .await
                .unwrap_err(),
            Error::Corrupt
        );
    });
}
#[cfg(not(target_arch = "wasm32"))]
#[test]
fn native_failures_are_not_absence() {
    futures_executor::block_on(async {
        let dir = tempfile::tempdir().unwrap();
        let absent = cwst::native::FileBackend::new(dir.path().join("missing-parent"));
        assert_eq!(absent.read().await.unwrap_err(), Error::Storage);
        assert_eq!(
            absent.compare_exchange(None, b"x").await.unwrap_err(),
            Error::Storage
        );
        let db = cwst::native::FileBackend::new(dir.path());
        std::fs::create_dir(dir.path().join("checkpoint")).unwrap();
        assert_eq!(db.read().await.unwrap_err(), Error::Storage);
    });
}
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen_test::wasm_bindgen_test]
async fn actual_indexeddb_round_trip_and_race() {
    let name = format!("cwst-test-{}", js_sys::Date::now());
    let backend = cwst::browser::IndexedDb::open(&name).await.unwrap();
    round_trip(backend.clone()).await;
    let other = cwst::browser::IndexedDb::open(&name).await.unwrap();
    let original = backend.read().await.unwrap().unwrap();
    let (a, b) = futures::join!(
        backend.compare_exchange(Some(&original), b"one"),
        other.compare_exchange(Some(&original), b"two")
    );
    assert_eq!(usize::from(a.is_ok()) + usize::from(b.is_ok()), 1);
    drop(backend);
    drop(other);
    keyvaluedb_web::Database::delete(&name).await.unwrap();
}

test_async!(compound_limits_and_replacements, {
    let backend = Memory::new();
    let mut store = Store::create(backend.clone(), &cipher(1), "s")
        .await
        .unwrap();
    let many: Vec<_> = (0..cwst::MAX_RECORDS + 1)
        .map(|_| Change::Delete {
            owner: "a",
            key: b"k",
        })
        .collect();
    assert_eq!(
        store.commit(0, [1; 32], &many, &[]).await.unwrap_err(),
        Error::Invalid
    );
    let output = Output {
        id: [1; 32],
        bytes: vec![1],
    };
    assert_eq!(format!("{output:?}"), "Output([redacted])");
    assert_eq!(
        store
            .commit(
                0,
                [1; 32],
                &[],
                &vec![output.clone(); cwst::MAX_OUTPUTS + 1]
            )
            .await
            .unwrap_err(),
        Error::Invalid
    );
    let large = vec![7; cwst::MAX_VALUE_BYTES];
    assert_eq!(
        store
            .commit(0, [1; 32], &changes(&large, &large), &[])
            .await
            .unwrap_err(),
        Error::TooLarge
    );
    store
        .commit(0, [1; 32], &changes(b"first", b"first"), &[output])
        .await
        .unwrap();
    assert_eq!(
        store.ack_output(0, [2; 32], [1; 32]).await.unwrap_err(),
        Error::Conflict
    );
    assert_eq!(
        store.ack_output(1, [0; 32], [1; 32]).await.unwrap_err(),
        Error::Invalid
    );
    store
        .commit(1, [2; 32], &changes(b"second", b"second"), &[])
        .await
        .unwrap();
    assert_eq!(
        store.read("wallet", b"state").unwrap(),
        Some(b"second".as_slice())
    );
    let original = backend.read().await.unwrap().unwrap();
    let header_only = &original[..20];
    backend
        .compare_exchange(Some(&original), header_only)
        .await
        .unwrap();
    assert_eq!(
        Store::open(backend, &cipher(1), "s").await.unwrap_err(),
        Error::Corrupt
    );
});

#[cfg(unix)]
#[test]
fn native_unreadable_and_oversized_files() {
    futures_executor::block_on(async {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("checkpoint");
        let db = cwst::native::FileBackend::new(dir.path());
        std::os::unix::fs::symlink("checkpoint", &path).unwrap();
        assert_eq!(db.read().await.unwrap_err(), Error::Storage);
        std::fs::remove_file(&path).unwrap();
        std::fs::write(&path, vec![0; cwst::MAX_CHECKPOINT_BYTES + 1]).unwrap();
        assert_eq!(db.read().await.unwrap_err(), Error::TooLarge);
    });
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn native_crash_child() {
    let Some(directory) = std::env::var_os("CWST_CRASH_TEST_DIRECTORY") else {
        return;
    };
    futures_executor::block_on(async {
        let backend = cwst::native::FileBackend::new(&directory);
        let mut store = Store::create(backend, &cipher(1), "crash").await.unwrap();
        for n in 1..=63u8 {
            let value = vec![n; 32 * 1024];
            let expected = store.version().unwrap();
            store
                .commit(
                    expected,
                    [n; 32],
                    &changes(&value, &value),
                    &[Output {
                        id: [n; 32],
                        bytes: vec![n],
                    }],
                )
                .await
                .unwrap();
            std::fs::write(std::path::Path::new(&directory).join("ready"), [n]).unwrap();
        }
        std::thread::sleep(std::time::Duration::from_secs(10));
    });
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn native_process_kill_preserves_whole_checkpoint() {
    for _ in 0..3 {
        let dir = tempfile::tempdir().unwrap();
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "native_crash_child", "--nocapture"])
            .env("CWST_CRASH_TEST_DIRECTORY", dir.path())
            .stdout(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while !dir.path().join("ready").exists() && std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
        child.kill().unwrap();
        child.wait().unwrap();
        assert!(dir.path().join("ready").exists());
        futures_executor::block_on(async {
            let store = Store::open(
                cwst::native::FileBackend::new(dir.path()),
                &cipher(1),
                "crash",
            )
            .await
            .unwrap();
            let wallet = store.read("wallet", b"state").unwrap().unwrap();
            assert_eq!(store.read("threads", b"state").unwrap().unwrap(), wallet);
            assert_eq!(
                store.load_pending().unwrap().last().unwrap().bytes,
                vec![wallet[0]]
            );
            assert_eq!(store.operation().unwrap(), [wallet[0]; 32]);
        });
    }
}

test_async!(aggregate_checkpoint_bound_across_commits, {
    let mut store = Store::create(Memory::new(), &cipher(1), "s").await.unwrap();
    let value = vec![1; cwst::MAX_VALUE_BYTES];
    store
        .commit(
            0,
            [1; 32],
            &[Change::Put {
                owner: "a",
                key: b"a",
                value: &value,
            }],
            &[],
        )
        .await
        .unwrap();
    assert_eq!(
        store
            .commit(
                1,
                [2; 32],
                &[Change::Put {
                    owner: "b",
                    key: b"b",
                    value: &value
                }],
                &[]
            )
            .await
            .unwrap_err(),
        Error::TooLarge
    );
    assert_eq!(store.version().unwrap(), 1);
});
