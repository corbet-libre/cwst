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
    assert!(store.receipt(&[0; 32]).is_err());
    let receipt = store
        .commit_with_receipt(
            0,
            [1; 32],
            &changes(b"accepted opening", b"MLS and history"),
            &[output],
        )
        .await
        .unwrap();
    assert!(receipt.is_commit(&store, &[1; 32]));
    assert!(!receipt.is_commit(&store, &[2; 32]));
    assert_eq!(receipt.version(), 1);
    assert!(receipt.contains_record(
        "wallet",
        b"state",
        blake3::hash(b"accepted opening").as_bytes()
    ));
    assert!(!receipt.contains_record(
        "wallet",
        b"other",
        blake3::hash(b"accepted opening").as_bytes()
    ));
    assert!(!receipt.contains_record("wallet", b"state", blake3::hash(b"other").as_bytes()));
    assert!(receipt.contains_output(
        &[8; 32],
        blake3::hash(b"exact pending ciphertext").as_bytes()
    ));
    assert!(!receipt.contains_output(
        &[9; 32],
        blake3::hash(b"exact pending ciphertext").as_bytes()
    ));
    assert!(!receipt.contains_output(&[8; 32], blake3::hash(b"other").as_bytes()));
    assert_eq!(format!("{receipt:?}"), "CommitReceipt([redacted])");
    let mut foreign = Store::create(Memory::new(), &key, "community")
        .await
        .unwrap();
    foreign
        .commit(
            0,
            [1; 32],
            &changes(b"accepted opening", b"MLS and history"),
            &[],
        )
        .await
        .unwrap();
    assert!(!receipt.is_commit(&foreign, &[1; 32]));
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
    store.lock_in_place();
    assert!(!receipt.is_commit(&store, &[1; 32]));
    assert!(store.receipt(&[1; 32]).is_err());
    let mut reopened = Store::open(backend.clone(), &key, "community")
        .await
        .unwrap();
    assert!(receipt.is_commit(&reopened, &[1; 32]));
    assert!(
        reopened
            .receipt(&[1; 32])
            .unwrap()
            .is_commit(&reopened, &[1; 32])
    );
    assert!(reopened.receipt(&[9; 32]).is_err());
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
    assert!(!receipt.is_commit(&reopened, &[1; 32]));
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

test_async!(receipt_binds_final_mutation_not_an_overwritten_candidate, {
    let mut store = Store::create(Memory::new(), &cipher(1), "community")
        .await
        .unwrap();
    let receipt = store
        .commit_with_receipt(
            0,
            [1; 32],
            &[
                Change::Put {
                    owner: "wallet",
                    key: b"state",
                    value: b"candidate",
                },
                Change::Put {
                    owner: "wallet",
                    key: b"state",
                    value: b"replacement",
                },
            ],
            &[],
        )
        .await
        .unwrap();
    assert!(!receipt.contains_record("wallet", b"state", blake3::hash(b"candidate").as_bytes()));
    assert!(receipt.contains_record("wallet", b"state", blake3::hash(b"replacement").as_bytes()));
    let receipt = store
        .commit_with_receipt(
            1,
            [2; 32],
            &[
                Change::Put {
                    owner: "wallet",
                    key: b"state",
                    value: b"candidate",
                },
                Change::Delete {
                    owner: "wallet",
                    key: b"state",
                },
            ],
            &[],
        )
        .await
        .unwrap();
    assert!(!receipt.contains_record("wallet", b"state", blake3::hash(b"candidate").as_bytes()));
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
            .commit_with_receipt(0, [2; 32], &changes(b"no", b"no"), &[])
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
            .commit_with_receipt(
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
    assert_eq!(store.receipt(&[3; 32]).unwrap_err(), Error::Locked);
    mode.set(0);
    store = Store::open(backend.clone(), &key, "s").await.unwrap();
    assert_eq!(store.operation().unwrap(), [3; 32]);
    assert!(store.receipt(&[3; 32]).unwrap().contains_record(
        "wallet",
        b"state",
        blake3::hash(b"yes").as_bytes()
    ));
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
fn native_dangling_checkpoint_is_not_absence() {
    futures_executor::block_on(async {
        for target in ["missing-checkpoint", "missing-parent/checkpoint"] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("checkpoint");
            std::os::unix::fs::symlink(target, &path).unwrap();
            let backend = cwst::native::FileBackend::new(dir.path());
            let key = cipher(1);
            let assert_unchanged = || {
                assert!(std::fs::symlink_metadata(&path).unwrap().is_symlink());
                assert_eq!(
                    std::fs::read_link(&path).unwrap(),
                    std::path::Path::new(target)
                );
                assert_eq!(
                    std::fs::symlink_metadata(dir.path().join(target))
                        .unwrap_err()
                        .kind(),
                    std::io::ErrorKind::NotFound
                );
                if target.starts_with("missing-parent/") {
                    assert_eq!(
                        std::fs::symlink_metadata(dir.path().join("missing-parent"))
                            .unwrap_err()
                            .kind(),
                        std::io::ErrorKind::NotFound
                    );
                }
            };

            assert_eq!(backend.read().await.unwrap_err(), Error::Storage);
            assert_unchanged();
            assert_eq!(
                Store::open(backend.clone(), &key, "community")
                    .await
                    .unwrap_err(),
                Error::Storage
            );
            assert_unchanged();
            assert_eq!(
                Store::create(backend.clone(), &key, "community")
                    .await
                    .unwrap_err(),
                Error::Storage
            );
            assert_unchanged();
            assert_eq!(
                backend
                    .compare_exchange(None, b"replacement")
                    .await
                    .unwrap_err(),
                Error::Storage
            );
            assert_unchanged();

            // Only explicit removal of the unreadable entry permits initialization.
            std::fs::remove_file(&path).unwrap();
            let store = Store::create(backend.clone(), &key, "community")
                .await
                .unwrap();
            assert_eq!(store.version().unwrap(), 0);
            assert!(std::fs::symlink_metadata(&path).unwrap().is_file());
            assert_eq!(
                Store::open(backend, &key, "community")
                    .await
                    .unwrap()
                    .version()
                    .unwrap(),
                0
            );
        }
    });
}

#[cfg(unix)]
#[test]
fn native_absent_checkpoint_allows_initialization() {
    futures_executor::block_on(async {
        for through_symlink in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let directory = dir.path().join("store");
            std::fs::create_dir(&directory).unwrap();
            let alias = dir.path().join("store-alias");
            let backend = if through_symlink {
                std::os::unix::fs::symlink(&directory, &alias).unwrap();
                cwst::native::FileBackend::new(&alias)
            } else {
                cwst::native::FileBackend::new(&directory)
            };
            let key = cipher(1);
            assert!(backend.read().await.unwrap().is_none());
            assert_eq!(
                Store::open(backend.clone(), &key, "community")
                    .await
                    .unwrap_err(),
                Error::NotInitialized
            );
            let store = Store::create(backend.clone(), &key, "community")
                .await
                .unwrap();
            assert_eq!(store.version().unwrap(), 0);
            let checkpoint = backend.read().await.unwrap().unwrap();

            let cas_directory = dir.path().join("cas-store");
            std::fs::create_dir(&cas_directory).unwrap();
            let cas = cwst::native::FileBackend::new(&cas_directory);
            cas.compare_exchange(None, &checkpoint).await.unwrap();
            assert_eq!(cas.read().await.unwrap().unwrap(), checkpoint);
            assert_eq!(
                Store::open(cas, &key, "community")
                    .await
                    .unwrap()
                    .version()
                    .unwrap(),
                0
            );
        }
    });
}

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

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen::prelude::wasm_bindgen(inline_js = "
export function abortNextDatabaseUpgrade(name) {
    const original = IDBFactory.prototype.open;
    IDBFactory.prototype.open = function(...args) {
        const request = original.apply(this, args);
        if (args[0] === name) {
            IDBFactory.prototype.open = original;
            request.addEventListener('upgradeneeded', () => request.transaction.abort(), {once: true});
        }
        return request;
    };
}
")]
extern "C" {
    #[wasm_bindgen::prelude::wasm_bindgen(js_name = abortNextDatabaseUpgrade)]
    fn abort_next_database_upgrade(name: &str);
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen_test::wasm_bindgen_test]
async fn indexeddb_bounds_and_deleted_database_refuse() {
    assert!(matches!(
        cwst::browser::IndexedDb::open("").await,
        Err(Error::Invalid)
    ));
    assert!(matches!(
        cwst::browser::IndexedDb::open(&"x".repeat(257)).await,
        Err(Error::Invalid)
    ));
    // Abort a real platform upgrade transaction. The upstream adapter must
    // propagate the actual IndexedDB AbortError as a coarse storage failure.
    let refused = format!("cwst-aborted-upgrade-{}", js_sys::Date::now());
    abort_next_database_upgrade(&refused);
    assert!(matches!(
        cwst::browser::IndexedDb::open(&refused).await,
        Err(Error::Storage)
    ));
    assert!(!keyvaluedb_web::Database::delete(&refused).await.unwrap());
    let name = format!("cwst-deletion-{}", js_sys::Date::now());
    let backend = cwst::browser::IndexedDb::open(&name).await.unwrap();
    keyvaluedb_web::Database::delete(&name).await.unwrap();
    assert_eq!(backend.read().await.unwrap_err(), Error::Storage);
    assert_eq!(
        backend
            .compare_exchange(None, b"replacement")
            .await
            .unwrap_err(),
        Error::Uncertain
    );
}

// Link the maintained profiling runtime only into the instrumented test binary.
#[cfg(all(target_arch = "wasm32", owned_browser_coverage))]
#[wasm_bindgen_test::wasm_bindgen_test]
fn profiling_runtime_is_linked() {
    let _ = browser_coverage_runtime::__owned_test_module_signature();
}

test_async!(live_owner_reads_follow_only_completed_commits, {
    let backend = Memory::new();
    let key = cipher(1);
    let mut store = Store::create(backend.clone(), &key, "s").await.unwrap();
    assert!(matches!(store.read_handle(""), Err(Error::Invalid)));
    assert!(matches!(
        store.read_handle(&"x".repeat(cwst::MAX_KEY_BYTES + 1)),
        Err(Error::Invalid)
    ));
    let reader = store.read_handle("wallet").unwrap();
    let other = store.read_handle("other").unwrap();
    assert!(reader.is_scope("s"));
    assert!(!reader.is_scope("other"));
    assert_eq!(reader.read(b"state", 0).unwrap(), None);
    assert_eq!(reader.read(b"", 10), Err(Error::Invalid));
    assert_eq!(format!("{reader:?}"), "ReadHandle([redacted])");
    store
        .commit(0, [1; 32], &changes(b"first", b"elsewhere"), &[])
        .await
        .unwrap();
    assert_eq!(reader.read(b"state", 5).unwrap(), Some(b"first".to_vec()));
    assert_eq!(reader.read(b"state", 4), Err(Error::TooLarge));
    assert_eq!(other.read(b"state", 100).unwrap(), None);
    // Refused candidates leave the actual committed view unchanged.
    assert_eq!(
        store.commit(0, [2; 32], &[], &[]).await,
        Err(Error::Conflict)
    );
    assert_eq!(reader.read(b"state", 5).unwrap(), Some(b"first".to_vec()));
    store
        .commit(1, [2; 32], &changes(b"second", b"new"), &[])
        .await
        .unwrap();
    assert_eq!(reader.read(b"state", 6).unwrap(), Some(b"second".to_vec()));
    store
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
    assert_eq!(reader.read(b"state", 0).unwrap(), None);
    store.lock_in_place();
    assert_eq!(reader.read(b"state", 100), Err(Error::Locked));
    assert_eq!(
        store.read_handle("wallet").unwrap().read(b"state", 100),
        Err(Error::Locked)
    );
    let reopened = Store::open(backend, &key, "s").await.unwrap();
    let reopened_reader = reopened.read_handle("threads").unwrap();
    assert_eq!(
        reopened_reader.read(b"state", 3).unwrap(),
        Some(b"new".to_vec())
    );
    assert_eq!(reader.read(b"state", 100), Err(Error::Locked));
    drop(reopened);
    assert_eq!(reopened_reader.read(b"state", 100), Err(Error::Locked));
});

test_async!(
    live_owner_reads_revoke_during_uncertain_or_cancelled_writes,
    {
        use futures::FutureExt;
        for fault in [2, 3, 4] {
            let mode = std::rc::Rc::new(std::cell::Cell::new(0));
            let backend = Faults {
                inner: Memory::new(),
                mode: mode.clone(),
            };
            let key = cipher(1);
            let mut store = Store::create(backend.clone(), &key, "s").await.unwrap();
            store
                .commit(0, [1; 32], &changes(b"before", b"before"), &[])
                .await
                .unwrap();
            let reader = store.read_handle("wallet").unwrap();
            mode.set(fault);
            let changes = changes(b"after", b"after");
            let mut pending = Box::pin(store.commit(1, [2; 32], &changes, &[]));
            let outcome = pending.as_mut().now_or_never();
            assert_eq!(
                outcome,
                match fault {
                    2 => Some(Err(Error::Storage)),
                    3 => Some(Err(Error::Uncertain)),
                    _ => None,
                }
            );
            // Polling may already have durably written bytes; until the real CAS
            // returns success, neither those bytes nor the old snapshot is readable.
            assert_eq!(reader.read(b"state", 100), Err(Error::Locked));
            drop(pending);
            assert_eq!(reader.read(b"state", 100), Err(Error::Locked));
            assert_eq!(store.version(), Err(Error::Locked));
            mode.set(0);
            let reopened = Store::open(backend, &key, "s").await.unwrap();
            let actual = reopened.read_handle("wallet").unwrap();
            let expected = if fault == 2 {
                b"before".as_slice()
            } else {
                b"after".as_slice()
            };
            assert_eq!(
                actual.read(b"state", 100).unwrap().as_deref(),
                Some(expected)
            );
            assert_eq!(reader.read(b"state", 100), Err(Error::Locked));
        }
    }
);

test_async!(
    receipt_binds_scope_version_and_operation_of_the_current_checkpoint,
    {
        let key = cipher(1);
        let mut store = Store::create(Memory::new(), &key, "community")
            .await
            .unwrap();
        let receipt = store
            .commit_with_receipt(0, [1; 32], &changes(b"a", b"b"), &[])
            .await
            .unwrap();
        assert!(receipt.is_commit(&store, &[1; 32]));
        // Another scope never adopts this receipt, even with the same key material.
        let other = Store::create(Memory::new(), &key, "other-community")
            .await
            .unwrap();
        assert!(!receipt.is_commit(&other, &[1; 32]));
        // Committing the same operation identifier again moves the version fence.
        store
            .commit(1, [1; 32], &changes(b"c", b"d"), &[])
            .await
            .unwrap();
        assert!(!receipt.is_commit(&store, &[1; 32]));
    }
);

test_async!(
    consuming_lock_wipes_the_state_and_leaves_the_backend_reopenable,
    {
        let backend = Memory::new();
        let key = cipher(1);
        let mut store = Store::create(backend.clone(), &key, "community")
            .await
            .unwrap();
        store
            .commit(0, [1; 32], &changes(b"a", b"b"), &[])
            .await
            .unwrap();
        store.lock();
        let reopened = Store::open(backend, &key, "community").await.unwrap();
        assert_eq!(reopened.version().unwrap(), 1);
    }
);

test_async!(
    retained_compound_wire_restores_exact_owners_outputs_and_fences,
    {
        let key = cipher(7);
        let source = Memory::new();
        let mut original = Store::create(source.clone(), &key, "restore")
            .await
            .unwrap();
        original
            .commit(
                0,
                [41; 32],
                &changes(b"wallet-original", b"threads-original"),
                &[Output {
                    id: [42; 32],
                    bytes: b"outbox-original".to_vec(),
                }],
            )
            .await
            .unwrap();
        let wire = original.sealed_checkpoint().unwrap().to_vec();
        assert_eq!(source.read().await.unwrap().unwrap(), wire);
        let destination = Memory::new();
        let restored = Store::restore(destination.clone(), &key, "restore", 1, &wire)
            .await
            .unwrap();
        assert_eq!(restored.sealed_checkpoint().unwrap(), wire);
        assert_eq!(restored.operation().unwrap(), [41; 32]);
        assert_eq!(
            restored.read("wallet", b"state").unwrap().unwrap(),
            b"wallet-original"
        );
        assert_eq!(
            restored.read("threads", b"state").unwrap().unwrap(),
            b"threads-original"
        );
        assert_eq!(
            restored.load_pending().unwrap()[0].bytes,
            b"outbox-original"
        );
        restored.lock();
        assert_eq!(
            Store::open(destination.clone(), &key, "restore")
                .await
                .unwrap()
                .version()
                .unwrap(),
            1
        );
        assert_eq!(
            Store::restore(destination.clone(), &key, "restore", 1, &wire)
                .await
                .unwrap_err(),
            Error::AlreadyInitialized
        );
        assert_eq!(destination.read().await.unwrap().unwrap(), wire);
        for (scope, expected, bytes) in [
            ("wrong", 1, wire.clone()),
            ("restore", 0, wire.clone()),
            ("restore", 1, {
                let mut bad = wire.clone();
                *bad.last_mut().unwrap() ^= 1;
                bad
            }),
            ("restore", 1, vec![]),
            ("restore", 1, vec![0; cwst::MAX_CHECKPOINT_BYTES + 1]),
        ] {
            let empty = Memory::new();
            assert!(
                Store::restore(empty.clone(), &key, scope, expected, &bytes)
                    .await
                    .is_err()
            );
            assert!(empty.read().await.unwrap().is_none());
        }
        let empty = Memory::new();
        assert!(
            Store::restore(empty.clone(), &cipher(8), "restore", 1, &wire)
                .await
                .is_err()
        );
        assert!(empty.read().await.unwrap().is_none());
        original.lock_in_place();
        assert_eq!(original.sealed_checkpoint(), Err(Error::Locked));
    }
);

test_async!(
    retained_restore_unknown_and_cancelled_cas_reopen_original_bytes,
    {
        use futures::FutureExt;
        let key = cipher(7);
        let original = Store::create(Memory::new(), &key, "restore").await.unwrap();
        let wire = original.sealed_checkpoint().unwrap().to_vec();
        for fault in [2, 3, 4] {
            let mode = std::rc::Rc::new(std::cell::Cell::new(fault));
            let backend = Faults {
                inner: Memory::new(),
                mode: mode.clone(),
            };
            let mut pending = Box::pin(Store::restore(backend.clone(), &key, "restore", 0, &wire));
            match pending.as_mut().now_or_never() {
                Some(Err(Error::Storage)) if fault == 2 => {}
                Some(Err(Error::Uncertain)) if fault == 3 => {}
                None if fault == 4 => {}
                _ => panic!("unexpected restore outcome"),
            }
            drop(pending);
            mode.set(0);
            if fault == 2 {
                assert!(backend.read().await.unwrap().is_none());
            } else {
                assert_eq!(
                    Store::open(backend, &key, "restore")
                        .await
                        .unwrap()
                        .sealed_checkpoint()
                        .unwrap(),
                    wire
                );
            }
        }
        let destination = Memory::new();
        let (one, two) = futures::join!(
            Store::restore(destination.clone(), &key, "restore", 0, &wire),
            Store::restore(destination.clone(), &key, "restore", 0, &wire)
        );
        assert!(one.is_ok() ^ two.is_ok());
        assert_eq!(one.err().or(two.err()).unwrap(), Error::AlreadyInitialized);
    }
);

test_async!(
    restore_checked_enforces_keys_digest_before_destination_cas,
    {
        #[derive(Clone)]
        struct Counting {
            inner: Memory,
            writes: std::rc::Rc<std::cell::Cell<usize>>,
        }
        impl Backend for Counting {
            async fn read(&self) -> Result<Option<Vec<u8>>, Error> {
                self.inner.read().await
            }
            async fn compare_exchange(
                &self,
                expected: Option<&[u8]>,
                next: &[u8],
            ) -> Result<(), Error> {
                self.writes.set(self.writes.get() + 1);
                self.inner.compare_exchange(expected, next).await
            }
        }
        let key = cipher(7);
        let mut original = Store::create(Memory::new(), &key, "restore").await.unwrap();
        original
            .commit(
                0,
                [41; 32],
                &[
                    Change::Put {
                        owner: "keys",
                        key: b"wraps",
                        value: b"selected-keys",
                    },
                    Change::Put {
                        owner: "wallet",
                        key: b"state",
                        value: b"wallet-original",
                    },
                ],
                &[Output {
                    id: [42; 32],
                    bytes: b"outbox-original".to_vec(),
                }],
            )
            .await
            .unwrap();
        let wire = original.sealed_checkpoint().unwrap().to_vec();
        let expected = *blake3::hash(b"selected-keys").as_bytes();
        let writes = std::rc::Rc::new(std::cell::Cell::new(0));
        let destination = Counting {
            inner: Memory::new(),
            writes: writes.clone(),
        };
        // Wrong expected Keys digest rejects before any destination CAS.
        let wrong = *blake3::hash(b"other-keys").as_bytes();
        assert_eq!(
            Store::restore_checked(destination.clone(), &key, "restore", 1, &wire, |checked| {
                let actual = checked.read("keys", b"wraps").unwrap().unwrap();
                if blake3::hash(actual).as_bytes() != &wrong {
                    return Err(Error::Invalid);
                }
                Ok(())
            })
            .await
            .unwrap_err(),
            Error::Invalid
        );
        assert!(destination.read().await.unwrap().is_none());
        assert_eq!(writes.get(), 0);
        // A checkpoint without the selected keys entry rejects the same way.
        let mut bare = Store::create(Memory::new(), &key, "restore").await.unwrap();
        bare.commit(0, [43; 32], &changes(b"wallet-only", b"threads-only"), &[])
            .await
            .unwrap();
        let bare_wire = bare.sealed_checkpoint().unwrap().to_vec();
        assert_eq!(
            Store::restore_checked(
                destination.clone(),
                &key,
                "restore",
                1,
                &bare_wire,
                |checked| {
                    if checked.read("keys", b"wraps").unwrap().is_none() {
                        return Err(Error::Invalid);
                    }
                    Ok(())
                }
            )
            .await
            .unwrap_err(),
            Error::Invalid
        );
        assert!(destination.read().await.unwrap().is_none());
        assert_eq!(writes.get(), 0);
        // The matching digest restores the exact version and bytes without overwrite.
        let restored =
            Store::restore_checked(destination.clone(), &key, "restore", 1, &wire, |checked| {
                let actual = checked.read("keys", b"wraps").unwrap().unwrap();
                if blake3::hash(actual).as_bytes() != &expected {
                    return Err(Error::Invalid);
                }
                if checked.read("wallet", b"state").unwrap() != Some(b"wallet-original".as_slice())
                {
                    return Err(Error::Invalid);
                }
                let pending = checked.load_pending().unwrap();
                if pending.len() != 1
                    || pending[0].id != [42; 32]
                    || pending[0].bytes.as_slice() != b"outbox-original".as_slice()
                {
                    return Err(Error::Invalid);
                }
                Ok(())
            })
            .await
            .unwrap();
        assert_eq!(restored.version().unwrap(), 1);
        assert_eq!(restored.operation().unwrap(), [41; 32]);
        assert_eq!(restored.sealed_checkpoint().unwrap(), wire);
        assert_eq!(
            restored.read("keys", b"wraps").unwrap(),
            Some(b"selected-keys".as_slice())
        );
        assert_eq!(
            restored.read("wallet", b"state").unwrap(),
            Some(b"wallet-original".as_slice())
        );
        assert_eq!(
            restored.load_pending().unwrap()[0].bytes,
            b"outbox-original"
        );
        assert_eq!(destination.read().await.unwrap().unwrap(), wire);
        assert_eq!(writes.get(), 1);
        assert_eq!(
            Store::restore_checked(destination.clone(), &key, "restore", 1, &wire, |_| Ok(()))
                .await
                .unwrap_err(),
            Error::AlreadyInitialized
        );
        assert_eq!(destination.read().await.unwrap().unwrap(), wire);
    }
);

test_async!(rewrap_commits_owner_changes_and_outbox_under_one_version, {
    let backend = Memory::new();
    let old_cipher = cipher(1);
    let new_cipher = cipher(2);
    let mut store = Store::create(backend.clone(), &old_cipher, "s")
        .await
        .unwrap();
    let original_output = Output {
        id: [1; 32],
        bytes: b"already committed ciphertext".to_vec(),
    };
    let previous = store
        .commit_with_receipt(
            0,
            [1; 32],
            &changes(b"old wallet", b"retained conversation"),
            std::slice::from_ref(&original_output),
        )
        .await
        .unwrap();
    let reader = store.read_handle("wallet").unwrap();
    let new_output = Output {
        id: [2; 32],
        bytes: b"new committed ciphertext".to_vec(),
    };
    assert_eq!(
        store
            .commit_rewrapped(
                1,
                [2; 32],
                &[
                    Change::Put {
                        owner: "wallet",
                        key: b"state",
                        value: b"new wallet",
                    },
                    Change::Put {
                        owner: "keys",
                        key: b"wraps",
                        value: b"opaque owner transition",
                    },
                ],
                std::slice::from_ref(&new_output),
                &new_cipher,
            )
            .await
            .unwrap(),
        2
    );
    assert_eq!(store.operation().unwrap(), [2; 32]);
    assert_eq!(
        reader.read(b"state", 100).unwrap(),
        Some(b"new wallet".to_vec())
    );
    assert!(!previous.is_commit(&store, &[1; 32]));
    store.lock_in_place();
    assert_eq!(
        Store::open(backend.clone(), &old_cipher, "s")
            .await
            .unwrap_err(),
        Error::Unlock
    );
    let mut reopened = Store::open(backend.clone(), &new_cipher, "s")
        .await
        .unwrap();
    assert_eq!(reopened.version().unwrap(), 2);
    assert_eq!(reopened.operation().unwrap(), [2; 32]);
    assert_eq!(
        reopened.read("wallet", b"state").unwrap(),
        Some(b"new wallet".as_slice())
    );
    assert_eq!(
        reopened.read("threads", b"state").unwrap(),
        Some(b"retained conversation".as_slice())
    );
    assert_eq!(
        reopened.read("keys", b"wraps").unwrap(),
        Some(b"opaque owner transition".as_slice())
    );
    let pending = reopened.load_pending().unwrap();
    assert_eq!(pending.len(), 2);
    assert_eq!(pending[0].id, original_output.id);
    assert_eq!(pending[0].bytes, original_output.bytes);
    assert_eq!(pending[1].id, new_output.id);
    assert_eq!(pending[1].bytes, new_output.bytes);
    let receipt = reopened.receipt(&[2; 32]).unwrap();
    assert!(receipt.is_commit(&reopened, &[2; 32]));
    assert!(receipt.contains_record(
        "keys",
        b"wraps",
        blake3::hash(b"opaque owner transition").as_bytes()
    ));
    assert!(receipt.contains_output(&new_output.id, blake3::hash(&new_output.bytes).as_bytes()));

    // An ordinary subsequent commit must retain the new wrapper as well.
    reopened
        .ack_output(2, [3; 32], original_output.id)
        .await
        .unwrap();
    reopened.lock();
    let continued = Store::open(backend, &new_cipher, "s").await.unwrap();
    assert_eq!(continued.version().unwrap(), 3);
    assert_eq!(continued.load_pending().unwrap().len(), 1);
    assert_eq!(continued.load_pending().unwrap()[0].bytes, new_output.bytes);
});

test_async!(rewrap_stale_backend_cas_preserves_the_winner, {
    let backend = Memory::new();
    let old_cipher = cipher(1);
    let new_cipher = cipher(2);
    let mut winner = Store::create(backend.clone(), &old_cipher, "s")
        .await
        .unwrap();
    let mut stale = Store::open(backend.clone(), &old_cipher, "s")
        .await
        .unwrap();
    let stale_reader = stale.read_handle("wallet").unwrap();
    winner
        .commit(0, [1; 32], &changes(b"winner", b"winner"), &[])
        .await
        .unwrap();
    let winner_wire = backend.read().await.unwrap().unwrap();
    // The expected version matches this handle: only the real backend CAS can
    // reject the concurrent checkpoint, including the proposed new wrapper.
    assert_eq!(stale.version().unwrap(), 0);
    assert_eq!(
        stale
            .commit_rewrapped(0, [2; 32], &changes(b"loser", b"loser"), &[], &new_cipher)
            .await
            .unwrap_err(),
        Error::Conflict
    );
    assert_eq!(stale.version(), Err(Error::Locked));
    assert_eq!(stale_reader.read(b"state", 100), Err(Error::Locked));
    assert_eq!(backend.read().await.unwrap().unwrap(), winner_wire);
    assert_eq!(
        Store::open(backend.clone(), &new_cipher, "s")
            .await
            .unwrap_err(),
        Error::Unlock
    );
    let reopened = Store::open(backend, &old_cipher, "s").await.unwrap();
    assert_eq!(reopened.version().unwrap(), 1);
    assert_eq!(reopened.operation().unwrap(), [1; 32]);
    assert_eq!(
        reopened.read("wallet", b"state").unwrap(),
        Some(b"winner".as_slice())
    );
});

test_async!(
    rewrap_failed_unknown_and_cancelled_writes_reconcile_one_wrapper,
    {
        use futures::FutureExt;
        for fault in [2, 3, 4] {
            let mode = std::rc::Rc::new(std::cell::Cell::new(0));
            let backend = Faults {
                inner: Memory::new(),
                mode: mode.clone(),
            };
            let old_cipher = cipher(1);
            let new_cipher = cipher(2);
            let mut store = Store::create(backend.clone(), &old_cipher, "s")
                .await
                .unwrap();
            let old_output = Output {
                id: [1; 32],
                bytes: b"retained output".to_vec(),
            };
            store
                .commit(
                    0,
                    [1; 32],
                    &changes(b"before", b"retained"),
                    std::slice::from_ref(&old_output),
                )
                .await
                .unwrap();
            let original = backend.read().await.unwrap().unwrap();
            let reader = store.read_handle("wallet").unwrap();
            let changed = changes(b"after", b"retained");
            let new_output = Output {
                id: [2; 32],
                bytes: b"new output".to_vec(),
            };
            mode.set(fault);
            let mut pending = Box::pin(store.commit_rewrapped(
                1,
                [2; 32],
                &changed,
                std::slice::from_ref(&new_output),
                &new_cipher,
            ));
            assert_eq!(
                pending.as_mut().now_or_never(),
                match fault {
                    2 => Some(Err(Error::Storage)),
                    3 => Some(Err(Error::Uncertain)),
                    _ => None,
                }
            );
            assert_eq!(reader.read(b"state", 100), Err(Error::Locked));
            drop(pending);
            assert_eq!(store.version(), Err(Error::Locked));
            assert_eq!(store.receipt(&[2; 32]).unwrap_err(), Error::Locked);
            mode.set(0);

            let (accepted, refused, version, operation, wallet) = if fault == 2 {
                assert_eq!(backend.read().await.unwrap().unwrap(), original);
                (&old_cipher, &new_cipher, 1, [1; 32], b"before".as_slice())
            } else {
                assert_ne!(backend.read().await.unwrap().unwrap(), original);
                (&new_cipher, &old_cipher, 2, [2; 32], b"after".as_slice())
            };
            assert_eq!(
                Store::open(backend.clone(), refused, "s")
                    .await
                    .unwrap_err(),
                Error::Unlock
            );
            let reopened = Store::open(backend, accepted, "s").await.unwrap();
            assert_eq!(reopened.version().unwrap(), version);
            assert_eq!(reopened.operation().unwrap(), operation);
            assert_eq!(reopened.read("wallet", b"state").unwrap(), Some(wallet));
            assert_eq!(
                reopened.read("threads", b"state").unwrap(),
                Some(b"retained".as_slice())
            );
            let outputs = reopened.load_pending().unwrap();
            assert_eq!(outputs.len(), if fault == 2 { 1 } else { 2 });
            assert_eq!(outputs[0].id, old_output.id);
            assert_eq!(outputs[0].bytes, old_output.bytes);
            if fault != 2 {
                assert_eq!(outputs[1].id, new_output.id);
                assert_eq!(outputs[1].bytes, new_output.bytes);
                assert!(
                    reopened.receipt(&operation).unwrap().contains_output(
                        &new_output.id,
                        blake3::hash(&new_output.bytes).as_bytes()
                    )
                );
            }
            assert_eq!(reader.read(b"state", 100), Err(Error::Locked));
        }
    }
);
