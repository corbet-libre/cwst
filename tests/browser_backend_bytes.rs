//! Browser-only byte-exact regression for the opaque IndexedDB byte port.
//!
//! Covers byte-exact compare semantics over two open connections: detached
//! reads, drop/reopen persistence, and isolation between two separately
//! named real IndexedDB databases. This complements the race and encryption
//! vectors in `tests/store.rs`. Fixtures are synthetic opaque storage bytes
//! and make no authenticated-ciphertext claim. Runs only as real browser
//! Wasm through `wasm-pack test --headless --chrome`; on other targets this
//! file compiles to an empty crate.

#![cfg(target_arch = "wasm32")]

use cwst::{Error, backend::Backend, browser::IndexedDb};

wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

/// Same-length fixture sharing every byte but the last, with NUL and high
/// bytes in the shared prefix.
fn fixture(last: u8) -> Vec<u8> {
    vec![0x00, 0x01, 0x7f, 0x80, 0xfe, 0xff, 0x42, last]
}

#[wasm_bindgen_test::wasm_bindgen_test]
async fn indexeddb_byte_exact_cas_detached_read_reopen_isolation() {
    let stamp = js_sys::Date::now();
    let name = format!("cwst-backend-bytes-{stamp}");
    let other_name = format!("cwst-backend-bytes-isolated-{stamp}");
    let value_a = fixture(0x10);
    let value_b = fixture(0x11);
    let stale = fixture(0x12);

    // Two independent open connections to the same real database.
    let first = IndexedDb::open(&name).await.unwrap();
    let second = IndexedDb::open(&name).await.unwrap();
    assert!(first.read().await.unwrap().is_none());

    // Initial creation; the second connection observes the same bytes.
    first.compare_exchange(None, &value_a).await.unwrap();
    assert_eq!(second.read().await.unwrap(), Some(value_a.clone()));

    // A mutated detached read must not disturb the persisted bytes.
    let mut detached = second.read().await.unwrap().unwrap();
    detached[0] ^= 0xff;
    *detached.last_mut().unwrap() ^= 0xff;
    detached.push(0x00);
    assert_eq!(first.read().await.unwrap(), Some(value_a.clone()));
    assert_eq!(second.read().await.unwrap(), Some(value_a.clone()));

    // A same-prefix expected value differing only in the last byte refuses
    // with an exact conflict and leaves the stored bytes untouched.
    assert_eq!(
        second
            .compare_exchange(Some(&stale), &stale)
            .await
            .unwrap_err(),
        Error::Conflict
    );
    assert_eq!(first.read().await.unwrap(), Some(value_a.clone()));

    // A separately named real database stays independent.
    let other = IndexedDb::open(&other_name).await.unwrap();
    let isolated = vec![0x00, 0xff, 0x42];
    other.compare_exchange(None, &isolated).await.unwrap();
    assert_eq!(other.read().await.unwrap(), Some(isolated.clone()));
    assert_eq!(first.read().await.unwrap(), Some(value_a.clone()));

    // Successful compare exchange, then drop every connection and reopen.
    first
        .compare_exchange(Some(&value_a), &value_b)
        .await
        .unwrap();
    assert_eq!(second.read().await.unwrap(), Some(value_b.clone()));
    drop(first);
    drop(second);
    let reopened = IndexedDb::open(&name).await.unwrap();
    assert_eq!(reopened.read().await.unwrap(), Some(value_b.clone()));

    // A stale writer still holding the pre-reopen bytes is fenced; the
    // persisted bytes stay exactly the post-reopen value.
    assert_eq!(
        reopened
            .compare_exchange(Some(&value_a), &value_a)
            .await
            .unwrap_err(),
        Error::Conflict
    );
    assert_eq!(reopened.read().await.unwrap(), Some(value_b.clone()));
    assert_eq!(other.read().await.unwrap(), Some(isolated.clone()));

    drop(reopened);
    drop(other);
    keyvaluedb_web::Database::delete(&name).await.unwrap();
    keyvaluedb_web::Database::delete(&other_name).await.unwrap();
}
