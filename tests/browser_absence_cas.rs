//! Browser-only IndexedDB backend contract: absent checkpoint versus empty
//! expected bytes and different-length prefix matches, using opaque bytes only.
//!
//! Empty and oversized replacement bounds already live in
//! `tests/store.rs` (`corruption_and_limits`) through the shared
//! `backend::check_size`, so this file covers only the missing distinction.
#![cfg(target_arch = "wasm32")]

use cwst::{Error, backend::Backend};

wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

#[wasm_bindgen_test::wasm_bindgen_test]
async fn indexeddb_absence_empty_and_prefix_lengths() {
    let name = format!("cwst-absence-cas-{}", js_sys::Date::now());
    let first = cwst::browser::IndexedDb::open(&name).await.unwrap();
    let second = cwst::browser::IndexedDb::open(&name).await.unwrap();
    let current: Vec<u8> = vec![11, 22, 33];
    let next: Vec<u8> = vec![44, 55];
    let shorter_prefix: Vec<u8> = vec![11, 22];
    let longer_prefix: Vec<u8> = vec![11, 22, 33, 44];

    // Absence is not an empty checkpoint: expecting empty bytes conflicts
    // before any write, and the checkpoint stays absent.
    assert_eq!(
        first
            .compare_exchange(Some(b"".as_slice()), &current)
            .await
            .unwrap_err(),
        Error::Conflict
    );
    assert!(first.read().await.unwrap().is_none());

    // Creating against absence succeeds and is visible on both connections.
    first.compare_exchange(None, &current).await.unwrap();
    assert_eq!(second.read().await.unwrap().unwrap(), current);

    // Absence no longer matches once a checkpoint exists.
    assert_eq!(
        second.compare_exchange(None, &next).await.unwrap_err(),
        Error::Conflict
    );
    assert_eq!(first.read().await.unwrap().unwrap(), current);

    // Equal prefixes of different lengths are not exact matches.
    assert_eq!(
        first
            .compare_exchange(Some(&shorter_prefix), &next)
            .await
            .unwrap_err(),
        Error::Conflict
    );
    assert_eq!(second.read().await.unwrap().unwrap(), current);
    assert_eq!(
        second
            .compare_exchange(Some(&longer_prefix), &next)
            .await
            .unwrap_err(),
        Error::Conflict
    );
    assert_eq!(first.read().await.unwrap().unwrap(), current);

    // The exact predecessor replaces the checkpoint.
    second
        .compare_exchange(Some(&current), &next)
        .await
        .unwrap();

    drop(first);
    drop(second);
    let reopened = cwst::browser::IndexedDb::open(&name).await.unwrap();
    assert_eq!(reopened.read().await.unwrap().unwrap(), next);
    drop(reopened);
    keyvaluedb_web::Database::delete(&name).await.unwrap();
}
