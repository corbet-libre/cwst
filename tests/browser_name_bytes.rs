//! Browser-only IndexedDB database-name byte-bound regression.
//!
//! The open bound counts Rust UTF-8 bytes, not characters or browser
//! `DOMString` UTF-16 units. This file owns the multibyte boundary: one database
//! name of exactly 256 UTF-8 bytes ending in a 4-byte scalar, and a separately
//! named database of exactly 256 UTF-8 bytes ending in a 2-byte scalar. Empty
//! and 257-byte ASCII names stay covered by `tests/store.rs` and are not
//! repeated here. Only the `Backend` port is exercised with small opaque byte
//! strings; no identities, wrapping capabilities or encryption take part, the
//! IndexedDB implementation under test is never mocked, and only the two
//! databases created here are touched or deleted.
#![cfg(target_arch = "wasm32")]

wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

use cwst::{Error, backend::Backend, browser::IndexedDb};

fn utf16_units(value: &str) -> usize {
    value.encode_utf16().count()
}

#[wasm_bindgen_test::wasm_bindgen_test]
async fn indexeddb_name_byte_bound_across_utf8_and_domstring() {
    let stamp = js_sys::Date::now() as u64;

    // Exactly 256 UTF-8 bytes ending in a 4-byte scalar (U+1F600): 252 ASCII
    // bytes plus 4 content bytes, hence fewer than 256 characters and fewer
    // than 256 UTF-16 units.
    let prefix4 = format!("cwst-nb4-{stamp}-");
    let pad4 = 252usize
        .checked_sub(prefix4.len())
        .expect("timestamp prefix fits 252 ASCII bytes");
    let name4 = format!("{}{}{}", prefix4, "x".repeat(pad4), "\u{1f600}");
    assert_eq!(name4.len(), 256);
    assert_eq!(name4.chars().count(), 253);
    assert_eq!(utf16_units(&name4), 254);
    assert!(name4.ends_with("\u{1f600}"));

    // Exactly 256 UTF-8 bytes ending in a 2-byte scalar (U+00E9): 254 ASCII
    // bytes plus 2 content bytes, hence 255 characters and 255 UTF-16 units.
    let prefix2 = format!("cwst-nb2-{stamp}-");
    let pad2 = 254usize
        .checked_sub(prefix2.len())
        .expect("timestamp prefix fits 254 ASCII bytes");
    let name2 = format!("{}{}{}", prefix2, "x".repeat(pad2), "\u{e9}");
    assert_eq!(name2.len(), 256);
    assert_eq!(name2.chars().count(), 255);
    assert_eq!(utf16_units(&name2), 255);
    assert!(name2.ends_with("\u{e9}"));
    assert_ne!(name4, name2);

    // First database: open, small opaque compare-and-swap, and read back.
    let backend4 = IndexedDb::open(&name4).await.expect("256-byte name opens");
    assert_eq!(backend4.read().await.expect("read works"), None);
    backend4
        .compare_exchange(None, b"\xa1\xb2")
        .await
        .expect("first write works");
    assert_eq!(
        backend4.read().await.expect("read works"),
        Some(vec![0xa1, 0xb2])
    );

    // One byte over the bound must refuse with the exact error even though the
    // name still holds fewer than 256 characters and UTF-16 units, and the
    // established database must keep its committed bytes.
    let too_long4 = format!("{name4}y");
    assert_eq!(too_long4.len(), 257);
    assert_eq!(too_long4.chars().count(), 254);
    assert_eq!(utf16_units(&too_long4), 255);
    let refused4 = match IndexedDb::open(&too_long4).await {
        Err(error) => error,
        Ok(_) => panic!("257-byte name opened"),
    };
    assert_eq!(refused4, Error::Invalid);
    assert_eq!(
        backend4.read().await.expect("valid database unchanged"),
        Some(vec![0xa1, 0xb2])
    );

    // Replace the bytes, drop the handle, and confirm the reopen sees them.
    backend4
        .compare_exchange(Some(b"\xa1\xb2"), b"\xc3\xd4\xe5")
        .await
        .expect("second write works");
    drop(backend4);
    let reopened4 = IndexedDb::open(&name4).await.expect("reopen works");
    assert_eq!(
        reopened4.read().await.expect("read works"),
        Some(vec![0xc3, 0xd4, 0xe5])
    );
    drop(reopened4);

    // Second database: same shape with different opaque bytes.
    let backend2 = IndexedDb::open(&name2).await.expect("256-byte name opens");
    assert_eq!(backend2.read().await.expect("read works"), None);
    backend2
        .compare_exchange(None, b"\x01")
        .await
        .expect("first write works");
    let too_long2 = format!("{name2}z");
    assert_eq!(too_long2.len(), 257);
    assert_eq!(too_long2.chars().count(), 256);
    assert_eq!(utf16_units(&too_long2), 256);
    let refused2 = match IndexedDb::open(&too_long2).await {
        Err(error) => error,
        Ok(_) => panic!("257-byte name opened"),
    };
    assert_eq!(refused2, Error::Invalid);
    assert_eq!(
        backend2.read().await.expect("valid database unchanged"),
        Some(vec![0x01])
    );
    backend2
        .compare_exchange(Some(b"\x01"), b"\x02\x03\x04\x05")
        .await
        .expect("second write works");
    drop(backend2);
    let reopened2 = IndexedDb::open(&name2).await.expect("reopen works");
    assert_eq!(
        reopened2.read().await.expect("read works"),
        Some(vec![0x02, 0x03, 0x04, 0x05])
    );
    drop(reopened2);

    // Close (via drops above) and delete exactly the two owned databases.
    assert!(keyvaluedb_web::Database::delete(&name4).await.unwrap());
    assert!(keyvaluedb_web::Database::delete(&name2).await.unwrap());
}
