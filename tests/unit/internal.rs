//! Authenticated malformed checkpoints, version exhaustion and private AEAD boundaries.
use super::*;
use crate::backend::Memory;
use ckmg::passkey::{PrfOutput, store_cipher};

#[test]
fn authenticated_checkpoint_invariants() {
    futures_executor::block_on(async {
        let cipher = store_cipher(&PrfOutput::from_bytes(&[4; 32]).unwrap(), "test").unwrap();
        let backend = Memory::new();
        let mut store = Store::create(backend.clone(), &cipher, "test")
            .await
            .unwrap();
        let original = backend.read().await.unwrap().unwrap();
        let current = store.current().unwrap();
        let valid = serde_json::to_value(&current.checkpoint).unwrap();
        let mut cases = Vec::new();
        let record = serde_json::json!({"owner":"a","key":[1],"value":[2]});
        let mut v = valid.clone();
        v["records"] = serde_json::json!(vec![record.clone(); MAX_RECORDS + 1]);
        cases.push(v);
        let mut v = valid.clone();
        v["pending"] = serde_json::json!(vec![
            Output {
                id: [1; 32],
                bytes: vec![]
            };
            MAX_OUTPUTS + 1
        ]);
        cases.push(v);
        let mut v = valid.clone();
        v["records"] = serde_json::json!([record.clone(), record]);
        cases.push(v);
        let mut v = valid.clone();
        v["records"] = serde_json::json!([{"owner":"","key":[1],"value":[]}]);
        cases.push(v);
        let mut v = valid.clone();
        v["records"] =
            serde_json::json!([{"owner":"a","key":[1],"value":vec![1;MAX_VALUE_BYTES+1]}]);
        cases.push(v);
        let mut v = valid.clone();
        v["version"] = serde_json::json!("invalid");
        cases.push(v);
        for value in cases {
            let encrypted = veilid_crypt::encrypt(
                &serde_json::to_vec(&value).unwrap(),
                &current.key,
                &aad(&store.context, &current.wrapped),
            )
            .unwrap();
            let wire = [HEADER, current.wrapped.as_slice(), encrypted.as_slice()].concat();
            backend
                .compare_exchange(Some(&original), &wire)
                .await
                .unwrap();
            assert!(Store::open(backend.clone(), &cipher, "test").await.is_err());
            backend
                .compare_exchange(Some(&wire), &original)
                .await
                .unwrap();
        }
        let mut c = current.checkpoint.clone();
        c.version = u64::MAX;
        let wire = encode(&c, &current.key, &current.wrapped, &store.context).unwrap();
        backend
            .compare_exchange(Some(&original), &wire)
            .await
            .unwrap();
        store = Store::open(backend, &cipher, "test").await.unwrap();
        assert_eq!(
            store.commit(u64::MAX, [1; 32], &[], &[]).await.unwrap_err(),
            Error::TooLarge
        );
        assert_eq!(
            veilid_crypt::decrypt(b"short", &Zeroizing::new([0; 32]), b"scope").unwrap_err(),
            Error::Corrupt
        );
    });
}
