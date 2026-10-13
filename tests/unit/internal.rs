//! Authenticated malformed checkpoints, version exhaustion and private AEAD boundaries.
use super::*;
use crate::backend::Memory;
use ckmg::passkey::{PrfOutput, store_cipher};

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn authenticated_checkpoint_invariants() {
    futures_executor::block_on(async {
        let cipher = store_cipher(&PrfOutput::from_bytes(&[4; 32]).unwrap(), "test").unwrap();
        let backend = Memory::new();
        let mut store = Store::create(backend.clone(), &cipher, "test")
            .await
            .unwrap();
        let original = backend.read().await.unwrap().unwrap();
        let current = store.current().unwrap();
        let valid = serde_json::to_value(current.checkpoint.as_ref()).unwrap();
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
        let mut c = current.checkpoint.as_ref().clone();
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

struct FailAfter(usize);
impl ckmg::Entropy for FailAfter {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), ckmg::Error> {
        if self.0 == 0 {
            return Err(ckmg::Error::Randomness);
        }
        self.0 -= 1;
        ckmg::Entropy::fill(&mut ckmg::SystemEntropy, out)
    }
}
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn entropy_failures_refuse_creation_and_data_encryption() {
    futures_executor::block_on(async {
        let cipher = store_cipher(&PrfOutput::from_bytes(&[4; 32]).unwrap(), "test").unwrap();
        for successful_calls in 0..2 {
            let backend = Memory::new();
            assert!(
                Store::create_with_entropy(
                    backend.clone(),
                    &cipher,
                    "test",
                    &mut FailAfter(successful_calls)
                )
                .await
                .is_err()
            );
            assert!(backend.read().await.unwrap().is_none());
        }
        let key = Zeroizing::new([0; 32]);
        assert_eq!(
            veilid_crypt::encrypt_with_entropy(b"plain", &key, b"scope", &mut FailAfter(0))
                .unwrap_err(),
            Error::Randomness
        );
        assert_eq!(
            veilid_crypt::encrypt(&vec![0; crate::MAX_CHECKPOINT_BYTES + 1], &key, b"scope")
                .unwrap_err(),
            Error::TooLarge
        );
    });
}

#[cfg(all(target_arch = "wasm32", owned_browser_coverage))]
#[wasm_bindgen_test::wasm_bindgen_test]
fn profiling_runtime_is_linked() {
    let _ = browser_coverage_runtime::__owned_test_module_signature();
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn poisoned_shared_checkpoint_stays_closed_when_the_store_is_locked() {
    futures_executor::block_on(async {
        let cipher = store_cipher(&PrfOutput::from_bytes(&[4; 32]).unwrap(), "test").unwrap();
        let mut store = Store::create(Memory::new(), &cipher, "test").await.unwrap();
        let shared = store.readable.clone();
        let poisoner = std::thread::spawn(move || {
            let _held = shared.lock().unwrap();
            panic!("poison the shared checkpoint");
        });
        assert!(poisoner.join().is_err());
        store.lock_in_place();
        assert!(matches!(store.version(), Err(Error::Locked)));
        // The wiped checkpoint stays closed to readers even though the mutex is poisoned.
        assert!(store.readable.lock().is_err());
        assert!(
            store
                .readable
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .is_none()
        );
    });
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn rewrap_retains_data_key_and_rejects_authentic_wrapper_substitution() {
    futures_executor::block_on(async {
        let old_cipher = store_cipher(&PrfOutput::from_bytes(&[4; 32]).unwrap(), "test").unwrap();
        let new_cipher = store_cipher(&PrfOutput::from_bytes(&[5; 32]).unwrap(), "test").unwrap();
        let backend = Memory::new();
        let mut store = Store::create(backend.clone(), &old_cipher, "test")
            .await
            .unwrap();
        let original = backend.read().await.unwrap().unwrap();
        let data_key = store.current().unwrap().key.clone();
        let old_wrapper = store.current().unwrap().wrapped.clone();
        store
            .commit_rewrapped(0, [1; 32], &[], &[], &new_cipher)
            .await
            .unwrap();
        assert_eq!(store.current().unwrap().key.as_slice(), data_key.as_slice());
        let new_wrapper = store.current().unwrap().wrapped.clone();
        assert_ne!(new_wrapper, old_wrapper);
        // Both independently authenticated wrappers open to the same data key.
        assert_eq!(
            old_cipher
                .open(&store.context, &old_wrapper)
                .unwrap()
                .as_slice(),
            data_key.as_slice()
        );
        assert_eq!(
            new_cipher
                .open(&store.context, &new_wrapper)
                .unwrap()
                .as_slice(),
            data_key.as_slice()
        );
        let replacement = backend.read().await.unwrap().unwrap();
        for (wire, wrapper, cipher) in [
            (&replacement, &old_wrapper, &old_cipher),
            (&original, &new_wrapper, &new_cipher),
        ] {
            let mut substituted = wire.clone();
            substituted[HEADER.len()..HEADER.len() + WRAPPED_BYTES].copy_from_slice(wrapper);
            backend
                .compare_exchange(Some(&replacement), &substituted)
                .await
                .unwrap();
            // The wrapping AEAD succeeds, but changing only that wrapper must
            // fail the checkpoint AEAD even though its data key is unchanged.
            assert_eq!(
                Store::open(backend.clone(), cipher, "test")
                    .await
                    .unwrap_err(),
                Error::Corrupt
            );
            backend
                .compare_exchange(Some(&substituted), &replacement)
                .await
                .unwrap();
        }
        let reopened = Store::open(backend, &new_cipher, "test").await.unwrap();
        assert_eq!(
            reopened.current().unwrap().key.as_slice(),
            data_key.as_slice()
        );
        assert_eq!(reopened.version().unwrap(), 1);
    });
}
