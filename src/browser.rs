//! IndexedDB checkpoint persistence. Reads reuse keyvaluedb-web; writes extend its
//! column layout with a single strict read/compare/write transaction across tabs.
use crate::{
    Error, MAX_CHECKPOINT_BYTES,
    backend::{Backend, check_size},
};
use keyvaluedb::KeyValueDB;
use wasm_bindgen::prelude::*;

#[wasm_bindgen(module = "/browser/checkpoint.js")]
extern "C" {
    #[wasm_bindgen(catch, js_name = compareCheckpoint)]
    async fn compare_checkpoint(
        name: &str,
        expected: JsValue,
        next: &[u8],
        maximum: u32,
    ) -> Result<JsValue, JsValue>;
}
/// A dedicated uncached keyvaluedb-web database; drop closes this connection.
#[derive(Clone)]
pub struct IndexedDb {
    database: keyvaluedb_web::Database,
}
impl IndexedDb {
    /// Open a vault-selected database name. Names are local, opaque identifiers.
    pub async fn open(name: &str) -> Result<Self, Error> {
        if name.is_empty() || name.len() > 256 {
            return Err(Error::Invalid);
        }
        let database = keyvaluedb_web::Database::open(name, 1, false)
            .await
            .map_err(|_| Error::Storage)?;
        Ok(Self { database })
    }
}
impl Backend for IndexedDb {
    async fn read(&self) -> Result<Option<Vec<u8>>, Error> {
        let bytes = self
            .database
            .get(0, b"checkpoint")
            .await
            .map_err(|_| Error::Storage)?;
        if let Some(bytes) = &bytes {
            check_size(bytes)?;
        }
        Ok(bytes)
    }
    async fn compare_exchange(&self, expected: Option<&[u8]>, next: &[u8]) -> Result<(), Error> {
        check_size(next)?;
        let previous = expected
            .map(|bytes| js_sys::Uint8Array::from(bytes).into())
            .unwrap_or(JsValue::NULL);
        let result = compare_checkpoint(
            &self.database.name(),
            previous,
            next,
            MAX_CHECKPOINT_BYTES as u32,
        )
        .await
        .map_err(|_| Error::Uncertain)?;
        if result.as_bool() == Some(true) {
            Ok(())
        } else {
            Err(Error::Conflict)
        }
    }
}
