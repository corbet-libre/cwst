//! Encrypted atomic device checkpoints for opaque owner records and pending outputs.
//! Keys supplies an opaque wrapping capability; storage never receives PRF or roots.
pub mod backend;
#[cfg(target_arch = "wasm32")]
pub mod browser;
mod error;
#[cfg(not(target_arch = "wasm32"))]
pub mod native;
mod store;
mod veilid_crypt;

pub use error::Error;
pub use store::{Change, CommitReceipt, Output, ReadHandle, Store};
/// Maximum encrypted checkpoint size, including all owners and pending outputs.
pub const MAX_CHECKPOINT_BYTES: usize = 8 * 1024 * 1024;
/// Maximum individual opaque value or output.
pub const MAX_VALUE_BYTES: usize = 1024 * 1024;
/// Maximum owner/key identifier length.
pub const MAX_KEY_BYTES: usize = 256;
/// Maximum number of owner records in one checkpoint.
pub const MAX_RECORDS: usize = 1024;
/// Maximum number of committed outputs awaiting acknowledgement.
pub const MAX_OUTPUTS: usize = 64;

#[cfg(all(test, target_arch = "wasm32"))]
wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);
