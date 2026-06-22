//! Binding generator entry point. Run in library mode against the built
//! `cdylib` to emit foreign-language bindings, e.g.:
//!
//! ```text
//! cargo run --bin uniffi-bindgen -- generate \
//!     --library target/debug/libkeetanetwork_ffi.dylib \
//!     --language python --out-dir target/bindings
//! ```

fn main() {
	uniffi::uniffi_bindgen_main()
}
