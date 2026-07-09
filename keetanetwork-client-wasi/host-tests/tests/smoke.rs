//! wasmtime host smoke tests for the `keetanetwork-client-wasi` artifacts.
//!
//!
//! Build the artifact first (the `test-wasi` Makefile target does this):
//!
//! ```sh
//! cargo build -p keetanetwork-client-wasi --target wasm32-wasip1 --features p1
//! ```

use std::path::PathBuf;

use wasmtime::{Engine, Instance, Linker, Memory, Module, Store, TypedFunc, WasmParams};
use wasmtime_wasi::p1::WasiP1Ctx;
use wasmtime_wasi::WasiCtxBuilder;

/// The signing algorithm the test derives accounts under.
const ALGORITHM: &str = "ecdsa_secp256k1";

/// Locate the prebuilt P1 core module.
fn module_path() -> PathBuf {
	if let Ok(path) = std::env::var("WASI_P1_MODULE") {
		return PathBuf::from(path);
	}

	PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/wasm32-wasip1/debug/keetanetwork_client_wasi.wasm")
}

/// The minimal flat-ABI surface the test exercises, resolved once up front.
struct Abi {
	memory: Memory,
	alloc: TypedFunc<i32, i32>,
	bytes_ptr: TypedFunc<i32, i32>,
	bytes_len: TypedFunc<i32, i32>,
	bytes_free: TypedFunc<i32, ()>,
	last_error_code: TypedFunc<(), i32>,
	generate_seed: TypedFunc<(), i32>,
	account_from_seed: TypedFunc<(i32, i32, i32, i32, i32), i32>,
	account_from_public_key_and_type: TypedFunc<(i32, i32), i32>,
	account_public_key_string: TypedFunc<i32, i32>,
	account_public_key_and_type_string: TypedFunc<i32, i32>,
	account_sign: TypedFunc<(i32, i32, i32), i32>,
	account_verify: TypedFunc<(i32, i32, i32, i32, i32), i32>,
	account_encrypt: TypedFunc<(i32, i32, i32), i32>,
	account_decrypt: TypedFunc<(i32, i32, i32), i32>,
	op_set_rep: TypedFunc<i32, i32>,
	builder_new: TypedFunc<(), i32>,
	builder_with_network: TypedFunc<(i32, i64), i32>,
	builder_with_account: TypedFunc<(i32, i32), i32>,
	builder_with_signer: TypedFunc<(i32, i32), i32>,
	builder_with_date: TypedFunc<(i32, i64), i32>,
	builder_as_opening: TypedFunc<i32, i32>,
	builder_with_operation: TypedFunc<(i32, i32), i32>,
	builder_build: TypedFunc<i32, i32>,
	unsigned_sign: TypedFunc<i32, i32>,
	block_hash: TypedFunc<i32, i32>,
	certificate_parse: TypedFunc<(i32, i32), i32>,
	certificate_pem: TypedFunc<i32, i32>,
	certificate_der: TypedFunc<i32, i32>,
	certificate_valid_at: TypedFunc<(i32, i64), i32>,
	certificate_free: TypedFunc<i32, ()>,
}

impl Abi {
	fn new(store: &mut Store<WasiP1Ctx>, instance: &Instance) -> wasmtime::Result<Self> {
		let memory = instance
			.get_memory(&mut *store, "memory")
			.ok_or_else(|| wasmtime::Error::msg("module must export `memory`"))?;

		Ok(Self {
			memory,
			alloc: instance.get_typed_func(&mut *store, "keeta_alloc")?,
			bytes_ptr: instance.get_typed_func(&mut *store, "keeta_bytes_ptr")?,
			bytes_len: instance.get_typed_func(&mut *store, "keeta_bytes_len")?,
			bytes_free: instance.get_typed_func(&mut *store, "keeta_bytes_free")?,
			last_error_code: instance.get_typed_func(&mut *store, "keeta_last_error_code")?,
			generate_seed: instance.get_typed_func(&mut *store, "keeta_generate_seed")?,
			account_from_seed: instance.get_typed_func(&mut *store, "keeta_account_from_seed")?,
			account_from_public_key_and_type: instance
				.get_typed_func(&mut *store, "keeta_account_from_public_key_and_type")?,
			account_public_key_string: instance.get_typed_func(&mut *store, "keeta_account_public_key_string")?,
			account_public_key_and_type_string: instance
				.get_typed_func(&mut *store, "keeta_account_public_key_and_type_string")?,
			account_sign: instance.get_typed_func(&mut *store, "keeta_account_sign")?,
			account_verify: instance.get_typed_func(&mut *store, "keeta_account_verify")?,
			account_encrypt: instance.get_typed_func(&mut *store, "keeta_account_encrypt")?,
			account_decrypt: instance.get_typed_func(&mut *store, "keeta_account_decrypt")?,
			op_set_rep: instance.get_typed_func(&mut *store, "keeta_op_set_rep")?,
			builder_new: instance.get_typed_func(&mut *store, "keeta_builder_new")?,
			builder_with_network: instance.get_typed_func(&mut *store, "keeta_builder_with_network")?,
			builder_with_account: instance.get_typed_func(&mut *store, "keeta_builder_with_account")?,
			builder_with_signer: instance.get_typed_func(&mut *store, "keeta_builder_with_signer")?,
			builder_with_date: instance.get_typed_func(&mut *store, "keeta_builder_with_date")?,
			builder_as_opening: instance.get_typed_func(&mut *store, "keeta_builder_as_opening")?,
			builder_with_operation: instance.get_typed_func(&mut *store, "keeta_builder_with_operation")?,
			builder_build: instance.get_typed_func(&mut *store, "keeta_builder_build")?,
			unsigned_sign: instance.get_typed_func(&mut *store, "keeta_unsigned_sign")?,
			block_hash: instance.get_typed_func(&mut *store, "keeta_block_hash")?,
			certificate_parse: instance.get_typed_func(&mut *store, "keeta_certificate_parse")?,
			certificate_pem: instance.get_typed_func(&mut *store, "keeta_certificate_pem")?,
			certificate_der: instance.get_typed_func(&mut *store, "keeta_certificate_der")?,
			certificate_valid_at: instance.get_typed_func(&mut *store, "keeta_certificate_valid_at")?,
			certificate_free: instance.get_typed_func(&mut *store, "keeta_certificate_free")?,
		})
	}

	/// Copy `data` into a fresh guest buffer, returning its `(ptr, len)`.
	fn write(&self, store: &mut Store<WasiP1Ctx>, data: &[u8]) -> wasmtime::Result<(i32, i32)> {
		let len = data.len() as i32;
		let ptr = self.alloc.call(&mut *store, len)?;

		self.memory.write(&mut *store, ptr as usize, data)?;

		Ok((ptr, len))
	}

	/// Read a bytes handle's payload and release it.
	fn take(&self, store: &mut Store<WasiP1Ctx>, handle: i32) -> wasmtime::Result<Vec<u8>> {
		if handle == 0 {
			let code = self.error_code(store)?;
			return Err(wasmtime::Error::msg(format!("guest call failed: {code}")));
		}

		let ptr = self.bytes_ptr.call(&mut *store, handle)?;
		let len = self.bytes_len.call(&mut *store, handle)?;
		let mut buffer = vec![0u8; len as usize];

		self.memory.read(&mut *store, ptr as usize, &mut buffer)?;
		self.bytes_free.call(&mut *store, handle)?;

		Ok(buffer)
	}

	/// Read a bytes handle as a UTF-8 string.
	fn take_string(&self, store: &mut Store<WasiP1Ctx>, handle: i32) -> wasmtime::Result<String> {
		Ok(String::from_utf8(self.take(store, handle)?)?)
	}

	/// The pending error code, for failure diagnostics.
	fn error_code(&self, store: &mut Store<WasiP1Ctx>) -> wasmtime::Result<String> {
		let handle = self.last_error_code.call(&mut *store, ())?;
		if handle == 0 {
			return Ok(String::from("<none>"));
		}

		let ptr = self.bytes_ptr.call(&mut *store, handle)?;
		let len = self.bytes_len.call(&mut *store, handle)?;
		let mut buffer = vec![0u8; len as usize];

		self.memory.read(&mut *store, ptr as usize, &mut buffer)?;
		self.bytes_free.call(&mut *store, handle)?;

		Ok(String::from_utf8(buffer)?)
	}

	/// A non-null object handle, or an error carrying the guest's error code.
	fn handle(&self, store: &mut Store<WasiP1Ctx>, handle: i32) -> wasmtime::Result<i32> {
		match handle {
			0 => {
				let code = self.error_code(store)?;
				Err(wasmtime::Error::msg(format!("guest produced a null handle: {code}")))
			}
			handle => Ok(handle),
		}
	}

	/// Call a guest function returning an object handle, checking it is non-null.
	fn checked<P>(&self, store: &mut Store<WasiP1Ctx>, func: &TypedFunc<P, i32>, params: P) -> wasmtime::Result<i32>
	where
		P: WasmParams,
	{
		let handle = func.call(&mut *store, params)?;
		self.handle(store, handle)
	}

	/// Generate a fresh seed as its 32-byte hex string.
	fn generate_seed_string(&self, store: &mut Store<WasiP1Ctx>) -> wasmtime::Result<String> {
		let handle = self.generate_seed.call(&mut *store, ())?;
		self.take_string(store, handle)
	}

	/// Derive an account from a hex seed at `index`, returning its handle.
	fn account_from_seed(&self, store: &mut Store<WasiP1Ctx>, seed: &str, index: i32) -> wasmtime::Result<i32> {
		let (seed_ptr, seed_len) = self.write(store, seed.as_bytes())?;
		let (algo_ptr, algo_len) = self.write(store, ALGORITHM.as_bytes())?;
		let handle = self
			.account_from_seed
			.call(&mut *store, (seed_ptr, seed_len, index, algo_ptr, algo_len))?;

		self.handle(store, handle)
	}

	/// Generate a fresh seed and derive the account at `index`.
	fn seeded_account(&self, store: &mut Store<WasiP1Ctx>, index: i32) -> wasmtime::Result<i32> {
		let seed = self.generate_seed_string(store)?;
		self.account_from_seed(store, &seed, index)
	}
}

fn instantiate() -> wasmtime::Result<(Store<WasiP1Ctx>, Abi)> {
	let path = module_path();
	let engine = Engine::default();
	let module = Module::from_file(&engine, &path)?;
	let mut linker: Linker<WasiP1Ctx> = Linker::new(&engine);

	wasmtime_wasi::p1::add_to_linker_sync(&mut linker, |context| context)?;

	let wasi = WasiCtxBuilder::new().inherit_stdio().build_p1();

	let mut store = Store::new(&engine, wasi);
	let instance = linker.instantiate(&mut store, &module)?;
	let abi = Abi::new(&mut store, &instance)?;
	Ok((store, abi))
}

#[test]
fn p1_derives_account_and_signs_an_opening_block() -> wasmtime::Result<()> {
	let (mut store, abi) = instantiate()?;

	let seed = abi.generate_seed_string(&mut store)?;
	assert_eq!(seed.len(), 64, "a generated seed must be 32-byte hex");

	let user = abi.account_from_seed(&mut store, &seed, 0)?;
	let rep = abi.account_from_seed(&mut store, &seed, 1)?;

	let string_handle = abi.account_public_key_string.call(&mut store, user)?;
	let public_key_string = abi.take_string(&mut store, string_handle)?;
	assert!(!public_key_string.is_empty(), "the account must have a public-key string");

	let operation = abi.checked(&mut store, &abi.op_set_rep, rep)?;

	let mut builder = abi.checked(&mut store, &abi.builder_new, ())?;
	builder = abi.checked(&mut store, &abi.builder_with_network, (builder, 0))?;
	builder = abi.checked(&mut store, &abi.builder_with_account, (builder, user))?;
	builder = abi.checked(&mut store, &abi.builder_with_signer, (builder, user))?;
	builder = abi.checked(&mut store, &abi.builder_with_date, (builder, 1_700_000_000_000))?;
	builder = abi.checked(&mut store, &abi.builder_as_opening, builder)?;
	builder = abi.checked(&mut store, &abi.builder_with_operation, (builder, operation))?;

	let unsigned = abi.checked(&mut store, &abi.builder_build, builder)?;
	let block = abi.checked(&mut store, &abi.unsigned_sign, unsigned)?;

	let hash_handle = abi.block_hash.call(&mut store, block)?;
	let hash = abi.take_string(&mut store, hash_handle)?;
	assert_eq!(hash.len(), 64, "the signed block hash must be 32-byte hex");
	assert!(hex::decode(&hash).is_ok(), "the block hash must be valid hex");

	Ok(())
}

#[test]
fn p1_account_signs_verifies_and_encrypts_round_trip() -> wasmtime::Result<()> {
	let (mut store, abi) = instantiate()?;

	let account = abi.seeded_account(&mut store, 0)?;
	let message: &[u8] = b"keeta account binding parity";

	let (msg_ptr, msg_len) = abi.write(&mut store, message)?;
	let raw = abi
		.account_sign
		.call(&mut store, (account, msg_ptr, msg_len))?;
	let signature = abi.take(&mut store, raw)?;
	assert!(!signature.is_empty(), "signing must produce a signature");

	let (msg_ptr, msg_len) = abi.write(&mut store, message)?;
	let (sig_ptr, sig_len) = abi.write(&mut store, &signature)?;
	let valid = abi
		.account_verify
		.call(&mut store, (account, msg_ptr, msg_len, sig_ptr, sig_len))?;
	assert_eq!(valid, 1, "the account must verify its own signature");

	let (plain_ptr, plain_len) = abi.write(&mut store, message)?;
	let raw = abi
		.account_encrypt
		.call(&mut store, (account, plain_ptr, plain_len))?;
	let ciphertext = abi.take(&mut store, raw)?;
	assert_ne!(ciphertext.as_slice(), message, "ciphertext must differ from plaintext");

	let (cipher_ptr, cipher_len) = abi.write(&mut store, &ciphertext)?;
	let raw = abi
		.account_decrypt
		.call(&mut store, (account, cipher_ptr, cipher_len))?;
	let recovered = abi.take(&mut store, raw)?;
	assert_eq!(recovered.as_slice(), message, "decrypt must recover the plaintext");

	Ok(())
}

#[test]
fn p1_account_round_trips_through_public_key_and_type() -> wasmtime::Result<()> {
	let (mut store, abi) = instantiate()?;

	let account = abi.seeded_account(&mut store, 0)?;
	let string_handle = abi.account_public_key_string.call(&mut store, account)?;
	let address = abi.take_string(&mut store, string_handle)?;

	let key_handle = abi
		.account_public_key_and_type_string
		.call(&mut store, account)?;
	let key_and_type = abi.take_string(&mut store, key_handle)?;
	assert!(key_and_type.starts_with("0x"), "the getter must be 0x-prefixed hex");

	let (hex_ptr, hex_len) = abi.write(&mut store, key_and_type.as_bytes())?;
	let reopened = abi.checked(&mut store, &abi.account_from_public_key_and_type, (hex_ptr, hex_len))?;
	let string_handle = abi.account_public_key_string.call(&mut store, reopened)?;
	let reopened_address = abi.take_string(&mut store, string_handle)?;
	assert_eq!(reopened_address, address, "the reopened account must keep its address");

	// An empty algorithm must select the default (`ecdsa_secp256k1`,
	// key type byte 0x00), matching the browser binding and the reference.
	let seed = abi.generate_seed_string(&mut store)?;
	let (seed_ptr, seed_len) = abi.write(&mut store, seed.as_bytes())?;
	let defaulted = abi.checked(&mut store, &abi.account_from_seed, (seed_ptr, seed_len, 0, 0, 0))?;
	let key_handle = abi
		.account_public_key_and_type_string
		.call(&mut store, defaulted)?;
	let defaulted_key = abi.take_string(&mut store, key_handle)?;
	assert!(defaulted_key.starts_with("0x00"), "the default algorithm must be ecdsa_secp256k1");

	Ok(())
}

#[test]
fn p1_parses_a_certificate_and_round_trips_pem_der_and_validity() -> wasmtime::Result<()> {
	use std::time::{SystemTime, UNIX_EPOCH};

	use keetanetwork_x509::doc_utils::create_test_certificate;

	let fixture = create_test_certificate("Host Smoke CA", None);
	let fixture_pem = fixture
		.to_pem()
		.map_err(|error| wasmtime::Error::msg(error.to_string()))?;
	let fixture_der = fixture
		.to_der()
		.map_err(|error| wasmtime::Error::msg(error.to_string()))?;

	let (mut store, abi) = instantiate()?;

	let (pem_ptr, pem_len) = abi.write(&mut store, fixture_pem.as_bytes())?;
	let certificate = abi.checked(&mut store, &abi.certificate_parse, (pem_ptr, pem_len))?;

	let pem_handle = abi.certificate_pem.call(&mut store, certificate)?;
	let round_tripped_pem = abi.take_string(&mut store, pem_handle)?;
	assert_eq!(round_tripped_pem, fixture_pem, "the guest must round-trip the certificate PEM");

	let der_handle = abi.certificate_der.call(&mut store, certificate)?;
	let der = abi.take(&mut store, der_handle)?;
	assert_eq!(der, fixture_der, "the guest must round-trip the certificate DER");

	let now_millis = SystemTime::now()
		.duration_since(UNIX_EPOCH)
		.expect("system clock must be after the unix epoch")
		.as_millis() as i64;
	let valid = abi
		.certificate_valid_at
		.call(&mut store, (certificate, now_millis))?;
	assert_eq!(valid, 1, "a freshly built certificate must be valid now");

	abi.certificate_free.call(&mut store, certificate)?;
	let after_free = abi
		.certificate_valid_at
		.call(&mut store, (certificate, now_millis))?;
	assert_eq!(after_free, -1, "a freed certificate handle must report an error");

	Ok(())
}
