//! wasmtime host smoke tests for the `keetanetwork-client-wasi` artifacts.
//!
//!
//! Build the artifact first (the `test-wasi` Makefile target does this):
//!
//! ```sh
//! cargo build -p keetanetwork-client-wasi --target wasm32-wasip1 --features p1
//! ```

use std::path::PathBuf;

use wasmtime::{Engine, Instance, Linker, Memory, Module, Store, TypedFunc};
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
	account_address: TypedFunc<i32, i32>,
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
			account_address: instance.get_typed_func(&mut *store, "keeta_account_address")?,
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

	/// Derive an account from a hex seed at `index`, returning its handle.
	fn account_from_seed(&self, store: &mut Store<WasiP1Ctx>, seed: &str, index: i32) -> wasmtime::Result<i32> {
		let (seed_ptr, seed_len) = self.write(store, seed.as_bytes())?;
		let (algo_ptr, algo_len) = self.write(store, ALGORITHM.as_bytes())?;
		let handle = self
			.account_from_seed
			.call(&mut *store, (seed_ptr, seed_len, index, algo_ptr, algo_len))?;

		self.handle(store, handle)
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

	let seed_handle = abi.generate_seed.call(&mut store, ())?;
	let seed = abi.take_string(&mut store, seed_handle)?;
	assert_eq!(seed.len(), 64, "a generated seed must be 32-byte hex");

	let user = abi.account_from_seed(&mut store, &seed, 0)?;
	let rep = abi.account_from_seed(&mut store, &seed, 1)?;

	let address_handle = abi.account_address.call(&mut store, user)?;
	let address = abi.take_string(&mut store, address_handle)?;
	assert!(!address.is_empty(), "the account must have an address");

	let raw = abi.op_set_rep.call(&mut store, rep)?;
	let operation = abi.handle(&mut store, raw)?;

	let raw = abi.builder_new.call(&mut store, ())?;
	let mut builder = abi.handle(&mut store, raw)?;
	let raw = abi.builder_with_network.call(&mut store, (builder, 0))?;
	builder = abi.handle(&mut store, raw)?;
	let raw = abi.builder_with_account.call(&mut store, (builder, user))?;
	builder = abi.handle(&mut store, raw)?;
	let raw = abi.builder_with_signer.call(&mut store, (builder, user))?;
	builder = abi.handle(&mut store, raw)?;
	let raw = abi
		.builder_with_date
		.call(&mut store, (builder, 1_700_000_000_000))?;
	builder = abi.handle(&mut store, raw)?;
	let raw = abi.builder_as_opening.call(&mut store, builder)?;
	builder = abi.handle(&mut store, raw)?;
	let raw = abi
		.builder_with_operation
		.call(&mut store, (builder, operation))?;
	builder = abi.handle(&mut store, raw)?;

	let raw = abi.builder_build.call(&mut store, builder)?;
	let unsigned = abi.handle(&mut store, raw)?;
	let raw = abi.unsigned_sign.call(&mut store, unsigned)?;
	let block = abi.handle(&mut store, raw)?;

	let hash_handle = abi.block_hash.call(&mut store, block)?;
	let hash = abi.take_string(&mut store, hash_handle)?;
	assert_eq!(hash.len(), 64, "the signed block hash must be 32-byte hex");
	assert!(hex::decode(&hash).is_ok(), "the block hash must be valid hex");

	Ok(())
}
