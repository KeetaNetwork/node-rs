//! Running contracts: loading sBPF code, laying out a contract's input,
//! running it in the VM, and the host functions it calls.
//!
//! One [`Invocation`] runs one contract once: the top-level instruction, or
//! a contract invoking another ([`syscall::INVOKE`]). Its accounts' data is
//! copied into the input region the contract sees; when the contract
//! returns (or before it invokes another contract), the engine checks what
//! changed and writes it to the call's [`Overlay`]. A nested invocation
//! reads those accounts back from the overlay, and the caller's copy is
//! refreshed when it returns, so both always see the same data.
//!
//! The VM itself needs `unsafe` (memory regions are raw host pointers);
//! it is confined to this module.

#![allow(unsafe_code)]

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex, MutexGuard};

use keetanetwork_account::KeyPairType;
use keetanetwork_block::{TextRule, ValidationConfig};
use keetanetwork_contract_std::abi::{self, layout, syscall, Address, StateId, ADDRESS_LEN, ADDRESS_SLOT};
use num_bigint::{BigInt, BigUint};
use sha2::{Digest, Sha256};
use solana_sbpf::aligned_memory::AlignedMemory;
use solana_sbpf::declare_builtin_function;
use solana_sbpf::ebpf::{self, HOST_ALIGN};
use solana_sbpf::elf::Executable;
use solana_sbpf::error::EbpfError;
use solana_sbpf::memory_region::{AccessType, MemoryMapping, MemoryRegion};
use solana_sbpf::program::{BuiltinProgram, SBPFVersion};
use solana_sbpf::verifier::RequisiteVerifier;
use solana_sbpf::vm::{CallFrame, Config, ContextObject, EbpfVm, ExecutionMode};

use crate::address::{from_address, parse_account_of, to_address};
use crate::code_cache::CodeCache;
use crate::engine::{AccountMeta, EngineConfig, Event, Fund, Log};
use crate::error::{ledger, EngineError};
use crate::gas;
use crate::host::{AccountInfo, CodeHash, Host};
use crate::overlay::Overlay;

type Memory = AlignedMemory<HOST_ALIGN>;

/// What lives as long as the engine: settings, the host functions and
/// loaded code.
pub(crate) struct Core {
	pub(crate) config: EngineConfig,
	loader: Arc<BuiltinProgram<Invocation>>,
	code: Mutex<CodeCache<Arc<Executable<Invocation>>>>,
}

impl Core {
	pub(crate) fn new(config: EngineConfig) -> Result<Self, EngineError> {
		let vm_config = Config {
			// Refuse code that calls host functions the engine does not have
			// when it is stored, not when the call is reached.
			reject_unregistered_static_syscalls: true,
			reject_broken_elfs: true,
			enabled_sbpf_versions: SBPFVersion::V3..=SBPFVersion::V3,
			..Config::default()
		};
		let mut loader = BuiltinProgram::new_loader(vm_config);
		register_host_functions(&mut loader)?;
		let code = Mutex::new(CodeCache::new(config.max_cached_code_size));
		Ok(Self { config, loader: Arc::new(loader), code })
	}

	/// Load and verify an ELF file.
	fn load(&self, elf: &[u8]) -> Result<Executable<Invocation>, EngineError> {
		let executable = Executable::from_elf(elf, self.loader.clone()).map_err(load_error)?;
		executable
			.verify::<RequisiteVerifier>()
			.map_err(load_error)?;
		Ok(executable)
	}

	/// Check code and keep it loaded. Returns its hash.
	pub(crate) fn store(&self, elf: &[u8]) -> Result<CodeHash, EngineError> {
		let limit = self.config.max_code_size;
		if elf.len() > limit {
			return Err(EngineError::CodeTooLarge { size: elf.len(), limit });
		}
		let executable = self.load(elf)?;
		let hash: CodeHash = Sha256::digest(elf).into();
		self.code
			.lock()
			.expect("code lock")
			.insert(hash, Arc::new(executable), elf.len());
		Ok(hash)
	}

	/// Loaded code by hash, fetched from the host if this process has not
	/// seen it. Not held to [`EngineConfig::max_code_size`]: the host only
	/// has code that passed it when it was stored.
	fn executable(&self, host: &dyn Host, hash: &CodeHash) -> Result<Arc<Executable<Invocation>>, EngineError> {
		if let Some(executable) = self.code.lock().expect("code lock").get(hash) {
			return Ok(executable);
		}
		let elf = host
			.code_bytes(hash)?
			.ok_or_else(|| EngineError::Setup { message: format!("host has no code {}", hex::encode(hash)) })?;
		if Sha256::digest(&elf).as_slice() != hash {
			return Err(EngineError::Setup {
				message: format!("host returned the wrong code for {}", hex::encode(hash)),
			});
		}
		let executable = Arc::new(self.load(&elf)?);
		self.code
			.lock()
			.expect("code lock")
			.insert(*hash, executable.clone(), elf.len());
		Ok(executable)
	}
}

fn load_error(error: impl std::fmt::Display) -> EngineError {
	let mut message = error.to_string();
	// Name unknown host functions: the loader only reports their hash.
	for name in syscall::ALL.iter().chain(syscall::PLATFORM) {
		let key = abi::syscall_hash(name.as_bytes());
		message = message.replace(&format!("({key})"), &format!("({key}, which is {name})"));
	}
	EngineError::Vm { message: format!("invalid code: {message}") }
}

/// One call in progress: what all its invocations share.
pub(crate) struct Session {
	core: Arc<Core>,
	host: Arc<dyn Host>,
	/// The block's time, milliseconds since the Unix epoch
	time_millis: i64,
	overlay: Mutex<Overlay>,
	pub(crate) events: Mutex<Vec<Event>>,
	pub(crate) logs: Mutex<Vec<Log>>,
	/// Contracts currently running, outermost first
	stack: Mutex<Vec<String>>,
}

impl Session {
	pub(crate) fn new(core: Arc<Core>, host: Arc<dyn Host>, time_millis: i64) -> Self {
		Self {
			core,
			host,
			time_millis,
			overlay: Mutex::default(),
			events: Mutex::default(),
			logs: Mutex::default(),
			stack: Mutex::default(),
		}
	}

	pub(crate) fn lock(&self) -> MutexGuard<'_, Overlay> {
		// A poisoned lock means a panic mid-update; the state cannot be trusted.
		self.overlay.lock().expect("overlay lock poisoned")
	}

	pub(crate) fn host(&self) -> &dyn Host {
		self.host.as_ref()
	}

	pub(crate) fn config(&self) -> &EngineConfig {
		&self.core.config
	}

	pub(crate) fn rules(&self) -> Result<ValidationConfig, EngineError> {
		ValidationConfig::for_network(&BigInt::from(self.config().network))
			.map_err(|error| EngineError::Setup { message: error.to_string() })
	}
}

/// A contract to run.
pub(crate) struct Request<'a> {
	pub(crate) contract: &'a str,
	pub(crate) caller: &'a str,
	pub(crate) funds: &'a [Fund],
	pub(crate) accounts: &'a [AccountMeta],
	/// For a nested invocation, the room the invoking contract has for each
	/// account, which the callee may not grow it beyond; empty at the top.
	pub(crate) room: &'a [usize],
	pub(crate) data: &'a [u8],
}

/// What a finished invocation leaves.
pub(crate) struct Outcome {
	pub(crate) return_data: Option<Vec<u8>>,
	/// Gas left
	pub(crate) remaining: u64,
}

/// Run a contract with `remaining` gas.
pub(crate) fn invoke(session: &Arc<Session>, request: Request<'_>, remaining: u64) -> Result<Outcome, EngineError> {
	let config = session.config();
	{
		let stack = session.stack.lock().expect("stack lock");
		if stack.len() >= config.max_call_depth {
			return Err(EngineError::DepthExceeded { limit: config.max_call_depth });
		}
		if stack.iter().any(|running| running == request.contract) {
			return Err(EngineError::Reentrancy { contract: request.contract.to_string() });
		}
	}
	check_instruction(request.accounts, request.data)?;

	let mut meter = remaining;
	charge(&mut meter, gas::INVOKE + gas::bytes(request.data.len()))?;
	let host = session.host();
	let record = session.lock().contract(host, request.contract)?;
	let executable = session.core.executable(host, &record.code_hash)?;

	let mut input = Vec::new();
	put_address(&mut input, &to_address(request.contract)?);
	put_address(&mut input, &to_address(request.caller)?);
	put_u64(&mut input, session.time_millis as u64);
	put_u64(&mut input, request.funds.len() as u64);
	for fund in request.funds {
		put_address(&mut input, &to_address(&fund.token)?);
		let amount = u128::try_from(&fund.amount)
			.map_err(|_| ledger(format!("{} of {} is too much to pass to a contract", fund.amount, fund.token)))?;
		input.extend_from_slice(&amount.to_le_bytes());
	}
	put_u64(&mut input, request.accounts.len() as u64);
	let mut slots = Vec::with_capacity(request.accounts.len());
	for (index, meta) in request.accounts.iter().enumerate() {
		let owner = to_address(&meta.owner)?;
		let data = {
			let mut overlay = session.lock();
			overlay.contract(host, &meta.owner)?;
			overlay
				.storage_get(host, &meta.owner, &meta.id)?
				.unwrap_or_default()
		};
		charge(&mut meter, gas::account_load(data.len()))?;
		let own = meta.owner == request.contract;
		let writable = meta.writable;
		// Room to grow every writable account: the caller's own, and those it
		// passes on, which the contract owning them may grow in a nested call.
		// A callee gets no more room than its caller has to take the data back.
		let capacity = if writable {
			let room = request.room.get(index).copied().unwrap_or(usize::MAX);
			(data.len() + abi::ACCOUNT_GROWTH)
				.min(abi::MAX_ACCOUNT_SIZE)
				.min(room)
				.max(data.len())
		} else {
			data.len()
		};

		let offset = input.len();
		input.extend_from_slice(&[writable as u8, own as u8, 0, 0, 0, 0, 0, 0]);
		put_address(&mut input, &owner);
		input.extend_from_slice(&meta.id);
		put_u64(&mut input, data.len() as u64);
		put_u64(&mut input, capacity as u64);
		let header: [u8; layout::ACCOUNT_HEADER] = input[offset..].try_into().expect("header size");
		input.extend_from_slice(&data);
		input.resize(input.len() + layout::padded(capacity) - data.len(), 0);
		slots.push(Slot { owner: meta.owner.clone(), id: meta.id, writable, own, offset, capacity, header, data });
	}
	put_u64(&mut input, request.data.len() as u64);
	input.extend_from_slice(request.data);

	let event = {
		let mut events = session.events.lock().expect("events lock");
		events.push(Event { contract: request.contract.into(), attributes: Vec::new() });
		events.len() - 1
	};
	let mut invocation = Invocation {
		mapping: None,
		session: session.clone(),
		contract: request.contract.to_string(),
		slots,
		remaining: meter,
		input: Memory::from_slice(&input),
		failure: None,
		error: None,
		attributes: Vec::new(),
		return_data: None,
		child_return: Vec::new(),
	};

	session
		.stack
		.lock()
		.expect("stack lock")
		.push(request.contract.to_string());
	let result = invocation.run(&executable);
	session.stack.lock().expect("stack lock").pop();
	result?;
	invocation.flush_accounts()?;

	session.events.lock().expect("events lock")[event]
		.attributes
		.append(&mut invocation.attributes);
	Ok(Outcome { return_data: invocation.return_data, remaining: invocation.remaining })
}

fn check_instruction(accounts: &[AccountMeta], data: &[u8]) -> Result<(), EngineError> {
	let invalid = |reason: String| EngineError::InvalidInstruction { reason };
	if accounts.len() > abi::MAX_ACCOUNTS {
		return Err(invalid(format!("{} accounts, at most {} allowed", accounts.len(), abi::MAX_ACCOUNTS)));
	}
	if data.len() > abi::MAX_INSTRUCTION_DATA {
		return Err(invalid(format!("{} bytes of data, at most {} allowed", data.len(), abi::MAX_INSTRUCTION_DATA)));
	}
	let mut seen = BTreeSet::new();
	for account in accounts {
		if !seen.insert((&account.owner, account.id)) {
			return Err(invalid(format!("account {} of {} is listed twice", hex::encode(account.id), account.owner)));
		}
	}
	Ok(())
}

fn charge(meter: &mut u64, cost: u64) -> Result<(), EngineError> {
	if *meter < cost {
		*meter = 0;
		return Err(EngineError::OutOfGas);
	}
	*meter -= cost;
	Ok(())
}

fn put_u64(input: &mut Vec<u8>, value: u64) {
	input.extend_from_slice(&value.to_le_bytes());
}

fn put_address(input: &mut Vec<u8>, address: &Address) {
	input.extend_from_slice(&address.0);
	input.extend_from_slice(&[0; ADDRESS_SLOT - ADDRESS_LEN]);
}

/// One account of an invocation.
struct Slot {
	owner: String,
	id: StateId,
	/// Writable in this invocation
	writable: bool,
	/// Owned by the contract being run
	own: bool,
	/// Where its header starts in the input
	offset: usize,
	capacity: usize,
	/// The header as written, which the contract must leave alone apart
	/// from the data length
	header: [u8; layout::ACCOUNT_HEADER],
	/// The data as last synced with the overlay
	data: Vec<u8>,
}

impl Slot {
	fn mutable(&self) -> bool {
		self.writable && self.own
	}

	fn describe(&self) -> String {
		format!("account {} of {}", hex::encode(self.id), self.owner)
	}
}

/// One contract running: the VM's context object.
pub(crate) struct Invocation {
	/// Declared first so it is dropped before the memory it points into.
	mapping: Option<MemoryMapping>,
	session: Arc<Session>,
	contract: String,
	slots: Vec<Slot>,
	/// Gas left
	remaining: u64,
	input: Memory,
	/// Why a host function aborted the contract
	failure: Option<EngineError>,
	/// The contract's own error message
	error: Option<String>,
	attributes: Vec<(String, String)>,
	return_data: Option<Vec<u8>>,
	/// Return data of the last contract this one invoked
	child_return: Vec<u8>,
}

impl ContextObject for Invocation {
	fn consume(&mut self, amount: u64) {
		self.remaining = self.remaining.saturating_sub(amount);
	}

	fn get_remaining(&self) -> u64 {
		self.remaining
	}

	fn active_mapping_ptr(&mut self) -> std::ptr::NonNull<MemoryMapping> {
		std::ptr::NonNull::from_mut(self.mapping.as_mut().expect("mapped while running"))
	}
}

impl Invocation {
	fn run(&mut self, executable: &Executable<Invocation>) -> Result<(), EngineError> {
		let config = executable.get_config();
		let version = executable.get_sbpf_version();
		let mut stack = Memory::zero_filled(config.stack_size());
		let mut heap = Memory::zero_filled(abi::HEAP_SIZE);
		let stack_len = stack.len();
		let stack_gap = if version.stack_frame_gaps() && config.enable_stack_frame_gaps {
			config.stack_frame_size as u64
		} else {
			0
		};
		let regions = vec![
			executable.get_ro_region(),
			MemoryRegion::new_gapped(&raw mut *stack.as_slice_mut(), ebpf::MM_STACK_START, stack_gap),
			MemoryRegion::new(&raw mut *heap.as_slice_mut(), ebpf::MM_HEAP_START),
			MemoryRegion::new(&raw mut *self.input.as_slice_mut(), ebpf::MM_INPUT_START),
		];
		// SAFETY: the regions point into `stack`, `heap`, `self.input` and the
		// executable's read-only section, all of which outlive the mapping:
		// it is dropped (set to `None`) below, before `stack` and `heap`, and
		// `self.input` is not reallocated while the contract runs.
		let mapping = unsafe { MemoryMapping::new(regions, config, version) }
			.map_err(|error| EngineError::Vm { message: error.to_string() })?;
		self.mapping = Some(mapping);

		let mut frames = vec![CallFrame::default(); config.max_call_depth];
		let mut mode = ExecutionMode::Interpreted;
		let loader = executable.get_loader().clone();
		let (_, result) = {
			let mut vm = EbpfVm::new(loader, version, self, stack_len);
			vm.registers[1] = ebpf::MM_INPUT_START;
			vm.execute_program(executable, &mut mode, &mut frames)
		};
		self.mapping = None;
		drop((stack, heap));

		let result: Result<u64, EbpfError> = result.into();
		match result {
			Ok(0) => Ok(()),
			Ok(code) => Err(EngineError::Contract {
				message: self
					.error
					.take()
					.unwrap_or_else(|| format!("returned error code {code}")),
			}),
			Err(EbpfError::ExceededMaxInstructions) => Err(EngineError::OutOfGas),
			Err(EbpfError::SyscallError(_)) => Err(self
				.failure
				.take()
				.unwrap_or_else(|| EngineError::Contract {
					message: self.error.take().unwrap_or_else(|| "aborted".into()),
				})),
			Err(error) => Err(EngineError::Vm { message: format!("{} faulted: {error}", self.contract) }),
		}
	}

	/// Check each account against what the contract may change, and write
	/// what it changed to the overlay.
	fn flush_accounts(&mut self) -> Result<(), EngineError> {
		for index in 0..self.slots.len() {
			let slot = &self.slots[index];
			let input = self.input.as_slice();
			let header = &input[slot.offset..slot.offset + layout::ACCOUNT_HEADER];
			let len = u64::from_le_bytes(
				header[layout::ACCOUNT_DATA_LEN..layout::ACCOUNT_DATA_LEN + 8]
					.try_into()
					.expect("8 bytes"),
			) as usize;
			let invalid = |reason: &str| EngineError::InvalidAccount {
				reason: format!("{} {reason} {}", self.contract, slot.describe()),
			};
			let header_intact = header[..layout::ACCOUNT_DATA_LEN] == slot.header[..layout::ACCOUNT_DATA_LEN]
				&& header[layout::ACCOUNT_CAPACITY..] == slot.header[layout::ACCOUNT_CAPACITY..];
			if !header_intact {
				return Err(invalid("changed the header of"));
			}
			if len > slot.capacity {
				return Err(invalid("set a length beyond the capacity of"));
			}
			let start = slot.offset + layout::ACCOUNT_HEADER;
			let data = &input[start..start + len];
			if data == slot.data.as_slice() {
				continue;
			}
			if !slot.mutable() {
				return Err(invalid(if slot.own {
					"changed read-only"
				} else {
					"changed another contract's"
				}));
			}
			let data = data.to_vec();
			self.charge(gas::account_write(data.len()))?;
			let slot = &mut self.slots[index];
			self.session
				.lock()
				.storage_set(&slot.owner, &slot.id, (!data.is_empty()).then(|| data.clone()));
			slot.data = data;
		}
		Ok(())
	}

	/// Refresh accounts from the overlay after a nested invocation.
	fn reload_accounts(&mut self, indexes: &[usize]) -> Result<(), EngineError> {
		for &index in indexes {
			let slot = &self.slots[index];
			let data = self
				.session
				.lock()
				.storage_get(self.session.host(), &slot.owner, &slot.id)?
				.unwrap_or_default();
			if data.len() > slot.capacity {
				return Err(EngineError::InvalidAccount {
					reason: format!("{} grew beyond the room {} has for it", slot.describe(), self.contract),
				});
			}
			let start = slot.offset + layout::ACCOUNT_HEADER;
			let input = self.input.as_slice_mut();
			input[slot.offset + layout::ACCOUNT_DATA_LEN..slot.offset + layout::ACCOUNT_DATA_LEN + 8]
				.copy_from_slice(&(data.len() as u64).to_le_bytes());
			input[start..start + data.len()].copy_from_slice(&data);
			input[start + data.len()..start + slot.capacity].fill(0);
			self.slots[index].data = data;
		}
		Ok(())
	}

	fn charge(&mut self, cost: u64) -> Result<(), EngineError> {
		charge(&mut self.remaining, cost)
	}

	// Memory ----------------------------------------------------------------

	fn mapping(&self) -> &MemoryMapping {
		self.mapping.as_ref().expect("mapped while running")
	}

	fn read(&self, address: u64, len: u64) -> Result<Vec<u8>, EngineError> {
		if len == 0 {
			return Ok(Vec::new());
		}
		let buffer: Result<_, EbpfError> = self.mapping().map(AccessType::Load, address, len).into();
		let buffer = buffer.map_err(|error| EngineError::Vm { message: format!("{}: {error}", self.contract) })?;
		// SAFETY: the mapping checked that the range lies within one region,
		// and nothing writes to VM memory while a host function runs.
		Ok(unsafe { &*buffer.ptr() }.to_vec())
	}

	/// `len` bytes of writable VM memory at `address`.
	fn store(&mut self, address: u64, len: u64) -> Result<&mut [u8], EngineError> {
		let buffer: Result<_, EbpfError> = self.mapping().map(AccessType::Store, address, len).into();
		let buffer = buffer.map_err(|error| EngineError::Vm { message: format!("{}: {error}", self.contract) })?;
		// SAFETY: as in `read`; the region is writable and `len` bytes long,
		// and `&mut self` keeps this the only view while a host function runs.
		Ok(unsafe { &mut *buffer.ptr_mut() })
	}

	fn write(&mut self, address: u64, bytes: &[u8]) -> Result<(), EngineError> {
		if bytes.is_empty() {
			return Ok(());
		}
		self.store(address, bytes.len() as u64)?
			.copy_from_slice(bytes);
		Ok(())
	}

	fn read_address(&self, address: u64) -> Result<String, EngineError> {
		let bytes: [u8; ADDRESS_LEN] = self
			.read(address, ADDRESS_LEN as u64)?
			.try_into()
			.expect("address size");
		from_address(&Address(bytes))
	}

	fn read_amount(&self, address: u64) -> Result<BigUint, EngineError> {
		let bytes: [u8; 16] = self.read(address, 16)?.try_into().expect("u128 size");
		Ok(BigUint::from(u128::from_le_bytes(bytes)))
	}

	fn write_amount(&mut self, address: u64, amount: &BigUint, what: &str) -> Result<(), EngineError> {
		let amount =
			u128::try_from(amount).map_err(|_| ledger(format!("{what} of {amount} does not fit in a u128")))?;
		self.write(address, &amount.to_le_bytes())
	}

	fn read_text(&self, address: u64, len: u64, field: &str) -> Result<String, EngineError> {
		if len as usize > abi::MAX_TEXT {
			return Err(EngineError::Contract { message: format!("{field} is longer than {} bytes", abi::MAX_TEXT) });
		}
		String::from_utf8(self.read(address, len)?)
			.map_err(|_| EngineError::Contract { message: format!("{field} is not UTF-8") })
	}

	/// The `(ptr, len)` table of `count` slices at `address`.
	fn read_slice_table(&self, address: u64, count: u64) -> Result<Vec<(u64, u64)>, EngineError> {
		if count > 64 {
			return Err(EngineError::Contract { message: "too many slices".into() });
		}
		let table = self.read(address, count * 16)?;
		Ok(table
			.chunks_exact(16)
			.map(|pair| {
				let ptr = u64::from_le_bytes(pair[..8].try_into().expect("8 bytes"));
				let len = u64::from_le_bytes(pair[8..].try_into().expect("8 bytes"));
				(ptr, len)
			})
			.collect())
	}

	/// `count` `(ptr, len)` slices at `address`.
	fn read_slices(&self, address: u64, count: u64) -> Result<Vec<Vec<u8>>, EngineError> {
		self.read_slice_table(address, count)?
			.into_iter()
			.map(|(ptr, len)| self.read(ptr, len))
			.collect()
	}

	fn read_fields<const N: usize>(&self, address: u64, names: [&str; N]) -> Result<[String; N], EngineError> {
		let slices = self.read_slices(address, N as u64)?;
		let mut fields = names.map(|_| String::new());
		for ((field, bytes), name) in fields.iter_mut().zip(slices).zip(names) {
			if bytes.len() > abi::MAX_TEXT {
				return Err(EngineError::Contract {
					message: format!("{name} is longer than {} bytes", abi::MAX_TEXT),
				});
			}
			*field = String::from_utf8(bytes)
				.map_err(|_| EngineError::Contract { message: format!("{name} is not UTF-8") })?;
		}
		Ok(fields)
	}

	// Host functions ----------------------------------------------------------

	fn abort(&mut self, _: u64, _: u64, _: u64, _: u64, _: u64) -> Result<u64, EngineError> {
		Err(EngineError::Contract { message: self.error.take().unwrap_or_else(|| "aborted".into()) })
	}

	/// A panic, where it happened; its message, when the contract reported
	/// one first ([`syscall::ERROR`]), follows. The contract SDK reports
	/// panics this way, so contracts carry no code to format them.
	fn panic(&mut self, file: u64, len: u64, line: u64, column: u64, _: u64) -> Result<u64, EngineError> {
		let file = self.read_text(file, len, "file name")?;
		let location = format!("panicked at {file}:{line}:{column}");
		let message = match self.error.take() {
			Some(text) => format!("{location}: {text}"),
			None => location,
		};
		Err(EngineError::Contract { message })
	}

	fn decimal(&mut self, value: u64, signed: u64, out: u64, _: u64, _: u64) -> Result<u64, EngineError> {
		self.charge(gas::SYSCALL / 10)?;
		let bytes: [u8; 16] = self
			.read(value, 16)?
			.try_into()
			.map_err(|_| EngineError::Contract { message: "a decimal needs 16 bytes".into() })?;
		let text = if signed == 0 {
			u128::from_le_bytes(bytes).to_string()
		} else {
			i128::from_le_bytes(bytes).to_string()
		};
		self.write(out, text.as_bytes())?;
		Ok(text.len() as u64)
	}

	fn std_log(&mut self, address: u64, len: u64, _: u64, _: u64, _: u64) -> Result<u64, EngineError> {
		self.log(address, len, 0, 0, 0)
	}

	fn mem_move(&mut self, destination: u64, source: u64, len: u64, _: u64, _: u64) -> Result<u64, EngineError> {
		self.charge(gas::SYSCALL / 10 + gas::bytes(len as usize))?;
		let bytes = self.read(source, len)?;
		self.write(destination, &bytes)?;
		Ok(0)
	}

	fn mem_set(&mut self, destination: u64, value: u64, len: u64, _: u64, _: u64) -> Result<u64, EngineError> {
		self.charge(gas::SYSCALL / 10 + gas::bytes(len as usize))?;
		if len > 0 {
			// Fill in place: `len` is bounded by the mapping, never allocated.
			self.store(destination, len)?.fill(value as u8);
		}
		Ok(0)
	}

	fn mem_cmp(&mut self, a: u64, b: u64, len: u64, out: u64, _: u64) -> Result<u64, EngineError> {
		self.charge(gas::SYSCALL / 10 + gas::bytes(len as usize))?;
		let (a, b) = (self.read(a, len)?, self.read(b, len)?);
		let order = a
			.iter()
			.zip(&b)
			.find(|(x, y)| x != y)
			.map_or(0, |(x, y)| *x as i32 - *y as i32);
		self.write(out, &order.to_le_bytes())?;
		Ok(0)
	}

	fn log(&mut self, address: u64, len: u64, _: u64, _: u64, _: u64) -> Result<u64, EngineError> {
		self.charge(gas::SYSCALL + gas::bytes(len as usize))?;
		let len = len.min(abi::MAX_TEXT as u64);
		let message = String::from_utf8_lossy(&self.read(address, len)?).into_owned();
		self.session
			.logs
			.lock()
			.expect("logs lock")
			.push(Log { contract: self.contract.clone(), message });
		Ok(0)
	}

	fn attribute(&mut self, key: u64, key_len: u64, value: u64, value_len: u64, _: u64) -> Result<u64, EngineError> {
		self.charge(gas::SYSCALL + gas::bytes((key_len + value_len) as usize))?;
		let key = self.read_text(key, key_len, "attribute key")?;
		if key.is_empty() || key.starts_with('_') {
			return Err(EngineError::Contract { message: format!("attribute key {key:?} is empty or reserved") });
		}
		let value = self.read_text(value, value_len, "attribute value")?;
		self.attributes.push((key, value));
		Ok(0)
	}

	fn set_error(&mut self, address: u64, len: u64, _: u64, _: u64, _: u64) -> Result<u64, EngineError> {
		let len = len.min(abi::MAX_TEXT as u64);
		self.error = Some(String::from_utf8_lossy(&self.read(address, len)?).into_owned());
		Ok(0)
	}

	fn set_return_data(&mut self, address: u64, len: u64, _: u64, _: u64, _: u64) -> Result<u64, EngineError> {
		self.charge(gas::SYSCALL + gas::bytes(len as usize))?;
		if len as usize > abi::MAX_RETURN_DATA {
			return Err(EngineError::Contract {
				message: format!("return data is longer than {} bytes", abi::MAX_RETURN_DATA),
			});
		}
		self.return_data = Some(self.read(address, len)?);
		Ok(0)
	}

	fn get_return_data(&mut self, address: u64, max_len: u64, _: u64, _: u64, _: u64) -> Result<u64, EngineError> {
		let len = self.child_return.len();
		let copy = len.min(max_len as usize);
		self.charge(gas::SYSCALL + gas::bytes(copy))?;
		let data = self.child_return[..copy].to_vec();
		self.write(address, &data)?;
		Ok(len as u64)
	}

	fn sha256(&mut self, slices: u64, count: u64, out: u64, _: u64, _: u64) -> Result<u64, EngineError> {
		// Charge for the bytes before copying any of them.
		let table = self.read_slice_table(slices, count)?;
		let total = table
			.iter()
			.fold(0u64, |total, (_, len)| total.saturating_add(*len));
		self.charge(gas::SYSCALL + gas::sha256(total as usize))?;
		let mut hasher = Sha256::new();
		for (ptr, len) in table {
			hasher.update(self.read(ptr, len)?);
		}
		self.write(out, &hasher.finalize())?;
		Ok(0)
	}

	fn send(&mut self, to: u64, token: u64, amount: u64, external: u64, external_len: u64) -> Result<u64, EngineError> {
		self.charge(gas::SYSCALL + gas::LEDGER)?;
		let (to, token, amount) = (self.read_address(to)?, self.read_address(token)?, self.read_amount(amount)?);
		parse_account_of(&token, KeyPairType::TOKEN)?;
		let external = match external_len {
			0 => None,
			len => {
				let external = self.read_text(external, len, "external")?;
				check_text("external", &self.session.rules()?.external, &external)?;
				Some(external)
			}
		};
		positive(&amount)?;
		let session = self.session.clone();
		session
			.lock()
			.send(session.host(), &self.contract, &to, &token, &amount, external)?;
		Ok(0)
	}

	fn balance(&mut self, account: u64, token: u64, out: u64, _: u64, _: u64) -> Result<u64, EngineError> {
		self.charge(gas::SYSCALL)?;
		let (account, token) = (self.read_address(account)?, self.read_address(token)?);
		let session = self.session.clone();
		let balance = session.lock().balance(session.host(), &account, &token)?;
		self.write_amount(out, &balance, "balance")?;
		Ok(0)
	}

	fn supply(&mut self, token: u64, out: u64, _: u64, _: u64, _: u64) -> Result<u64, EngineError> {
		self.charge(gas::SYSCALL)?;
		let token = self.read_address(token)?;
		let session = self.session.clone();
		let Some(supply) = session.lock().supply(session.host(), &token)? else {
			return Ok(0);
		};
		self.write_amount(out, &supply, "supply")?;
		Ok(1)
	}

	fn set_info(&mut self, fields: u64, _: u64, _: u64, _: u64, _: u64) -> Result<u64, EngineError> {
		self.charge(gas::SYSCALL + gas::LEDGER)?;
		let [name, description, metadata] = self.read_fields(fields, ["name", "description", "metadata"])?;
		let rules = self.session.rules()?;
		check_text("name", &rules.name, &name)?;
		check_text("description", &rules.description, &description)?;
		check_text("metadata", &rules.metadata, &metadata)?;
		self.session
			.lock()
			.set_info(&self.contract, AccountInfo { name, description, metadata });
		Ok(0)
	}

	fn invoke(&mut self, contract: u64, metas: u64, count: u64, data: u64, data_len: u64) -> Result<u64, EngineError> {
		self.charge(gas::SYSCALL)?;
		let callee = self.read_address(contract)?;
		if count as usize > abi::MAX_ACCOUNTS || data_len as usize > abi::MAX_INSTRUCTION_DATA {
			return Err(EngineError::InvalidInstruction { reason: "too many accounts or too much data".into() });
		}
		let table = self.read(metas, count * 16)?;
		let data = self.read(data, data_len)?;
		let mut indexes = Vec::with_capacity(count as usize);
		let mut accounts = Vec::with_capacity(count as usize);
		let mut room = Vec::with_capacity(count as usize);
		for meta in table.chunks_exact(16) {
			let index = u64::from_le_bytes(meta[..8].try_into().expect("8 bytes")) as usize;
			let writable = u64::from_le_bytes(meta[8..].try_into().expect("8 bytes")) != 0;
			let slot = self
				.slots
				.get(index)
				.ok_or_else(|| EngineError::InvalidInstruction {
					reason: format!("{} passed account {index}, but has {}", self.contract, self.slots.len()),
				})?;
			if writable && !slot.writable {
				return Err(EngineError::InvalidInstruction {
					reason: format!("{} passed {} as writable, but it is read-only", self.contract, slot.describe()),
				});
			}
			indexes.push(index);
			room.push(slot.capacity);
			accounts.push(AccountMeta { owner: slot.owner.clone(), id: slot.id, writable });
		}

		// The callee reads accounts from the overlay: bring it up to date.
		self.flush_accounts()?;
		let session = self.session.clone();
		let outcome = invoke(
			&session,
			Request {
				contract: &callee,
				caller: &self.contract,
				funds: &[],
				accounts: &accounts,
				room: &room,
				data: &data,
			},
			self.remaining,
		);
		let outcome = match outcome {
			Ok(outcome) => outcome,
			Err(error) => {
				self.remaining = 0;
				return Err(error);
			}
		};
		self.remaining = outcome.remaining;
		self.child_return = outcome.return_data.unwrap_or_default();
		self.reload_accounts(&indexes)?;
		Ok(0)
	}
}

fn positive(amount: &BigUint) -> Result<(), EngineError> {
	if *amount == BigUint::ZERO {
		return Err(ledger("amount must be positive"));
	}
	Ok(())
}

pub(crate) fn check_text(field: &'static str, rule: &TextRule, value: &str) -> Result<(), EngineError> {
	rule.check(value)
		.map_err(|violation| EngineError::InvalidField { field, reason: format!("{violation:?}") })
}

/// Marks a host function's failure; the real error is kept in
/// [`Invocation::failure`].
#[derive(Debug)]
struct Aborted;

impl std::fmt::Display for Aborted {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.write_str("host function failed")
	}
}

impl std::error::Error for Aborted {}

macro_rules! host_functions {
	($($name:ident => $method:ident,)*) => {
		$(
			declare_builtin_function!(
				$name,
				fn rust(
					invocation: &mut Invocation,
					a: u64,
					b: u64,
					c: u64,
					d: u64,
					e: u64,
				) -> Result<u64, Box<dyn std::error::Error>> {
					match invocation.$method(a, b, c, d, e) {
						Ok(value) => Ok(value),
						Err(error) => {
							if invocation.failure.is_none() {
								invocation.failure = Some(error);
							}
							Err(Box::new(Aborted))
						}
					}
				}
			);
		)*
	};
}

host_functions! {
	AbortCall => abort,
	PanicCall => panic,
	StdLogCall => std_log,
	MemMoveCall => mem_move,
	MemSetCall => mem_set,
	MemCmpCall => mem_cmp,
	LogCall => log,
	AttributeCall => attribute,
	SetErrorCall => set_error,
	SetReturnDataCall => set_return_data,
	GetReturnDataCall => get_return_data,
	Sha256Call => sha256,
	SendCall => send,
	BalanceCall => balance,
	SupplyCall => supply,
	SetInfoCall => set_info,
	InvokeCall => invoke,
	DecimalCall => decimal,
}

fn register_host_functions(loader: &mut BuiltinProgram<Invocation>) -> Result<(), EngineError> {
	let failed = |error: solana_sbpf::elf::ElfError| EngineError::Setup {
		message: format!("registering host functions: {error}"),
	};
	loader
		.register_definition::<AbortCall>("abort")
		.map_err(failed)?;
	loader
		.register_definition::<PanicCall>(syscall::PANIC)
		.map_err(failed)?;
	loader
		.register_definition::<StdLogCall>("sol_log_")
		.map_err(failed)?;
	loader
		.register_definition::<MemMoveCall>(syscall::MEMCPY)
		.map_err(failed)?;
	loader
		.register_definition::<MemMoveCall>(syscall::MEMMOVE)
		.map_err(failed)?;
	loader
		.register_definition::<MemSetCall>(syscall::MEMSET)
		.map_err(failed)?;
	loader
		.register_definition::<MemCmpCall>(syscall::MEMCMP)
		.map_err(failed)?;
	loader
		.register_definition::<LogCall>(syscall::LOG)
		.map_err(failed)?;
	loader
		.register_definition::<AttributeCall>(syscall::ATTRIBUTE)
		.map_err(failed)?;
	loader
		.register_definition::<SetErrorCall>(syscall::ERROR)
		.map_err(failed)?;
	loader
		.register_definition::<SetReturnDataCall>(syscall::SET_RETURN_DATA)
		.map_err(failed)?;
	loader
		.register_definition::<GetReturnDataCall>(syscall::GET_RETURN_DATA)
		.map_err(failed)?;
	loader
		.register_definition::<Sha256Call>(syscall::SHA256)
		.map_err(failed)?;
	loader
		.register_definition::<SendCall>(syscall::SEND)
		.map_err(failed)?;
	loader
		.register_definition::<BalanceCall>(syscall::BALANCE)
		.map_err(failed)?;
	loader
		.register_definition::<SupplyCall>(syscall::SUPPLY)
		.map_err(failed)?;
	loader
		.register_definition::<SetInfoCall>(syscall::SET_INFO)
		.map_err(failed)?;
	loader
		.register_definition::<InvokeCall>(syscall::INVOKE)
		.map_err(failed)?;
	loader
		.register_definition::<DecimalCall>(syscall::DECIMAL)
		.map_err(failed)?;
	Ok(())
}
