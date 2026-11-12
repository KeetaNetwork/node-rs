//! A contract's interface: what its instruction data, state accounts and
//! views look like, so explorers and other tools can decode them.
//!
//! Off-chain only. A contract describes itself with a function named
//! `contract_interface`, which `keeta-contract interface` (anchor-contracts)
//! calls to print the JSON:
//!
//! ```ignore
//! #[cfg(not(target_os = "solana"))]
//! pub fn contract_interface() -> keetanetwork_contract_std::interface::Interface {
//!     use keetanetwork_contract_std::interface::{Interface, Seed};
//!     Interface::new("keeta-pet")
//!         .instruction::<Instruction>()
//!         .account::<Config>("config", &[Seed::bytes(b"config")])
//!         .account::<Pet>("pet", &[Seed::bytes(b"pet"), Seed::address("owner")])
//!         .view::<Vec<PetView>>("Pets")
//! }
//! ```
//!
//! The types derive `BorshSchema` (borsh's `unstable__schema` feature,
//! which this crate turns on for off-chain builds), so a contract does
//! `#[cfg_attr(not(target_os = "solana"), derive(borsh::BorshSchema))]`.
//! On-chain builds are unchanged by any of this.
//!
//! The JSON (`format: "keeta-contract-interface"`):
//!
//! ```text
//! {
//!   "format": "keeta-contract-interface",
//!   "name": "keeta-pet",
//!   "instruction": "Instruction",               // the type of the instruction data
//!   "accounts": [                                // state accounts, by the seeds of their id
//!     { "name": "pet", "type": "Pet",
//!       "seeds": [{ "bytes": "706574" }, { "address": "owner" }] }   // hex bytes, or an Address
//!   ],
//!   "views": [{ "instruction": "Pets", "returns": "Vec<PetView>" }], // variants that return data
//!   "types": {                                   // borsh's schema, every type by its name
//!     "Pet": { "kind": "struct", "fields": [{ "name": "owner", "type": "Address" }, ...] },
//!     "Instruction": { "kind": "enum", "tagWidth": 1,
//!                      "variants": [{ "discriminant": 0, "name": "Init", "type": "InstructionInit" }, ...] },
//!     "String": { "kind": "sequence", "lengthWidth": 4, "elements": "u8" },
//!     "u64": { "kind": "primitive", "size": 8 },
//!     "Address": { "kind": "address" },          // 34 bytes: a Keeta account, shown as keeta_...
//!     ...
//!   }
//! }
//! ```
//!
//! Struct fields are `{ name, type }` (named) or bare type names (tuple
//! structs); a struct without fields has `fields: []`. Sequences have a
//! `length` instead of `lengthWidth` when their length is fixed (arrays).

use std::collections::BTreeMap;
use std::fmt::Write;

use borsh::schema::{BorshSchema, Declaration, Definition, Fields};

use crate::abi::{Address, ADDRESS_LEN};

impl BorshSchema for Address {
	fn add_definitions_recursively(definitions: &mut BTreeMap<Declaration, Definition>) {
		// Borsh sees 34 bytes; the interface marks them as an address.
		let definition = Definition::Sequence {
			length_width: Definition::ARRAY_LENGTH_WIDTH,
			length_range: ADDRESS_LEN as u64..=ADDRESS_LEN as u64,
			elements: u8::declaration(),
		};
		borsh::schema::add_definition(Self::declaration(), definition, definitions);
		u8::add_definitions_recursively(definitions);
	}

	fn declaration() -> Declaration {
		"Address".into()
	}
}

/// One seed of a state account's id (`state_id(&[seeds...])`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Seed {
	/// Fixed bytes, such as `b"config"`
	Bytes(Vec<u8>),
	/// A Keeta account's 34-byte address, named for what it is (`owner`)
	Address(String),
}

impl Seed {
	/// Fixed bytes.
	pub fn bytes(bytes: &[u8]) -> Self {
		Self::Bytes(bytes.to_vec())
	}

	/// An account's address, which differs from one state account to the next.
	pub fn address(name: &str) -> Self {
		Self::Address(name.into())
	}
}

struct AccountKind {
	name: String,
	declaration: Declaration,
	seeds: Vec<Seed>,
}

/// A contract's interface; see the module documentation.
pub struct Interface {
	name: String,
	instruction: Option<Declaration>,
	accounts: Vec<AccountKind>,
	views: Vec<(String, Declaration)>,
	definitions: BTreeMap<Declaration, Definition>,
}

impl Interface {
	/// An interface for the contract named `name` (its package, usually).
	pub fn new(name: &str) -> Self {
		Self {
			name: name.into(),
			instruction: None,
			accounts: Vec::new(),
			views: Vec::new(),
			definitions: BTreeMap::new(),
		}
	}

	/// The type the contract decodes its instruction data as.
	pub fn instruction<T: BorshSchema>(mut self) -> Self {
		T::add_definitions_recursively(&mut self.definitions);
		self.instruction = Some(T::declaration());
		self
	}

	/// A kind of state account: what it holds, and the seeds of its id.
	pub fn account<T: BorshSchema>(mut self, name: &str, seeds: &[Seed]) -> Self {
		T::add_definitions_recursively(&mut self.definitions);
		self.accounts
			.push(AccountKind { name: name.into(), declaration: T::declaration(), seeds: seeds.to_vec() });
		self
	}

	/// An instruction variant that returns data (`set_return_data`), and the type it returns.
	pub fn view<T: BorshSchema>(mut self, instruction: &str) -> Self {
		T::add_definitions_recursively(&mut self.definitions);
		self.views.push((instruction.into(), T::declaration()));
		self
	}

	/// The interface as JSON.
	pub fn to_json(&self) -> String {
		let mut out = String::new();
		out.push_str("{\"format\":\"keeta-contract-interface\",\"name\":");
		string(&mut out, &self.name);
		out.push_str(",\"instruction\":");
		match &self.instruction {
			Some(declaration) => string(&mut out, declaration),
			None => out.push_str("null"),
		}

		out.push_str(",\"accounts\":[");
		for (index, account) in self.accounts.iter().enumerate() {
			if index > 0 {
				out.push(',');
			}
			out.push_str("{\"name\":");
			string(&mut out, &account.name);
			out.push_str(",\"type\":");
			string(&mut out, &account.declaration);
			out.push_str(",\"seeds\":[");
			for (position, seed) in account.seeds.iter().enumerate() {
				if position > 0 {
					out.push(',');
				}
				match seed {
					Seed::Bytes(bytes) => {
						out.push_str("{\"bytes\":\"");
						for byte in bytes {
							let _ = write!(out, "{byte:02x}");
						}
						out.push_str("\"}");
					}
					Seed::Address(name) => {
						out.push_str("{\"address\":");
						string(&mut out, name);
						out.push('}');
					}
				}
			}
			out.push_str("]}");
		}

		out.push_str("],\"views\":[");
		for (index, (instruction, returns)) in self.views.iter().enumerate() {
			if index > 0 {
				out.push(',');
			}
			out.push_str("{\"instruction\":");
			string(&mut out, instruction);
			out.push_str(",\"returns\":");
			string(&mut out, returns);
			out.push('}');
		}

		out.push_str("],\"types\":{");
		for (index, (declaration, definition)) in self.definitions.iter().enumerate() {
			if index > 0 {
				out.push(',');
			}
			string(&mut out, declaration);
			out.push(':');
			if declaration == "Address" {
				out.push_str("{\"kind\":\"address\"}");
			} else {
				definition_json(&mut out, definition);
			}
		}
		out.push_str("}}");
		out
	}
}

fn definition_json(out: &mut String, definition: &Definition) {
	match definition {
		Definition::Primitive(size) => {
			let _ = write!(out, "{{\"kind\":\"primitive\",\"size\":{size}}}");
		}
		Definition::Sequence { length_width, length_range, elements } => {
			out.push_str("{\"kind\":\"sequence\",");
			if *length_width == Definition::ARRAY_LENGTH_WIDTH {
				let _ = write!(out, "\"length\":{}", length_range.start());
			} else {
				let _ = write!(out, "\"lengthWidth\":{length_width}");
			}
			out.push_str(",\"elements\":");
			string(out, elements);
			out.push('}');
		}
		Definition::Tuple { elements } => {
			out.push_str("{\"kind\":\"tuple\",\"elements\":[");
			for (index, element) in elements.iter().enumerate() {
				if index > 0 {
					out.push(',');
				}
				string(out, element);
			}
			out.push_str("]}");
		}
		Definition::Enum { tag_width, variants } => {
			let _ = write!(out, "{{\"kind\":\"enum\",\"tagWidth\":{tag_width},\"variants\":[");
			for (index, (discriminant, name, declaration)) in variants.iter().enumerate() {
				if index > 0 {
					out.push(',');
				}
				let _ = write!(out, "{{\"discriminant\":{discriminant},\"name\":");
				string(out, name);
				out.push_str(",\"type\":");
				string(out, declaration);
				out.push('}');
			}
			out.push_str("]}");
		}
		Definition::Struct { fields } => {
			out.push_str("{\"kind\":\"struct\",\"fields\":[");
			match fields {
				Fields::NamedFields(named) => {
					for (index, (name, declaration)) in named.iter().enumerate() {
						if index > 0 {
							out.push(',');
						}
						out.push_str("{\"name\":");
						string(out, name);
						out.push_str(",\"type\":");
						string(out, declaration);
						out.push('}');
					}
				}
				Fields::UnnamedFields(unnamed) => {
					for (index, declaration) in unnamed.iter().enumerate() {
						if index > 0 {
							out.push(',');
						}
						string(out, declaration);
					}
				}
				Fields::Empty => {}
			}
			out.push_str("]}");
		}
	}
}

/// A JSON string.
fn string(out: &mut String, text: &str) {
	out.push('"');
	for character in text.chars() {
		match character {
			'"' => out.push_str("\\\""),
			'\\' => out.push_str("\\\\"),
			'\n' => out.push_str("\\n"),
			'\r' => out.push_str("\\r"),
			'\t' => out.push_str("\\t"),
			control if (control as u32) < 0x20 => {
				let _ = write!(out, "\\u{:04x}", control as u32);
			}
			other => out.push(other),
		}
	}
	out.push('"');
}

#[cfg(test)]
mod tests {
	use super::*;

	#[derive(borsh::BorshSchema)]
	#[allow(dead_code)]
	enum Instruction {
		Set { value: u64, note: String },
		Show,
	}

	#[derive(borsh::BorshSchema)]
	#[allow(dead_code)]
	struct Record {
		owner: Address,
		value: Option<u64>,
	}

	#[test]
	fn describes_instructions_accounts_and_views() {
		let json = Interface::new("example")
			.instruction::<Instruction>()
			.account::<Record>("record", &[Seed::bytes(b"record"), Seed::address("owner")])
			.view::<Vec<Record>>("Show")
			.to_json();
		assert!(json.starts_with(
			"{\"format\":\"keeta-contract-interface\",\"name\":\"example\",\"instruction\":\"Instruction\""
		));
		assert!(json.contains("\"accounts\":[{\"name\":\"record\",\"type\":\"Record\",\"seeds\":[{\"bytes\":\"7265636f7264\"},{\"address\":\"owner\"}]}]"));
		assert!(json.contains("\"views\":[{\"instruction\":\"Show\",\"returns\":\"Vec<Record>\"}]"));
		assert!(json.contains("\"Address\":{\"kind\":\"address\"}"));
		assert!(json.contains("\"Record\":{\"kind\":\"struct\",\"fields\":[{\"name\":\"owner\",\"type\":\"Address\"},{\"name\":\"value\",\"type\":\"Option<u64>\"}]}"));
		assert!(json.contains("\"discriminant\":0,\"name\":\"Set\""));
		assert!(json.contains("\"String\":{\"kind\":\"sequence\",\"lengthWidth\":4,\"elements\":\"u8\"}"));
	}

	#[test]
	fn escapes_strings() {
		let mut out = String::new();
		string(&mut out, "a\"b\\c\n\u{1}");
		assert_eq!(out, "\"a\\\"b\\\\c\\n\\u0001\"");
	}
}
