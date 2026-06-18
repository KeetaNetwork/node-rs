use std::env;
use std::fs;
use std::path::Path;

use serde_json::Value;

use keetanetwork_utils::build::{compile_asn1_directory_with_full_config, Asn1CompileConfig};

fn main() {
	// Get OUT_DIR for generated files (required by cargo for publishable crates)
	let out_dir = env::var("OUT_DIR").expect("OUT_DIR must be set by cargo");
	let generated_dir = Path::new(&out_dir).join("generated");

	// Ensure the generated directory exists
	fs::create_dir_all(&generated_dir).expect("Failed to create generated directory");

	let generated_dir_str = generated_dir
		.to_str()
		.expect("OUT_DIR path must be valid UTF-8");

	// Generate OID schema tokens
	generate_schema();
	// Generate OIDs from JSON
	generate_oids_from_json(generated_dir_str);

	// Use OUT_DIR includes pattern for cargo publish compatibility
	let config = Asn1CompileConfig::new("asn1", generated_dir_str)
		.with_out_dir_includes(true)
		.with_strip_prebuilt_methods(true)
		.with_methods_to_strip("algorithm_identifier_definitions", vec!["new"])
		.with_methods_to_strip("subject_public_key_info_definitions", vec!["new"])
		.with_public_modules(vec!["iso20022"]);

	if let Err(e) = compile_asn1_directory_with_full_config(&config) {
		panic!("Failed to compile ASN.1 files: {e}");
	}

	// Substitute the canonical-DER `GeneralizedTime` type in block.rs and
	// vote.rs with `Asn1Time`, which preserves trailing zeros to match
	// the reference TypeScript transport format.
	rewrite_generalized_time(generated_dir_str, "block.rs");
	rewrite_generalized_time(generated_dir_str, "vote.rs");

	// Generate From implementations for wrapper types
	generate_from_implementations(generated_dir_str);
}

fn rewrite_generalized_time(generated_dir: &str, file_name: &str) {
	let path = Path::new(generated_dir).join(file_name);
	let Ok(original) = fs::read_to_string(&path) else {
		return;
	};

	let imports_replacement = "use rasn::prelude::*;\nuse crate::Asn1Time as GeneralizedTime;";
	let rewritten = original.replace("use rasn::prelude::*;", imports_replacement);
	if rewritten != original {
		fs::write(&path, rewritten).expect("post-process generated module must succeed");
	}
}

fn generate_sequence_fields_with_context_tags(
	schema_content: &mut String,
	fields: &serde_json::Map<String, Value>,
	field_order_value: Option<&Value>,
) {
	// Get field order
	let field_order: Vec<String> = if let Some(order_array) = field_order_value.and_then(|v| v.as_array()) {
		order_array
			.iter()
			.filter_map(|v| v.as_str())
			.map(|s| s.to_string())
			.collect()
	} else {
		fields.keys().cloned().collect()
	};

	for (index, field_name) in field_order.iter().enumerate() {
		if let Some(field_info) = fields.get(field_name) {
			if let (Some(field_type), Some(optional)) = (field_info["type"].as_str(), field_info["optional"].as_bool())
			{
				let optional_str = if optional {
					" OPTIONAL"
				} else {
					""
				};

				// Use EXPLICIT context tagging for each field
				schema_content
					.push_str(&format!("        {field_name:<17} [{index}] EXPLICIT {field_type}{optional_str},\n"));
			}
		}
	}
}

fn generate_schema() {
	let oids = load_oids_json();
	let dest_path = Path::new("asn1").join("iso20022.asn");
	let mut schema_content = String::new();

	// Add ASN.1 module header
	schema_content.push_str(
		"Iso20022 DEFINITIONS AUTOMATIC TAGS ::= BEGIN

",
	);

	// Generate all type definitions
	generate_primitive_types(&oids, &mut schema_content);
	generate_sensitive_primitive_types(&oids, &mut schema_content);

	schema_content.push('\n');

	generate_choice_types(&oids, &mut schema_content);
	generate_sensitive_sequence_types(&oids, &mut schema_content);
	generate_iso20022_sequence_types(&oids, &mut schema_content);
	generate_sensitive_choice_types(&oids, &mut schema_content);
	generate_enumerated_types(&oids, &mut schema_content);

	// Add module footer
	schema_content.push_str("END\n");

	// Ensure the asn1 directory exists
	if let Some(parent) = dest_path.parent() {
		fs::create_dir_all(parent).expect("Failed to create asn1 directory");
	}

	ensure_single_newline_ending(&mut schema_content);
	fs::write(&dest_path, schema_content).expect("Failed to write iso20022.asn");
}

fn generate_primitive_types(oids: &Value, schema_content: &mut String) {
	if let Some(primitives) = oids["iso20022_types"]["primitives"].as_object() {
		let mut primitive_items: Vec<_> = primitives.iter().collect();
		sort_by_oid(&mut primitive_items, |(_, info)| *info);

		for (name, info) in primitive_items {
			if let (Some(oid_array), Some(type_str)) = (info["oid"].as_array(), info["type"].as_str()) {
				let oid_comment = format_oid_comment(oid_array);
				let padded_name = format!("{:<21}", format!("{} ::= {}", name, type_str));
				schema_content.push_str(&format!("    {padded_name} --{oid_comment}\n"));
			}
		}
	}
}

fn generate_sensitive_primitive_types(oids: &Value, schema_content: &mut String) {
	if let Some(sensitive_attrs) = oids["sensitive_attributes"].as_object() {
		let mut simple_attrs: Vec<_> = sensitive_attrs
			.iter()
			.filter(|(_, info)| matches!(info["type"].as_str(), Some("UTF8String") | Some("GeneralizedTime")))
			.collect();

		sort_by_oid(&mut simple_attrs, |(_, info)| *info);

		for (_name, info) in simple_attrs {
			if let (Some(oid_array), Some(type_str), Some(token)) =
				(info["oid"].as_array(), info["type"].as_str(), info["token"].as_str())
			{
				let oid_comment = format_oid_comment(oid_array);
				let padded_name = format!("{:<21}", format!("{} ::= {}", token, type_str));
				schema_content.push_str(&format!("    {padded_name} --{oid_comment}\n"));
			}
		}
	}
}

fn generate_choice_types(oids: &Value, schema_content: &mut String) {
	if let Some(choices) = oids["iso20022_types"]["choices"].as_object() {
		let mut choice_items: Vec<_> = choices.iter().collect();
		sort_by_oid(&mut choice_items, |(_, info)| *info);

		for (name, info) in choice_items {
			if let (Some(oid_array), Some(choices_obj)) = (info["oid"].as_array(), info["choices"].as_object()) {
				let oid_comment = format_oid_comment(oid_array);
				schema_content.push_str(&format!("    {name} ::= CHOICE {{ -- {oid_comment}\n"));

				generate_choice_fields(schema_content, choices_obj);
				schema_content.push_str("    }\n\n");
			}
		}
	}
}

fn generate_sensitive_sequence_types(oids: &Value, schema_content: &mut String) {
	if let Some(sensitive_attrs) = oids["sensitive_attributes"].as_object() {
		let mut sequence_attrs: Vec<_> = sensitive_attrs
			.iter()
			.filter(|(_, info)| info["type"].as_str() == Some("SEQUENCE"))
			.collect();

		sort_by_oid(&mut sequence_attrs, |(_, info)| *info);

		for (_, info) in sequence_attrs {
			if let (Some(oid_array), Some(token), Some(fields)) =
				(info["oid"].as_array(), info["token"].as_str(), info["fields"].as_object())
			{
				let oid_comment = format_oid_comment(oid_array);
				schema_content.push_str(&format!("    {token} ::= SEQUENCE {{ --{oid_comment}\n"));

				// Pass field_order if available
				generate_sequence_fields_with_context_tags(schema_content, fields, info.get("field_order"));
				close_asn1_structure(schema_content);
			}
		}
	}
}

fn generate_iso20022_sequence_types(oids: &Value, schema_content: &mut String) {
	if let Some(sequences) = oids["iso20022_types"]["sequences"].as_object() {
		let mut sequence_items: Vec<_> = sequences.iter().collect();
		sort_by_oid(&mut sequence_items, |(_, info)| *info);

		for (name, info) in sequence_items {
			if let (Some(oid_array), Some(fields)) = (info["oid"].as_array(), info["fields"].as_object()) {
				let oid_comment = format_oid_comment(oid_array);
				schema_content.push_str(&format!("    {name} ::= SEQUENCE {{ --{oid_comment}\n"));

				// Use context tags with field_order
				generate_sequence_fields_with_context_tags(schema_content, fields, info.get("field_order"));
				close_asn1_structure(schema_content);
			}
		}
	}
}

fn generate_sensitive_choice_types(oids: &Value, schema_content: &mut String) {
	if let Some(sensitive_attrs) = oids["sensitive_attributes"].as_object() {
		let mut choice_attrs: Vec<_> = sensitive_attrs
			.iter()
			.filter(|(_, info)| info["type"].as_str() == Some("CHOICE"))
			.collect();

		sort_by_oid(&mut choice_attrs, |(_, info)| *info);

		for (_, info) in choice_attrs {
			if let (Some(oid_array), Some(token), Some(choices_obj)) =
				(info["oid"].as_array(), info["token"].as_str(), info["choices"].as_object())
			{
				let oid_comment = format_oid_comment(oid_array);
				schema_content.push_str(&format!("    {token} ::= CHOICE {{ --{oid_comment}\n"));

				generate_choice_fields(schema_content, choices_obj);
				schema_content.push_str("    }\n\n");
			}
		}
	}
}

fn generate_enumerated_types(oids: &Value, schema_content: &mut String) {
	if let Some(enumerations) = oids["iso20022_types"]["enumerations"].as_object() {
		let mut enum_items: Vec<_> = enumerations.iter().collect();
		sort_by_oid(&mut enum_items, |(_, info)| *info);

		for (name, info) in enum_items {
			if let (Some(oid_array), Some(values)) = (info["oid"].as_array(), info["values"].as_array()) {
				let oid_comment = format_oid_comment(oid_array);
				schema_content.push_str(&format!("    {name} ::= ENUMERATED {{ --{oid_comment}\n"));

				let enum_values: Vec<String> = values
					.iter()
					.filter_map(|v| v.as_str())
					.map(|s| s.to_string())
					.collect();
				schema_content.push_str(&format!("        {}\n", enum_values.join(", ")));
				schema_content.push_str("    }\n\n");
			}
		}
	}
}

fn format_oid_comment(oid_array: &[Value]) -> String {
	let numbers: Vec<String> = oid_array
		.iter()
		.filter_map(|v| v.as_u64())
		.map(|n| n.to_string())
		.collect();
	numbers.join(".")
}

/// Helper function to sort items by their OID arrays
fn sort_by_oid<T>(items: &mut [T], get_info: impl Fn(&T) -> &Value) {
	items.sort_by_key(|item| {
		get_info(item)["oid"]
			.as_array()
			.map(|arr| arr.iter().filter_map(|v| v.as_u64()).collect::<Vec<_>>())
			.unwrap_or_default()
	});
}

/// Helper function to remove trailing comma and close ASN.1 structure
fn close_asn1_structure(schema_content: &mut String) {
	// Remove the trailing comma and newline, add closing brace
	if schema_content.ends_with(",\n") {
		schema_content.truncate(schema_content.len() - 2);
		schema_content.push('\n');
	}
	schema_content.push_str("    }\n\n");
}

/// Helper function to generate SEQUENCE field definitions from JSON fields
fn _generate_sequence_fields(schema_content: &mut String, fields: &serde_json::Map<String, Value>) {
	// Get field order if available
	let field_order: Vec<String> = if let Some(order_array) = fields.get("field_order").and_then(|v| v.as_array()) {
		order_array
			.iter()
			.filter_map(|v| v.as_str())
			.map(|s| s.to_string())
			.collect()
	} else {
		fields.keys().cloned().collect()
	};

	for (index, field_name) in field_order.iter().enumerate() {
		if let Some(field_info) = fields.get(field_name) {
			if let (Some(field_type), Some(optional)) = (field_info["type"].as_str(), field_info["optional"].as_bool())
			{
				let optional_str = if optional {
					" OPTIONAL"
				} else {
					""
				};

				// Add context tag with explicit tagging
				schema_content
					.push_str(&format!("        {field_name:<17} [{index}] EXPLICIT {field_type}{optional_str},\n"));
			}
		}
	}
}

/// Helper function to generate CHOICE field definitions from JSON choices
fn generate_choice_fields(schema_content: &mut String, choices_obj: &serde_json::Map<String, Value>) {
	let choice_entries: Vec<_> = choices_obj.iter().collect();
	for (i, (choice_name, choice_info)) in choice_entries.iter().enumerate() {
		if let Some(choice_type) = choice_info["type"].as_str() {
			let comma = if i == choice_entries.len() - 1 {
				""
			} else {
				","
			};

			schema_content.push_str(&format!("        {choice_name:<17} [{i}] EXPLICIT {choice_type}{comma}\n"));
		}
	}
}

/// Helper function to load and parse the oids.json file
fn load_oids_json() -> Value {
	println!("cargo:rerun-if-changed=oids.json");

	let json_content = fs::read_to_string("oids.json").expect("Failed to read oids.json");
	serde_json::from_str(&json_content).expect("Failed to parse oids.json")
}

fn generate_oids_from_json(path: &str) {
	let oids = load_oids_json();

	let dest_path = Path::new(path).join("oids.rs");

	// Ensure the directory exists
	if let Some(parent) = dest_path.parent() {
		fs::create_dir_all(parent).expect("Failed to create generated directory");
	}

	let mut generated_code = String::new();

	// Add imports and header
	generated_code.push_str(
		r#"
use alloc::borrow::Cow;
use alloc::collections::BTreeMap;
use rasn::types::ObjectIdentifier;

"#,
	);

	emit_algorithm_constants(&oids, &mut generated_code);
	emit_crypto_typed_module(&oids, &mut generated_code);
	emit_plain_attribute_constants(&oids, &mut generated_code);
	emit_keeta_module(&oids, &mut generated_code);
	emit_algorithm_attributes_map(&oids, &mut generated_code);
	emit_plain_attributes_map(&oids, &mut generated_code);

	ensure_single_newline_ending(&mut generated_code);
	fs::write(&dest_path, generated_code).expect("OUT_DIR must be writable during build");
}

/// Resolve the constant name used for a plain certificate attribute.
fn plain_attr_const_name(name: &str) -> String {
	match name {
		"postalCode" => "ADDRESS_POSTAL_CODE".to_string(),
		_ => format!("ADDRESS_{}", name.to_uppercase()),
	}
}

fn emit_algorithm_constants(oids: &Value, generated_code: &mut String) {
	let Some(algorithms) = oids["algorithms"].as_object() else {
		return;
	};

	generated_code.push_str("// Algorithm OID constants\n");
	for (name, oid_array) in algorithms {
		let const_name = name.to_uppercase().replace('-', "_");
		let oid_values = format_oid_array(oid_array);
		generated_code.push_str(&format!(
			"pub const {const_name}: ObjectIdentifier = ObjectIdentifier::new_unchecked(Cow::Borrowed(&{oid_values}));\n"
		));
	}
	generated_code.push('\n');
}

fn emit_crypto_typed_module(oids: &Value, generated_code: &mut String) {
	let Some(crypto) = oids["crypto"].as_object() else {
		return;
	};

	generated_code.push_str("/// Typed OID constants for the rasn backend.\n");
	generated_code.push_str("/// These are const-evaluated at compile time, avoiding runtime panics.\n");
	generated_code.push_str("pub mod typed {\n");
	generated_code.push_str("    use super::*;\n\n");
	for (name, crypto_info) in crypto {
		let Some(oid_array) = crypto_info["oid"].as_array() else {
			continue;
		};

		let const_name = name.to_uppercase().replace('-', "_");
		let oid_values = format_oid_array(&Value::Array(oid_array.clone()));

		if let Some(description) = crypto_info["description"].as_str() {
			generated_code.push_str(&format!("    /// {description}\n"));
		}

		generated_code.push_str(&format!(
			"    pub const {const_name}: ObjectIdentifier = ObjectIdentifier::new_unchecked(Cow::Borrowed(&{oid_values}));\n"
		));
	}
	generated_code.push_str("}\n\n");
}

fn emit_plain_attribute_constants(oids: &Value, generated_code: &mut String) {
	let Some(plain_attrs) = oids["plain_attributes"].as_object() else {
		return;
	};

	generated_code.push_str("// Plain attribute OID constants\n");
	for (name, attr_info) in plain_attrs {
		let Some(oid_array) = attr_info["oid"].as_array() else {
			continue;
		};

		let const_name = plain_attr_const_name(name);
		let oid_values = format_oid_array(&Value::Array(oid_array.clone()));

		if let Some(description) = attr_info["description"].as_str() {
			generated_code.push_str(&format!("/// {description}\n"));
		}
		if let Some(reference) = attr_info["reference"].as_str() {
			generated_code.push_str(&format!("/// # References\n/// - [{reference}]({reference})\n"));
		}

		generated_code.push_str(&format!(
			"pub const {const_name}: ObjectIdentifier = ObjectIdentifier::new_unchecked(Cow::Borrowed(&{oid_values}));\n"
		));
	}
	generated_code.push('\n');
}

fn emit_keeta_module(oids: &Value, generated_code: &mut String) {
	generated_code.push_str("pub mod keeta {\n");
	generated_code.push_str("    use super::*;\n\n");

	emit_extension_constants(oids, generated_code);
	emit_sensitive_attribute_constants(oids, generated_code);
	emit_sensitive_attributes_map(oids, generated_code);

	generated_code.push_str("}\n\n");
}

fn emit_extension_constants(oids: &Value, generated_code: &mut String) {
	let Some(extensions) = oids["extensions"].as_object() else {
		return;
	};

	generated_code.push_str("    // Extension OID constants\n");
	for (name, ext_info) in extensions {
		let Some(oid_array) = ext_info["oid"].as_array() else {
			continue;
		};

		let const_name = camel_to_snake_upper(name);
		let oid_values = format_oid_array(&Value::Array(oid_array.clone()));
		generated_code.push_str(&format!(
			"    pub const {const_name}_EXTENSION: ObjectIdentifier = ObjectIdentifier::new_unchecked(Cow::Borrowed(&{oid_values}));\n"
		));
	}
	generated_code.push('\n');
}

fn emit_sensitive_attribute_constants(oids: &Value, generated_code: &mut String) {
	let Some(sensitive_attrs) = oids["sensitive_attributes"].as_object() else {
		return;
	};

	generated_code.push_str("    // Sensitive attribute OID constants\n");
	for (name, attr_info) in sensitive_attrs {
		let Some(oid_array) = attr_info["oid"].as_array() else {
			continue;
		};

		let const_name = camel_to_snake_upper(name);
		let oid_values = format_oid_array(&Value::Array(oid_array.clone()));

		if let Some(description) = attr_info["description"].as_str() {
			generated_code.push_str(&format!("    /// {description}\n"));
		}

		generated_code.push_str(&format!(
			"    pub const {const_name}: ObjectIdentifier = ObjectIdentifier::new_unchecked(Cow::Borrowed(&{oid_values}));\n"
		));
	}
	generated_code.push('\n');
}

fn emit_sensitive_attributes_map(oids: &Value, generated_code: &mut String) {
	let Some(sensitive_attrs) = oids["sensitive_attributes"].as_object() else {
		return;
	};

	generated_code.push_str("    lazy_static::lazy_static! {\n");
	generated_code.push_str("        /// OID database for sensitive certificate attributes.\n");
	generated_code
		.push_str("        pub static ref SENSITIVE_ATTRIBUTES: BTreeMap<&'static str, ObjectIdentifier> = {\n");
	generated_code.push_str("            [\n");
	for name in sensitive_attrs.keys() {
		let const_name = camel_to_snake_upper(name);
		generated_code.push_str(&format!("                (\"{name}\", {const_name}),\n"));
	}
	generated_code.push_str("            ]\n");
	generated_code.push_str("            .iter()\n");
	generated_code.push_str("            .cloned()\n");
	generated_code.push_str("            .collect()\n");
	generated_code.push_str("        };\n");
	generated_code.push_str("    }\n");
}

fn emit_algorithm_attributes_map(oids: &Value, generated_code: &mut String) {
	let Some(algorithms) = oids["algorithms"].as_object() else {
		return;
	};

	generated_code.push_str("lazy_static::lazy_static! {\n");
	generated_code.push_str("    /// OID database for sensitive attribute algorithms.\n");
	generated_code.push_str("    pub static ref ALGORITHM_ATTRIBUTES: BTreeMap<&'static str, ObjectIdentifier> = {\n");
	generated_code.push_str("        [\n");
	for name in algorithms.keys() {
		let const_name = name.to_uppercase().replace('-', "_");
		generated_code.push_str(&format!("            (\"{name}\", {const_name}),\n"));
	}
	generated_code.push_str("        ]\n");
	generated_code.push_str("        .iter()\n");
	generated_code.push_str("        .cloned()\n");
	generated_code.push_str("        .collect()\n");
	generated_code.push_str("    };\n");
	generated_code.push_str("}\n\n");
}

fn emit_plain_attributes_map(oids: &Value, generated_code: &mut String) {
	let Some(plain_attrs) = oids["plain_attributes"].as_object() else {
		return;
	};

	generated_code.push_str("lazy_static::lazy_static! {\n");
	generated_code.push_str("    /// OID database for plain certificate attributes.\n");
	generated_code.push_str("    pub static ref PLAIN_ATTRIBUTES: BTreeMap<&'static str, ObjectIdentifier> = {\n");
	generated_code.push_str("        [\n");
	for name in plain_attrs.keys() {
		let const_name = plain_attr_const_name(name);
		generated_code.push_str(&format!("            (\"{name}\", {const_name}),\n"));
	}
	generated_code.push_str("        ]\n");
	generated_code.push_str("        .iter()\n");
	generated_code.push_str("        .cloned()\n");
	generated_code.push_str("        .collect()\n");
	generated_code.push_str("    };\n");
	generated_code.push_str("}\n");
}

#[derive(Debug)]
struct TypeMapping {
	asn1_type: &'static str,
	implementations: Vec<FromImpl>,
}

#[derive(Debug)]
struct FromImpl {
	from_type: &'static str,
	conversion: &'static str,
	feature_gate: Option<&'static str>,
}

fn generate_from_impl_for_type(generated_code: &mut String, wrapper_types: &[String], type_mapping: &TypeMapping) {
	for wrapper_type in wrapper_types {
		for from_impl in &type_mapping.implementations {
			let impl_block = format!(
				r#"impl From<{from_type}> for {wrapper_type} {{
	fn from(value: {from_type}) -> Self {{
		Self({conversion})
	}}
}}

"#,
				from_type = from_impl.from_type,
				wrapper_type = wrapper_type,
				conversion = from_impl.conversion
			);

			if let Some(feature) = from_impl.feature_gate {
				generated_code.push_str(&format!("#[cfg(feature = \"{feature}\")]\n{impl_block}"));
			} else {
				generated_code.push_str(&impl_block);
			}
		}
	}
}

fn generate_default_impl(oids: &Value, generated_code: &mut String) {
	generated_code.push_str("// Default implementations for types with default fields\n\n");

	// Types that typically implement Default in rasn
	let default_types = [
		"String",
		"UTF8String",
		"Utf8String",
		"Vec",
		"SequenceOf",
		"BooleanType",
		"Integer",
		"BitString",
		"OctetString",
	];

	emit_defaults_for_sensitive(oids, generated_code, &default_types);
	emit_defaults_for_sequences(oids, generated_code, &default_types);
}

/// Determine whether a field type can be defaulted via `Default::default()`.
fn type_implements_default(field_type: &str, default_types: &[&str]) -> bool {
	default_types.iter().any(|&t| field_type.contains(t))
		|| field_type == "NamePrefixCode"
		|| field_type == "PreferredContactMethodCode"
}

/// Compute the `Self::new` arguments for a sequence type, or `None` when a
/// required field has no `Default` implementation.
fn field_defaults(fields: &serde_json::Map<String, Value>, default_types: &[&str]) -> Option<Vec<String>> {
	let mut defaults = Vec::new();
	for field_info in fields.values() {
		let is_optional = field_info["optional"].as_bool().unwrap_or(false);
		let field_type = field_info["type"].as_str().unwrap_or("");

		if is_optional {
			defaults.push("None".to_string());
		} else if type_implements_default(field_type, default_types) {
			defaults.push("Default::default()".to_string());
		} else {
			return None;
		}
	}

	Some(defaults)
}

fn emit_default_impl(generated_code: &mut String, type_name: &str, defaults: &[String]) {
	generated_code.push_str(&format!(
		r#"impl Default for {type_name} {{
	fn default() -> Self {{
		Self::new({})
	}}
}}

"#,
		defaults.join(", ")
	));
}

fn emit_defaults_for_sensitive(oids: &Value, generated_code: &mut String, default_types: &[&str]) {
	let Some(sensitive_attrs) = oids["sensitive_attributes"].as_object() else {
		return;
	};

	for (name, attr_info) in sensitive_attrs {
		if attr_info["type"] != "SEQUENCE" {
			continue;
		}
		let Some(fields) = attr_info["fields"].as_object() else {
			continue;
		};
		let Some(defaults) = field_defaults(fields, default_types) else {
			continue;
		};

		let token = attr_info["token"].as_str().unwrap_or(name);
		emit_default_impl(generated_code, token, &defaults);
	}
}

fn emit_defaults_for_sequences(oids: &Value, generated_code: &mut String, default_types: &[&str]) {
	let Some(iso_types) = oids["iso20022_types"]["sequences"].as_object() else {
		return;
	};

	for (name, type_info) in iso_types {
		let Some(fields) = type_info["fields"].as_object() else {
			continue;
		};
		let Some(defaults) = field_defaults(fields, default_types) else {
			continue;
		};

		emit_default_impl(generated_code, name, &defaults);
	}
}

fn collect_wrapper_types(oids: &Value) -> std::collections::HashMap<String, Vec<String>> {
	let mut wrapper_types: std::collections::HashMap<String, Vec<String>> = std::collections::HashMap::new();

	add_primitive_wrappers(oids, &mut wrapper_types);
	add_sensitive_wrappers(oids, &mut wrapper_types);

	// Sort for consistent output
	for wrappers in wrapper_types.values_mut() {
		wrappers.sort();
	}

	wrapper_types
}

fn add_primitive_wrappers(oids: &Value, wrapper_types: &mut std::collections::HashMap<String, Vec<String>>) {
	let Some(primitives) = oids["iso20022_types"]["primitives"].as_object() else {
		return;
	};

	for (name, info) in primitives {
		if let Some(asn1_type) = info["type"].as_str() {
			wrapper_types
				.entry(asn1_type.to_string())
				.or_default()
				.push(name.clone());
		}
	}
}

fn add_sensitive_wrappers(oids: &Value, wrapper_types: &mut std::collections::HashMap<String, Vec<String>>) {
	let Some(sensitive_attrs) = oids["sensitive_attributes"].as_object() else {
		return;
	};

	for info in sensitive_attrs.values() {
		let Some(token) = info["token"].as_str() else {
			continue;
		};
		if let Some(asn1_type) = info["type"].as_str() {
			wrapper_types
				.entry(asn1_type.to_string())
				.or_default()
				.push(token.to_string());
		}
	}
}

fn generate_from_implementations(path: &str) {
	let filename = "iso20022_from_implementations.rs";
	let oids = load_oids_json();
	let dest_path = Path::new(path).join(filename);
	let mut generated_code = String::new();

	// Add header comment
	generated_code.push_str(
		r#"//! Generated From implementations for wrapper types
//!
//! This module provides convenient From implementations for all wrapper types
//! that delegate to primitive types like Utf8String and GeneralizedTime,
//! making them more ergonomic to use.

use crate::generated::iso20022::*;

"#,
	);

	// Define supported type mappings with their From implementations
	let type_mappings = vec![
		TypeMapping {
			asn1_type: "UTF8String",
			implementations: vec![
				FromImpl { from_type: "String", conversion: "value", feature_gate: None },
				FromImpl { from_type: "&str", conversion: "value.into()", feature_gate: None },
			],
		},
		TypeMapping {
			asn1_type: "GeneralizedTime",
			implementations: vec![
				FromImpl { from_type: "rasn::types::GeneralizedTime", conversion: "value", feature_gate: None },
				FromImpl {
					from_type: "std::time::SystemTime",
					conversion: "chrono::DateTime::<chrono::Utc>::from(value).into()",
					feature_gate: Some("chrono"),
				},
				FromImpl {
					from_type: "chrono::DateTime<chrono::Utc>",
					conversion: "value.into()",
					feature_gate: Some("chrono"),
				},
				FromImpl {
					from_type: "chrono::NaiveDate",
					conversion: "value.and_hms_opt(0, 0, 0).unwrap().and_utc().fixed_offset()",
					feature_gate: Some("chrono"),
				},
			],
		},
	];

	// Collect wrapper types by their underlying ASN.1 type
	let wrapper_types = collect_wrapper_types(&oids);

	// Generate From implementations for each type mapping
	for type_mapping in &type_mappings {
		if let Some(wrappers) = wrapper_types.get(type_mapping.asn1_type) {
			generate_from_impl_for_type(&mut generated_code, wrappers, type_mapping);
		}
	}

	// Generate Default implementations for types
	generate_default_impl(&oids, &mut generated_code);

	if let Some(parent) = dest_path.parent() {
		fs::create_dir_all(parent).expect("Failed to create src/generated directory");
	}

	ensure_single_newline_ending(&mut generated_code);
	fs::write(&dest_path, generated_code).unwrap_or_else(|_| panic!("Failed to write {filename}"));
}

fn format_oid_array(value: &Value) -> String {
	if let Some(array) = value.as_array() {
		let numbers: Vec<String> = array
			.iter()
			.filter_map(|v| v.as_u64())
			.map(|n| n.to_string())
			.collect();
		format!("[{}]", numbers.join(", "))
	} else {
		"[0]".to_string()
	}
}

fn camel_to_snake_upper(s: &str) -> String {
	let mut result = String::new();
	let chars = s.chars().peekable();
	for c in chars {
		if c.is_uppercase() && !result.is_empty() {
			result.push('_');
		}
		result.push(
			c.to_uppercase()
				.next()
				.expect("ASCII char must have uppercase"),
		);
	}

	result
}

#[allow(dead_code)]
fn camel_to_pascal_case(s: &str) -> String {
	let mut result = String::new();
	let mut chars = s.chars();

	if let Some(first_char) = chars.next() {
		result.push(
			first_char
				.to_uppercase()
				.next()
				.expect("ASCII char must have uppercase"),
		);
		for c in chars {
			result.push(c);
		}
	}

	result
}

/// Ensures the file ends with exactly one newline
fn ensure_single_newline_ending(content: &mut String) {
	// Remove all trailing whitespace including newlines
	*content = content.trim_end().to_string();
	// Add exactly one newline
	content.push('\n');
}
