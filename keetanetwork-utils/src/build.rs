//! Build utilities for ASN.1 code generation
//!
//! This module provides utilities for processing generated ASN.1 code,
//! particularly for removing module wrappers and cleaning up imports.

use rasn_compiler::RasnCompiler;
use std::path::Path;

/// Configuration options for ASN.1 compilation
#[derive(Debug, Clone)]
pub struct Asn1CompileConfig {
	/// Directory containing ASN.1 files
	pub asn_dir: String,
	/// Output directory for generated Rust files  
	pub out_dir: String,
	/// Path for the generated.rs file (optional)
	pub generated_rs_path: Option<String>,
	/// Use `include!(concat!(env!("OUT_DIR"), ...))` pattern in generated.rs.
	pub use_out_dir_includes: bool,
	/// Whether to strip pre-built methods from generated types
	pub strip_prebuilt_methods: bool,
	/// Methods to strip per module (if strip_prebuilt_methods is true)
	/// Key is module name, value is list of method names to strip
	pub methods_to_strip: std::collections::HashMap<String, Vec<String>>,
	/// Whether to remove module wrappers
	pub remove_module_wrappers: bool,
	/// Whether to run cargo clippy after compilation and apply fixes
	pub run_clippy_fixes: bool,
	/// Optional list of module names that should be declared as public
	/// - `None`: All modules are private (`mod module_name;`)
	/// - `Some(vec!["*"])`: All modules are public (`pub mod module_name;`)
	/// - `Some(vec!["mod1", "mod2"])`: Only specified modules are public
	pub public_modules: Option<Vec<String>>,
}

impl Default for Asn1CompileConfig {
	fn default() -> Self {
		Self {
			asn_dir: "asn1".to_string(),
			out_dir: "generated".to_string(),
			generated_rs_path: None,
			use_out_dir_includes: false,
			strip_prebuilt_methods: false,
			methods_to_strip: std::collections::HashMap::new(),
			remove_module_wrappers: true,
			run_clippy_fixes: true,
			public_modules: None,
		}
	}
}

impl Asn1CompileConfig {
	/// Create a new configuration with default settings
	pub fn new(asn_dir: &str, out_dir: &str) -> Self {
		Self { asn_dir: asn_dir.to_string(), out_dir: out_dir.to_string(), ..Default::default() }
	}

	/// Set the generated.rs output path
	pub fn with_generated_rs_path(mut self, path: &str) -> Self {
		self.generated_rs_path = Some(path.to_string());
		self
	}

	/// Use `include!(concat!(env!("OUT_DIR"), ...))` pattern in generated.rs.
	/// Required for cargo publish compatibility when out_dir is set to OUT_DIR.
	pub fn with_out_dir_includes(mut self, use_includes: bool) -> Self {
		self.use_out_dir_includes = use_includes;
		self
	}

	/// Enable stripping of pre-built methods
	pub fn with_strip_prebuilt_methods(mut self, strip: bool) -> Self {
		self.strip_prebuilt_methods = strip;
		self
	}

	/// Set which methods to strip for a specific module
	pub fn with_methods_to_strip(mut self, module: &str, methods: Vec<&str>) -> Self {
		let method_strings = methods.into_iter().map(|s| s.to_string()).collect();
		self.methods_to_strip
			.insert(module.to_string(), method_strings);
		self
	}

	/// Set whether to remove module wrappers
	pub fn with_remove_module_wrappers(mut self, remove: bool) -> Self {
		self.remove_module_wrappers = remove;
		self
	}

	/// Enable automatic clippy fixes after compilation
	pub fn with_clippy_fixes(mut self, enable: bool) -> Self {
		self.run_clippy_fixes = enable;
		self
	}

	/// Set which modules should be declared as public
	/// Pass a vector of module names that should be public
	pub fn with_public_modules(mut self, modules: Vec<&str>) -> Self {
		self.public_modules = Some(modules.into_iter().map(|s| s.to_string()).collect());
		self
	}

	/// Make all modules public
	pub fn with_all_modules_public(mut self) -> Self {
		self.public_modules = Some(vec!["*".to_string()]);
		self
	}

	/// Make all modules private (default)
	pub fn with_all_modules_private(mut self) -> Self {
		self.public_modules = None;
		self
	}
}

/// Compile all ASN.1 files in a directory to Rust code
pub fn compile_asn1_directory(asn_dir: &str, out_dir: &str) -> Result<(), Box<dyn std::error::Error>> {
	let config = Asn1CompileConfig::new(asn_dir, out_dir);
	compile_asn1_directory_with_full_config(&config)
}

/// Compile all ASN.1 files in a directory to Rust code with configurable generated.rs output
pub fn compile_asn1_directory_with_config(
	asn_dir: &str,
	out_dir: &str,
	generated_rs_path: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
	let mut config = Asn1CompileConfig::new(asn_dir, out_dir);
	if let Some(path) = generated_rs_path {
		config.generated_rs_path = Some(path.to_string());
	}
	compile_asn1_directory_with_full_config(&config)
}

/// Compile all ASN.1 files in a directory to Rust code with full configuration
pub fn compile_asn1_directory_with_full_config(config: &Asn1CompileConfig) -> Result<(), Box<dyn std::error::Error>> {
	// Create output dir if missing
	if !Path::new(&config.out_dir).exists() {
		std::fs::create_dir_all(&config.out_dir)?;
	}

	// Find all .asn files in the asn1 directory
	let asn_files = collect_asn_files(&config.asn_dir)?;

	// Track generated modules for creating generated.rs
	let mut generated_modules = Vec::new();
	// Compile each ASN.1 file
	for asn_file in &asn_files {
		// Read the ASN.1 file to get the proper module name
		let asn_content = std::fs::read_to_string(asn_file)?;
		let module_name = resolve_module_name(asn_file, &asn_content);
		let output_file = Path::new(&config.out_dir).join(format!("{module_name}.rs"));

		let result = RasnCompiler::new()
			.add_asn_by_path(asn_file)
			.compile_to_string();

		let compile_result = match result {
			Ok(compile_result) => compile_result,
			Err(error) => {
				return Err(format!("ASN.1 compilation failed for {asn_file:?}: {error:?}").into());
			}
		};

		let final_code = post_process_generated(&compile_result.generated, config, &module_name);

		// Write the processed code to file
		std::fs::write(&output_file, final_code)?;

		// Track this module for the generated.rs file
		generated_modules.push((module_name, asn_file.clone()));

		for warning in compile_result.warnings {
			println!("cargo:warning=ASN.1 compilation warning: {warning:?}");
		}

		println!("cargo:rerun-if-changed={}", asn_file.display());
	}

	// Generate the generated.rs file - use provided path or default to src/generated.rs
	let default_generated_path = Path::new("src").join("generated.rs");
	let generated_path = config.generated_rs_path.as_deref().unwrap_or(
		default_generated_path
			.to_str()
			.expect("OUT_DIR path must be valid UTF-8"),
	);
	generate_generated_rs(&generated_modules, generated_path, &config.out_dir, config)?;

	// Run clippy fixes if enabled
	if config.run_clippy_fixes {
		run_clippy_fixes()?;
	}

	println!("cargo:rerun-if-changed={}", config.asn_dir);
	Ok(())
}

/// Collect all `.asn` files in a directory.
fn collect_asn_files(asn_dir: &str) -> Result<Vec<std::path::PathBuf>, Box<dyn std::error::Error>> {
	let asn_files = std::fs::read_dir(asn_dir)?
		.filter_map(|entry| {
			let entry = entry.ok()?;
			let path = entry.path();
			if path.extension()? == "asn" {
				Some(path)
			} else {
				None
			}
		})
		.collect();

	Ok(asn_files)
}

/// Resolve the Rust module name for an ASN.1 file, preferring the declared
/// module name and falling back to the file stem.
fn resolve_module_name(asn_file: &Path, asn_content: &str) -> String {
	if let Some(asn1_module_name) = extract_asn1_module_name(asn_content) {
		// Convert ASN.1 module name to snake_case for Rust module name
		asn1_module_name_to_import_name(&asn1_module_name)
	} else {
		// Fallback to filename if we can't extract the module name
		asn_file
			.file_stem()
			.expect("ASN file must have a stem")
			.to_string_lossy()
			.to_string()
	}
}

/// Apply the configured post-processing pipeline to freshly generated code.
fn post_process_generated(generated_code: &str, config: &Asn1CompileConfig, module_name: &str) -> String {
	// Remove module wrapper by extracting the inner content if enabled
	let processed_code = if config.remove_module_wrappers {
		remove_module_wrapper(generated_code)
	} else {
		generated_code.to_string()
	};

	// Strip pre-built methods if enabled
	let processed_code = if config.strip_prebuilt_methods {
		if let Some(methods) = config.methods_to_strip.get(module_name) {
			strip_prebuilt_methods(&processed_code, methods)
		} else {
			processed_code
		}
	} else {
		processed_code
	};

	// Fix common issues in generated code
	let processed_code = fix_generated_code_issues(&processed_code);
	// Add lint suppressions for generated code
	let final_code = add_lint_suppressions(&processed_code);

	// If using OUT_DIR includes, strip inner attributes (they're invalid inside mod blocks)
	if config.use_out_dir_includes {
		strip_inner_attributes(&final_code)
	} else {
		final_code
	}
}

/// Remove module wrapper from generated code
pub fn remove_module_wrapper(code: &str) -> String {
	// Look for pattern: pub mod module_name {
	let lines: Vec<&str> = code.lines().collect();

	// If we found a module wrapper, extract the content
	let inner_content = if let Some((start, end)) = find_module_bounds(&lines) {
		// Extract lines between the module declaration and closing brace,
		// removing one level of indentation (typically one tab)
		lines[start + 1..end]
			.iter()
			.map(|line| dedent_line(line))
			.collect::<Vec<_>>()
			.join("\n")
	} else {
		// No module wrapper found, return as-is
		code.to_string()
	};

	// Clean up unused imports
	clean_unused_imports(&inner_content)
}

/// Locate the `pub mod` wrapper bounds as (declaration line, closing-brace line).
fn find_module_bounds(lines: &[&str]) -> Option<(usize, usize)> {
	let mut start_idx = None;
	let mut brace_count = 0;

	for (i, line) in lines.iter().enumerate() {
		let trimmed = line.trim();

		// Look for pub mod declaration
		if trimmed.starts_with("pub mod ") && trimmed.ends_with(" {") {
			start_idx = Some(i);
			brace_count = 1;
			continue;
		}

		// If we're inside a module, track braces
		if let Some(start) = start_idx {
			brace_count += line.matches('{').count();
			brace_count -= line.matches('}').count();

			if brace_count == 0 {
				return Some((start, i));
			}
		}
	}

	None
}

/// Remove one level of leading indentation (tab or four spaces) from a line.
fn dedent_line(line: &str) -> &str {
	if let Some(stripped) = line.strip_prefix('\t') {
		stripped
	} else if let Some(stripped) = line.strip_prefix("    ") {
		stripped
	} else {
		line
	}
}

/// Strip pre-built methods from generated code
pub fn strip_prebuilt_methods(code: &str, methods_to_strip: &[String]) -> String {
	if methods_to_strip.is_empty() {
		return code.to_string();
	}

	let lines: Vec<&str> = code.lines().collect();
	let mut result_lines = Vec::new();
	let mut i = 0;
	while i < lines.len() {
		if is_strip_target(lines[i], methods_to_strip) {
			// Skip this method by finding its closing brace
			advance_past_method(&lines, &mut i);
		} else {
			// Keep this line
			result_lines.push(lines[i]);
			i += 1;
		}
	}

	result_lines.join("\n")
}

/// Check whether a line begins one of the methods to strip.
fn is_strip_target(line: &str, methods_to_strip: &[String]) -> bool {
	let trimmed = line.trim();
	methods_to_strip
		.iter()
		.any(|method_name| trimmed.contains(&format!("pub fn {method_name}(")))
}

/// Advance `*i` past the brace-balanced method body starting at `*i`.
fn advance_past_method(lines: &[&str], i: &mut usize) {
	let mut brace_count = 0;
	let mut method_started = false;

	// Continue from current line until we balance the braces
	while *i < lines.len() {
		// Count braces on this line
		for ch in lines[*i].chars() {
			match ch {
				'{' => {
					brace_count += 1;
					method_started = true;
				}
				'}' => {
					brace_count -= 1;
				}
				_ => {}
			}
		}

		*i += 1;

		// If we've closed all braces for this method, we're done
		if method_started && brace_count == 0 {
			break;
		}
	}
}

/// Clean up unused imports from generated code
pub fn clean_unused_imports(code: &str) -> String {
	// Split into lines and filter out common unused imports
	let lines: Vec<&str> = code.lines().collect();
	let mut cleaned_lines = Vec::new();
	for line in lines {
		// Skip unused imports commonly generated by rasn-compiler
		let trimmed = line.trim();
		if trimmed == "use core::borrow::Borrow;"
			|| trimmed == "use std::sync::LazyLock;"
			|| (trimmed == "extern crate alloc;" && code.contains("use rasn::prelude::*;"))
		{
			continue;
		}

		cleaned_lines.push(line);
	}

	cleaned_lines.join("\n")
}

/// Fix common issues in generated code
pub fn fix_generated_code_issues(code: &str) -> String {
	let mut result = code.to_string();

	// Fix ANY -> Any (rasn uses lowercase)
	result = result.replace("Option<ANY>", "Option<Any>");
	result = result.replace(" ANY>", " Any>");
	result = result.replace(" ANY ", " Any ");

	result
}

/// Extract the ASN.1 module name from ASN.1 file content
fn extract_asn1_module_name(asn_content: &str) -> Option<String> {
	for line in asn_content.lines() {
		let trimmed = line.trim();
		// Look for module definition: "ModuleName DEFINITIONS"
		if trimmed.contains("DEFINITIONS") && !trimmed.starts_with("--") {
			if let Some(module_name) = trimmed.split_whitespace().next() {
				return Some(module_name.to_string());
			}
		}
	}

	None
}

/// Convert ASN.1 module name to the format used in import statements
/// This typically converts CamelCase to snake_case
fn asn1_module_name_to_import_name(asn1_name: &str) -> String {
	// Convert CamelCase to snake_case
	let mut result = String::new();
	let chars = asn1_name.chars().peekable();
	for ch in chars {
		if ch.is_uppercase() && !result.is_empty() {
			// Add underscore before uppercase letters (except the first character)
			result.push('_');
		}
		result.push(ch.to_lowercase().next().unwrap_or(ch));
	}

	result
}

/// Add lint suppressions to generated code
pub fn add_lint_suppressions(code: &str) -> String {
	// Add comprehensive lint suppressions at the top of the file
	let suppressions = [
		"#![allow(unused_imports)]",
		"#![allow(unused_variables)]",
		"#![allow(dead_code)]",
		"#![allow(non_camel_case_types)]",
		"#![allow(non_snake_case)]",
		"#![allow(non_upper_case_globals)]",
		"#![allow(clippy::all)]",
		"", // Empty line for readability
	];

	let mut result = suppressions.join("\n");
	result.push_str(code);

	// Ensure the file ends with a newline
	if !result.ends_with('\n') {
		result.push('\n');
	}

	result
}

/// Strip inner attributes from generated code.
/// This is needed when using `include!()` inside a `mod {}` block,
/// as inner attributes are not allowed in that context.
pub fn strip_inner_attributes(code: &str) -> String {
	code.lines()
		.filter(|line| !line.trim().starts_with("#!["))
		.collect::<Vec<_>>()
		.join("\n")
}

/// Calculate relative path from one directory to another
fn calculate_relative_path(from: &Path, to: &Path) -> String {
	// Convert both paths to absolute paths for easier comparison
	let from_absolute = std::env::current_dir()
		.expect("current_dir must exist during build")
		.join(from);
	let to_absolute = std::env::current_dir()
		.expect("current_dir must exist during build")
		.join(to);
	// Get the components of both paths
	let from_components: Vec<_> = from_absolute.components().collect();
	let to_components: Vec<_> = to_absolute.components().collect();

	// Find the common prefix
	let mut common_prefix_len = 0;
	for (f, t) in from_components.iter().zip(to_components.iter()) {
		if f == t {
			common_prefix_len += 1;
		} else {
			break;
		}
	}

	// Calculate the number of ".." needed to go up from the 'from' directory
	let up_count = from_components.len() - common_prefix_len;
	// Build the relative path
	let mut relative_parts = vec![".."; up_count];
	// Add the remaining components from the 'to' path
	for component in &to_components[common_prefix_len..] {
		if let Some(os_str) = component.as_os_str().to_str() {
			relative_parts.push(os_str);
		}
	}

	// Join with forward slashes for Rust module paths
	if relative_parts.is_empty() {
		".".to_string()
	} else {
		relative_parts.join("/")
	}
}

/// Generate a generated.rs file that re-exports all types from generated modules
pub fn generate_generated_rs(
	modules: &[(String, std::path::PathBuf)],
	output_path: &str,
	modules_dir: &str,
	config: &Asn1CompileConfig,
) -> Result<(), Box<dyn std::error::Error>> {
	// Create the output directory if it doesn't exist
	if let Some(parent) = Path::new(output_path).parent() {
		if !parent.exists() {
			std::fs::create_dir_all(parent)?;
		}
	}

	// Calculate the correct relative path from the generated.rs file to the modules directory
	let output_path_obj = Path::new(output_path);
	let modules_dir_path = Path::new(modules_dir);
	// Get the directory containing the generated.rs file
	let output_dir = output_path_obj.parent().unwrap_or(Path::new("."));
	// Calculate relative path from output directory to modules directory
	let relative_path = calculate_relative_path(output_dir, modules_dir_path);

	let mut content = String::new();
	content.push_str("#![cfg_attr(rustfmt, rustfmt::skip)]\n");
	content.push_str("//! Generated ASN.1 code\n");
	content.push_str("//!\n");
	content.push_str("//! This module contains all the generated ASN.1 structures and re-exports them\n");
	content.push_str("//! for use throughout the library.\n");
	content.push_str("//!\n");
	content.push_str("//! This file is automatically generated by build.rs - do not edit manually.\n\n");

	// Add module declarations
	emit_module_declarations(&mut content, modules, &relative_path, config);

	content.push_str("\n// Re-export all types from the generated modules\n");

	// Add re-exports for each module
	emit_reexports(&mut content, modules, modules_dir, config);

	// Write the generated.rs file
	std::fs::write(output_path, content)?;
	println!("cargo:rerun-if-changed={output_path}");

	Ok(())
}

/// Determine whether a module should be declared `pub` per the configuration.
fn module_is_public(config: &Asn1CompileConfig, module_name: &str) -> bool {
	match config.public_modules {
		Some(ref public_modules) => {
			public_modules.contains(&"*".to_string()) || public_modules.contains(&module_name.to_string())
		}
		None => false,
	}
}

/// Emit `mod` declarations for every generated module.
fn emit_module_declarations(
	content: &mut String,
	modules: &[(String, std::path::PathBuf)],
	relative_path: &str,
	config: &Asn1CompileConfig,
) {
	for (module_name, _) in modules {
		let mod_visibility = if module_is_public(config, module_name) {
			"pub "
		} else {
			""
		};

		if config.use_out_dir_includes {
			// Use include! pattern for OUT_DIR compatibility (required for cargo publish)
			// Add outer attributes to suppress warnings since inner attrs don't work with include!
			content.push_str("#[allow(unused_imports, unused_variables, dead_code, non_camel_case_types, clippy::too_many_arguments)]\n");
			content.push_str(&format!("{mod_visibility}mod {module_name} {{\n"));
			content.push_str(&format!("\tinclude!(concat!(env!(\"OUT_DIR\"), \"/generated/{module_name}.rs\"));\n"));
			content.push_str("}\n");
		} else {
			// Use #[path] directive for source-tree generation
			content.push_str(&format!("#[path = \"{relative_path}/{module_name}.rs\"]\n"));
			content.push_str(&format!("{mod_visibility}mod {module_name};\n"));
		}
	}
}

/// Emit `pub use` re-exports for modules not already declared public.
fn emit_reexports(
	content: &mut String,
	modules: &[(String, std::path::PathBuf)],
	modules_dir: &str,
	config: &Asn1CompileConfig,
) {
	for (module_name, _asn_file) in modules {
		// Skip modules already defined in `public_modules`
		if module_is_public(config, module_name) {
			continue;
		}

		// Parse the generated file to find exported types - look in the modules directory
		let generated_file_path = format!("{modules_dir}/{module_name}.rs");
		let Ok(generated_content) = std::fs::read_to_string(&generated_file_path) else {
			continue;
		};

		let exported_types = extract_exported_types(&generated_content);
		// Emit rustfmt-canonical re-exports so the generated file is
		// byte-stable under `cargo fmt --check`.
		match exported_types.as_slice() {
			[] => {}
			[single] => content.push_str(&format!("pub use {module_name}::{single};\n")),
			types => content.push_str(&format!("pub use {}::{{{}}};\n", module_name, types.join(", "))),
		}
	}
}

/// Extract exported type names from generated code
pub fn extract_exported_types(content: &str) -> Vec<String> {
	let mut types = Vec::new();

	for line in content.lines() {
		let trimmed = line.trim();

		// Look for pub struct, pub enum, pub type declarations
		if trimmed.starts_with("pub struct ") || trimmed.starts_with("pub enum ") || trimmed.starts_with("pub type ") {
			if let Some(name_part) = trimmed.split_whitespace().nth(2) {
				// Extract the type name (before any generic parameters or brackets)
				let type_name = name_part
					.split('<')
					.next()
					.unwrap_or(name_part)
					.split('(')
					.next()
					.unwrap_or(name_part)
					.split('{')
					.next()
					.unwrap_or(name_part);
				types.push(type_name.to_string());
			}
		}
	}

	types
}

/// Run rustfmt directly on generated files to avoid cargo recursion
pub fn run_clippy_fixes() -> Result<(), Box<dyn std::error::Error>> {
	println!("cargo:info=Formatting generated code...");

	// Only run rustfmt directly on the files to avoid cargo recursion issues
	format_generated_files()?;

	Ok(())
}

/// Format specific generated files using rustfmt directly
pub fn format_generated_files() -> Result<(), Box<dyn std::error::Error>> {
	// Find all .rs files in the generated directory
	let generated_dir = std::path::Path::new("generated");
	if !generated_dir.exists() {
		return Ok(()); // Nothing to format
	}

	let rs_files: Vec<_> = std::fs::read_dir(generated_dir)?
		.filter_map(|entry| {
			let entry = entry.ok()?;
			let path = entry.path();
			if path.extension()? == "rs" {
				Some(path)
			} else {
				None
			}
		})
		.collect();

	let mut all_files = rs_files;

	// Also include src/generated.rs if it exists
	let src_generated = std::path::Path::new("src/generated.rs");
	if src_generated.exists() {
		all_files.push(src_generated.to_path_buf());
	}

	if all_files.is_empty() {
		return Ok(());
	}

	// Run rustfmt directly on the specific files
	let mut rustfmt_cmd = std::process::Command::new("rustfmt");
	rustfmt_cmd.args(["--edition", "2021"]);

	for file in &all_files {
		rustfmt_cmd.arg(file);
	}

	match rustfmt_cmd.output() {
		Ok(result) => {
			if !result.status.success() {
				let stderr = String::from_utf8_lossy(&result.stderr);
				println!("cargo:warning=Rustfmt completed with warnings: {stderr}");
			} else {
				println!("cargo:info=Generated code formatting applied successfully");
			}
		}
		Err(e) => {
			println!("cargo:warning=Failed to run rustfmt: {e}");
		}
	}

	Ok(())
}
