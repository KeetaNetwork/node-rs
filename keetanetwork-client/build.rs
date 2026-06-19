use std::error::Error;
use std::fs;
use std::path::Path;

/// Generate the raw progenitor transport client from the committed OpenAPI
/// document. The output is written to `$OUT_DIR/codegen.rs` and included by
/// the crate root, keeping the generated source visible for inspection.
fn main() -> Result<(), Box<dyn Error>> {
	let spec_path = "openapi/keetanet-node.yaml";
	println!("cargo:rerun-if-changed={spec_path}");
	println!("cargo:rerun-if-changed=build.rs");

	let raw = fs::read_to_string(spec_path)?;
	let spec = serde_yaml::from_str(&raw)?;

	let mut generator = progenitor::Generator::default();
	let tokens = generator.generate_tokens(&spec)?;
	let ast = syn::parse2(tokens)?;
	let code = prettyplease::unparse(&ast);

	let out_dir = std::env::var("OUT_DIR")?;
	fs::write(Path::new(&out_dir).join("codegen.rs"), code)?;

	Ok(())
}
