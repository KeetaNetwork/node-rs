use keetanetwork_utils::build::{compile_asn1_directory_with_full_config, Asn1CompileConfig};

fn main() {
	let config = Asn1CompileConfig::new("asn1", "generated")
		.with_generated_rs_path("src/generated.rs")
		.with_strip_prebuilt_methods(true)
		.with_methods_to_strip(vec!["new"]);

	if let Err(e) = compile_asn1_directory_with_full_config(&config) {
		panic!("Failed to compile ASN.1 files: {e}");
	}
}
