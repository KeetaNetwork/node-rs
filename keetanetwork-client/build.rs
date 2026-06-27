use std::error::Error;
use std::fs;
use std::path::Path;

/// The `api-version` request header the generated client attaches to every
/// call. Browsers treat it as a non-safe-listed header, forcing a CORS
/// preflight. The TS reference node does not list it in
/// `Access-Control-Allow-Headers`, so the preflight fails. The node does not
/// require the header, so wasm builds drop it to keep cross-origin `fetch`
/// working.
///
/// Progenitor emits this header unconditionally from `info.version` (PR #1120)
/// and exposes no setting to suppress it, so stripping the generated source is
/// the only available option.
const API_VERSION_HEADER: &str = "        let mut header_map = ::reqwest::header::HeaderMap::with_capacity(1usize);
        header_map
            .append(
                ::reqwest::header::HeaderName::from_static(\"api-version\"),
                ::reqwest::header::HeaderValue::from_static(Self::api_version()),
            );";

/// The empty header map that replaces it on wasm targets.
const EMPTY_HEADER_MAP: &str = "        let header_map = ::reqwest::header::HeaderMap::new();";

/// Generate the raw progenitor transport client from the committed OpenAPI
/// document, split into two included files so the serde transport types compile
/// without the `reqwest` client.
fn main() -> Result<(), Box<dyn Error>> {
	let spec_path = "openapi/keetanet-node.yaml";
	println!("cargo:rerun-if-changed={spec_path}");
	println!("cargo:rerun-if-changed=build.rs");
	println!("cargo:rerun-if-env-changed=CARGO_CFG_TARGET_FAMILY");

	let raw = fs::read_to_string(spec_path)?;
	let spec = serde_yaml::from_str(&raw)?;

	let mut generator = progenitor::Generator::default();
	let tokens = generator.generate_tokens(&spec)?;
	let ast: syn::File = syn::parse2(tokens)?;

	let mut types_items = Vec::new();
	let mut client_items = Vec::new();
	for item in ast.items {
		match &item {
			syn::Item::Mod(module) if module.ident == "types" => types_items.push(item),
			_ => client_items.push(item),
		}
	}

	assert!(
		!types_items.is_empty(),
		"progenitor output no longer contains a `types` module; update build.rs so the \
		 codec half (`codegen_types.rs`) keeps compiling without the reqwest client"
	);

	let types_code = unparse_items(types_items);
	let client_code = strip_browser_incompatible_headers(unparse_items(client_items));

	let out_dir = std::env::var("OUT_DIR")?;
	fs::write(Path::new(&out_dir).join("codegen_types.rs"), types_code)?;
	fs::write(Path::new(&out_dir).join("codegen_client.rs"), client_code)?;

	Ok(())
}

/// Render a set of items as formatted Rust source. File-level attributes are
/// dropped; the including `generated` module already carries the lint allows.
fn unparse_items(items: Vec<syn::Item>) -> String {
	let file = syn::File { shebang: None, attrs: Vec::new(), items };
	prettyplease::unparse(&file)
}

/// On wasm targets, drop the `api-version` header so browser `fetch` does not
/// trigger a CORS preflight the node rejects. Native targets keep the header.
fn strip_browser_incompatible_headers(code: String) -> String {
	let wasm = std::env::var("CARGO_CFG_TARGET_FAMILY").is_ok_and(|family| family == "wasm");
	if !wasm {
		return code;
	}

	assert!(
		code.contains(API_VERSION_HEADER),
		"progenitor output no longer contains the api-version header snippet; \
		 update API_VERSION_HEADER in keetanetwork-client/build.rs so wasm builds \
		 keep stripping it (otherwise browser fetch fails CORS at runtime)"
	);

	code.replace(API_VERSION_HEADER, EMPTY_HEADER_MAP)
}
