package network.keeta.wasi;

/**
 * A key-pair signing algorithm, named exactly as the wasm core module's
 * boundary parser expects.
 */
public enum Algorithm {
	ECDSA_SECP256K1("ecdsa_secp256k1"),
	ED25519("ed25519"),
	ECDSA_SECP256R1("ecdsa_secp256r1");

	private final String token;

	Algorithm(String token) {
		this.token = token;
	}

	/** The boundary token passed to the core module. */
	public String token() {
		return token;
	}
}
