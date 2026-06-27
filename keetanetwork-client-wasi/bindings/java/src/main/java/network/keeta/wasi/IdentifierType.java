package network.keeta.wasi;

/**
 * A derived identifier kind. Multisig identifiers are created through the
 * dedicated multisig operation path, so they are intentionally absent here.
 */
public enum IdentifierType {
	NETWORK("network"),
	TOKEN("token"),
	STORAGE("storage");

	private final String token;

	IdentifierType(String token) {
		this.token = token;
	}

	/** The boundary token passed to the core module. */
	public String token() {
		return token;
	}
}
