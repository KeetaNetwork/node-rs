package network.keeta.wasi;

/**
 * How a {@code MODIFY_PERMISSIONS} operation combines with the principal's
 * existing permissions.
 */
public enum AdjustMethod {
	ADD("add"),
	SUBTRACT("subtract"),
	SET("set");

	private final String token;

	AdjustMethod(String token) {
		this.token = token;
	}

	/** The boundary token passed to the core module. */
	public String token() {
		return token;
	}
}
