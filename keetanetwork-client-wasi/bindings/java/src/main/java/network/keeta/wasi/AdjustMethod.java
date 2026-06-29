package network.keeta.wasi;

/**
 * How an adjusting operation ({@code MODIFY_PERMISSIONS}, {@code TOKEN_ADMIN_SUPPLY},
 * {@code TOKEN_ADMIN_MODIFY_BALANCE}) combines with the existing value.
 */
public enum AdjustMethod {
	ADD("add"),
	SUBTRACT("subtract"),
	SET("set");

	private final String token;

	AdjustMethod(String token) {
		this.token = token;
	}

	/**
	 * The boundary token passed to the core module.
	 */
	public String token() {
		return token;
	}
}
