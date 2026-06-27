package network.keeta.wasi;

/**
 * A failure surfaced from the wasm core module or the node, carrying the stable
 * machine-readable {@code code} alongside a human-readable message.
 */
public final class KeetaException extends RuntimeException {
	private final String code;

	public KeetaException(String code, String message) {
		super(code + ": " + message);
		this.code = code;
	}

	/** The stable, machine-readable error code (e.g. {@code INVALID_SEED}). */
	public String code() {
		return code;
	}
}
