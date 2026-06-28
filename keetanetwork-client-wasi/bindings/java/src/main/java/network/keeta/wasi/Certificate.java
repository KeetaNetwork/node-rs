package network.keeta.wasi;

/**
 * An X.509 certificate parsed from PEM or DER, backed by the wasm core. All
 * parsing, encoding, and validity logic lives in the shared Rust bindings; this
 * class only plumbs handles across the flat ABI.
 */
public final class Certificate implements AutoCloseable {
	private final KeetaNet net;
	private int handle;

	Certificate(KeetaNet net, int handle) {
		this.net = net;
		this.handle = handle;
	}

	int handle() {
		if (handle == 0) {
			throw new KeetaException("FREED_HANDLE", "certificate has been closed");
		}

		return handle;
	}

	/** The PEM encoding of this certificate. */
	public String pem() {
		return net.takeString(net.handle("keeta_certificate_pem", handle()));
	}

	/** The DER encoding of this certificate. */
	public byte[] der() {
		return net.takeBytes(net.handle("keeta_certificate_der", handle()));
	}

	/** Whether this certificate is within its validity window at {@code unixMillis}. */
	public boolean validAt(long unixMillis) {
		int result = net.callInt("keeta_certificate_valid_at", handle(), unixMillis);
		if (result < 0) {
			throw net.lastError("keeta_certificate_valid_at");
		}

		return result == 1;
	}

	@Override
	public void close() {
		if (handle != 0) {
			net.free("keeta_certificate_free", handle);
			handle = 0;
		}
	}
}
