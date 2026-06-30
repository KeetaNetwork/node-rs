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

	/** The subject distinguished name as an RFC 4514 string. */
	public String subject() {
		return net.takeString(net.handle("keeta_certificate_subject", handle()));
	}

	/** The issuer distinguished name as an RFC 4514 string. */
	public String issuer() {
		return net.takeString(net.handle("keeta_certificate_issuer", handle()));
	}

	/** The serial number as a base-10 string. */
	public String serial() {
		return net.takeString(net.handle("keeta_certificate_serial", handle()));
	}

	/** The start of the validity window, in Unix seconds. */
	public long notBefore() {
		return net.call("keeta_certificate_not_before", handle());
	}

	/** The end of the validity window, in Unix seconds. */
	public long notAfter() {
		return net.call("keeta_certificate_not_after", handle());
	}

	/**
	 * The subject public key, type-prefixed and hex-encoded to match
	 * {@link Account#publicKey()}, so a subject can be matched to an account.
	 */
	public String subjectPublicKey() {
		return net.takeString(net.handle("keeta_certificate_subject_public_key", handle()));
	}

	@Override
	public void close() {
		if (handle != 0) {
			net.free("keeta_certificate_free", handle);
			handle = 0;
		}
	}
}
