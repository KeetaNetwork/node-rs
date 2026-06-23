package network.keeta.wasi;

import java.nio.charset.StandardCharsets;

/**
 * A KeetaNet account: either a key pair (when derived from a seed, private key,
 * or passphrase) or a read-only/identifier account.
 */
public final class Account implements AutoCloseable {
	private final KeetaNet net;
	private int handle;

	Account(KeetaNet net, int handle) {
		this.net = net;
		this.handle = handle;
	}

	int handle() {
		if (handle == 0) {
			throw new KeetaException("FREED_HANDLE", "account has been closed");
		}

		return handle;
	}

	/** The textual account address. */
	public String address() {
		return net.takeString(net.handle("keeta_account_address", handle()));
	}

	/** The signing algorithm name, or {@code "other"} for identifier accounts. */
	public String algorithm() {
		return net.takeString(net.handle("keeta_account_algorithm", handle()));
	}

	/** The type-prefixed public key, hex-encoded. */
	public String publicKey() {
		return net.takeString(net.handle("keeta_account_public_key", handle()));
	}

	/** Produce a detached signature over {@code message}. */
	public byte[] sign(byte[] message) {
		int messagePtr = net.write(message);
		return net.takeBytes(net.handle("keeta_account_sign", handle(), messagePtr, message.length));
	}

	/** Whether {@code signature} is a valid signature of {@code message} by this account. */
	public boolean verify(byte[] message, byte[] signature) {
		int messagePtr = net.write(message);
		int signaturePtr = net.write(signature);

		return net.callInt("keeta_account_verify", handle(), messagePtr, message.length, signaturePtr, signature.length) == 1;
	}

	/**
	 * Derive an identifier account relative to this account, an optional
	 * previous block hash (the account opening hash when {@code null}), and an
	 * operation index.
	 */
	public Account generateIdentifier(IdentifierType type, byte[] previousHash, int operationIndex) {
		byte[] kind = type.token().getBytes(StandardCharsets.UTF_8);
		int kindPtr = net.write(kind);
		int previousPtr = previousHash == null ? 0 : net.write(previousHash);
		int previousLen = previousHash == null ? 0 : previousHash.length;
		int derived = net.handle("keeta_generate_identifier", handle(), kindPtr, kind.length, previousPtr, previousLen, operationIndex);

		return new Account(net, derived);
	}

	/**
	 * Derive the multisig identifier this account creates at the given previous
	 * block hash (the account opening hash when {@code null}) and operation index.
	 */
	public Account generateMultisigIdentifier(byte[] previousHash, int operationIndex) {
		int previousPtr = previousHash == null ? 0 : net.write(previousHash);
		int previousLen = previousHash == null ? 0 : previousHash.length;
		int derived = net.handle("keeta_generate_multisig_identifier", handle(), previousPtr, previousLen, operationIndex);

		return new Account(net, derived);
	}

	@Override
	public String toString() {
		return address();
	}

	@Override
	public void close() {
		if (handle != 0) {
			net.free("keeta_account_free", handle);
			handle = 0;
		}
	}
}
