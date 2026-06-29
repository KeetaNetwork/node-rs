package network.keeta.wasi;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;

/**
 * The KeetaNet SDK entry point: a high-level facade over the wasm core module
 * that derives accounts, builds operations and blocks, and opens networked
 * {@link UserClient}s.
 */
public final class Keeta implements AutoCloseable {
	private final KeetaNet net;

	private Keeta(KeetaNet net) {
		this.net = net;
	}

	/** Load the SDK, locating the core module via system property/environment. */
	public static Keeta load() {
		return new Keeta(KeetaNet.load());
	}

	/** Load the SDK from an explicit core-module path. */
	public static Keeta load(Path module) {
		return new Keeta(KeetaNet.load(module));
	}

	KeetaNet runtime() {
		return net;
	}

	/* ----------------------------- accounts ----------------------------- */

	/** Generate a fresh random 32-byte seed, hex-encoded. */
	public String generateSeed() {
		return net.takeString(net.handle("keeta_generate_seed"));
	}

	/** Generate a fresh random BIP39 mnemonic. */
	public List<String> generatePassphrase() {
		String words = net.takeString(net.handle("keeta_generate_passphrase"));
		return Arrays.asList(words.split("\n"));
	}

	/** Derive an account from a hex seed at a derivation index. */
	public Account account(String seedHex, int index, Algorithm algorithm) {
		byte[] seed = seedHex.getBytes(StandardCharsets.UTF_8);
		byte[] algo = algorithm.token().getBytes(StandardCharsets.UTF_8);
		int seedPtr = net.write(seed);
		int algoPtr = net.write(algo);
		int handle = net.handle("keeta_account_from_seed", seedPtr, seed.length, index, algoPtr, algo.length);

		return new Account(net, handle);
	}

	/** Build an account from a hex-encoded private key. */
	public Account accountFromPrivateKey(String privateKeyHex, Algorithm algorithm) {
		byte[] key = privateKeyHex.getBytes(StandardCharsets.UTF_8);
		byte[] algo = algorithm.token().getBytes(StandardCharsets.UTF_8);
		int keyPtr = net.write(key);
		int algoPtr = net.write(algo);
		int handle = net.handle("keeta_account_from_private_key", keyPtr, key.length, algoPtr, algo.length);

		return new Account(net, handle);
	}

	/** Derive an account from a BIP39 mnemonic at a derivation index. */
	public Account accountFromPassphrase(List<String> words, int index, Algorithm algorithm) {
		byte[] joined = String.join("\n", words).getBytes(StandardCharsets.UTF_8);
		byte[] algo = algorithm.token().getBytes(StandardCharsets.UTF_8);
		int wordsPtr = net.write(joined);
		int algoPtr = net.write(algo);
		int handle = net.handle("keeta_account_from_passphrase", wordsPtr, joined.length, index, algoPtr, algo.length);

		return new Account(net, handle);
	}

	/** Build a read-only account from a hex-encoded public key. */
	public Account accountFromPublicKey(String publicKeyHex, Algorithm algorithm) {
		byte[] key = publicKeyHex.getBytes(StandardCharsets.UTF_8);
		byte[] algo = algorithm.token().getBytes(StandardCharsets.UTF_8);
		int keyPtr = net.write(key);
		int algoPtr = net.write(algo);
		int handle = net.handle("keeta_account_from_public_key", keyPtr, key.length, algoPtr, algo.length);

		return new Account(net, handle);
	}

	/** Build a read-only account from its textual address. */
	public Account address(String address) {
		byte[] bytes = address.getBytes(StandardCharsets.UTF_8);
		int ptr = net.write(bytes);
		return new Account(net, net.handle("keeta_account_from_address", ptr, bytes.length));
	}

	/* ---------------------------- certificates -------------------------- */

	/** Parse a PEM-encoded X.509 certificate. */
	public Certificate certificate(String pem) {
		byte[] bytes = pem.getBytes(StandardCharsets.UTF_8);
		int ptr = net.write(bytes);

		return new Certificate(net, net.handle("keeta_certificate_parse", ptr, bytes.length));
	}

	/** Parse a DER-encoded X.509 certificate. */
	public Certificate certificateFromDer(byte[] der) {
		int ptr = net.write(der);

		return new Certificate(net, net.handle("keeta_certificate_parse_der", ptr, der.length));
	}

	/** The {@code SHA3-256} hash (hex) of a hex-DER certificate, used to reference it on-chain. */
	public String certificateHash(String certificateDerHex) {
		byte[] der = certificateDerHex.getBytes(StandardCharsets.UTF_8);
		int ptr = net.write(der);

		return net.takeString(net.handle("keeta_certificate_hash", ptr, der.length));
	}

	/** A {@code MANAGE_CERTIFICATE} add operation for a hex-DER certificate plus hex-DER intermediates. */
	public Operation manageCertificateAdd(String certificateDerHex, List<String> intermediates) {
		byte[] cert = certificateDerHex.getBytes(StandardCharsets.UTF_8);
		byte[] inter = String.join("\n", intermediates).getBytes(StandardCharsets.UTF_8);
		int certPtr = net.write(cert);
		int interPtr = net.write(inter);
		int handle = net.handle("keeta_op_manage_certificate_add", certPtr, cert.length, interPtr, inter.length);

		return new Operation(net, handle);
	}

	/** A {@code MANAGE_CERTIFICATE} remove operation identified by a 32-byte hex {@code hash}. */
	public Operation manageCertificateRemove(String hashHex) {
		byte[] hash = hashHex.getBytes(StandardCharsets.UTF_8);
		int ptr = net.write(hash);

		return new Operation(net, net.handle("keeta_op_manage_certificate_remove", ptr, hash.length));
	}

	/* ---------------------------- operations ---------------------------- */

	/** A {@code SET_REP} operation delegating voting weight to {@code to}. */
	public Operation setRep(Account to) {
		return new Operation(net, net.handle("keeta_op_set_rep", to.handle()));
	}

	/** A {@code SEND} operation transferring {@code amount} of {@code token} to {@code to}. */
	public Operation send(Account to, BigInteger amount, Account token, String external) {
		byte[] amountBytes = amount.toString().getBytes(StandardCharsets.UTF_8);
		byte[] externalBytes = (external == null ? "" : external).getBytes(StandardCharsets.UTF_8);
		int amountPtr = net.write(amountBytes);
		int externalPtr = net.write(externalBytes);
		int handle = net.handle("keeta_op_send", to.handle(), amountPtr, amountBytes.length, token.handle(), externalPtr, externalBytes.length);

		return new Operation(net, handle);
	}

	/** A {@code TOKEN_ADMIN_SUPPLY} operation adjusting the block token's supply by {@code amount}. */
	public Operation tokenAdminSupply(BigInteger amount, AdjustMethod method) {
		byte[] amountBytes = amount.toString().getBytes(StandardCharsets.UTF_8);
		byte[] methodBytes = method.token().getBytes(StandardCharsets.UTF_8);
		int amountPtr = net.write(amountBytes);
		int methodPtr = net.write(methodBytes);
		int handle = net.handle("keeta_op_token_admin_supply", amountPtr, amountBytes.length, methodPtr, methodBytes.length);

		return new Operation(net, handle);
	}

	/** A {@code TOKEN_ADMIN_MODIFY_BALANCE} operation adjusting the block account's {@code token} balance. */
	public Operation tokenAdminModifyBalance(Account token, BigInteger amount, AdjustMethod method) {
		byte[] amountBytes = amount.toString().getBytes(StandardCharsets.UTF_8);
		byte[] methodBytes = method.token().getBytes(StandardCharsets.UTF_8);
		int amountPtr = net.write(amountBytes);
		int methodPtr = net.write(methodBytes);
		int handle = net.handle("keeta_op_token_admin_modify_balance", token.handle(), amountPtr, amountBytes.length, methodPtr, methodBytes.length);

		return new Operation(net, handle);
	}

	/** A {@code RECEIVE} operation crediting {@code amount} of {@code token} from {@code from}. */
	public Operation receive(Account from, BigInteger amount, Account token, boolean exact, Account forward) {
		byte[] amountBytes = amount.toString().getBytes(StandardCharsets.UTF_8);
		int amountPtr = net.write(amountBytes);
		int forwardHandle = forward == null ? 0 : forward.handle();
		int handle = net.handle("keeta_op_receive", from.handle(), amountPtr, amountBytes.length, token.handle(), exact ? 1 : 0, forwardHandle);

		return new Operation(net, handle);
	}

	/** A {@code SET_INFO} operation with no default permission. */
	public Operation setInfo(String name, String description, String metadata) {
		return setInfo(name, description, metadata, null);
	}

	/** A {@code SET_INFO} operation, optionally with a default permission set. */
	public Operation setInfo(String name, String description, String metadata, Permissions defaultPermission) {
		byte[] nameBytes = name.getBytes(StandardCharsets.UTF_8);
		byte[] descriptionBytes = description.getBytes(StandardCharsets.UTF_8);
		byte[] metadataBytes = metadata.getBytes(StandardCharsets.UTF_8);
		int namePtr = net.write(nameBytes);
		int descriptionPtr = net.write(descriptionBytes);
		int metadataPtr = net.write(metadataBytes);
		int permissions = defaultPermission == null ? 0 : defaultPermission.handle();
		int handle = net.handle("keeta_op_set_info", namePtr, nameBytes.length, descriptionPtr, descriptionBytes.length, metadataPtr, metadataBytes.length, permissions);

		return new Operation(net, handle);
	}

	/** A {@code CREATE_IDENTIFIER} operation for a plain identifier (token, storage, network). */
	public Operation createIdentifier(Account identifier) {
		return new Operation(net, net.handle("keeta_op_create_identifier", identifier.handle()));
	}

	/** A {@code CREATE_IDENTIFIER} multisig operation requiring {@code quorum} of {@code signers}. */
	public Operation createMultisig(Account multisig, List<Account> signers, int quorum) {
		int[] handles = new int[signers.size()];
		for (int index = 0; index < handles.length; index++) {
			handles[index] = signers.get(index).handle();
		}

		int signersPtr = net.writeHandles(handles);
		int handle = net.handle("keeta_op_create_multisig", multisig.handle(), signersPtr, handles.length * 4, quorum);

		return new Operation(net, handle);
	}

	/** A {@code MODIFY_PERMISSIONS} operation on the block account. */
	public Operation modifyPermissions(Account principal, Permissions permissions, AdjustMethod method) {
		return modifyPermissions(principal, permissions, method, null);
	}

	/** A {@code MODIFY_PERMISSIONS} operation against an optional target account. */
	public Operation modifyPermissions(Account principal, Permissions permissions, AdjustMethod method, Account target) {
		byte[] methodBytes = method.token().getBytes(StandardCharsets.UTF_8);
		int methodPtr = net.write(methodBytes);
		int targetHandle = target == null ? 0 : target.handle();
		int handle = net.handle("keeta_op_modify_permissions", principal.handle(), permissions.handle(), methodPtr, methodBytes.length, targetHandle);

		return new Operation(net, handle);
	}

	/** A permission set built from snake_case base flag names (see {@link Permissions}). */
	public Permissions permissions(String... flags) {
		byte[] joined = String.join("\n", flags).getBytes(StandardCharsets.UTF_8);
		int flagsPtr = net.write(joined);

		return new Permissions(net, net.handle("keeta_permissions_from_flags", flagsPtr, joined.length, 0, 0));
	}

	/* ------------------------------ blocks ------------------------------ */

	/** Start a fluent block builder. */
	public Block.Builder builder() {
		return new Block.Builder(net);
	}

	/* ------------------------------ client ------------------------------ */

	/** Open a networked client bound to a node REST {@code api} URL and network id. */
	public UserClient connect(String api, long network) {
		return new UserClient(this, api, network);
	}

	@Override
	public void close() {
		net.close();
	}
}
