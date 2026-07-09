package network.keeta.wasi.harness;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import network.keeta.wasi.Account;
import network.keeta.wasi.Algorithm;
import network.keeta.wasi.Keeta;

/**
 * Cross-implementation account parity check for the bound Java SDK.
 *
 * Consumes the reference TypeScript SDK's canonical account material (via the
 * {@code KEETA_PARITY_INPUT} JSON) and, for every algorithm, reconstructs the
 * account through each of the three key-material constructors
 * ({@code accountFromPrivateKey}, {@code accountFromPublicKey},
 * {@code accountFromPassphrase}). It asserts address/public-key parity, verifies
 * the reference signature, decrypts the reference ciphertext, and emits its own
 * signature and ciphertexts so the caller can round-trip them back through the
 * reference SDK.
 */
public final class AccountParity {
	private static final ObjectMapper MAPPER = new ObjectMapper();

	private AccountParity() {
	}

	public static void main(String[] args) throws Exception {
		JsonNode accounts = MAPPER.readTree(require("KEETA_PARITY_INPUT")).get("accounts");
		byte[] message = hexDecode(require("KEETA_MESSAGE_HEX"));
		byte[] plaintext = hexDecode(require("KEETA_PLAINTEXT_HEX"));
		List<String> words = Arrays.asList(require("KEETA_PASSPHRASE").trim().split("\\s+"));
		int index = Integer.parseInt(require("KEETA_INDEX").trim());
		String[] algorithms = require("KEETA_ALGORITHMS").trim().split(",");

		ObjectNode results = MAPPER.createObjectNode();

		try (Keeta keeta = Keeta.load()) {
			for (String name : algorithms) {
				Algorithm algorithm = algorithmFor(name);
				JsonNode reference = accounts.get(name);
				check(reference != null, "reference is missing algorithm " + name);

				String address = reference.get("address").asText();
				String publicKeyHex = reference.get("publicKeyHex").asText();
				String rawPublicKeyHex = reference.get("rawPublicKeyHex").asText();
				byte[] referenceSignature = hexDecode(reference.get("signatureHex").asText());
				byte[] referenceCiphertext = hexDecode(reference.get("ciphertextHex").asText());
				String passphraseAddress = reference.get("passphraseAddress").asText();

				ObjectNode result = results.putObject(name);
				roundTripPrivateKey(keeta, algorithm, name, reference.get("privateKeyHex").asText(),
					address, publicKeyHex, message, referenceSignature, plaintext, referenceCiphertext, result);
				roundTripPublicKey(keeta, algorithm, name, rawPublicKeyHex, address, publicKeyHex, message,
					referenceSignature, plaintext, result);
				roundTripPublicKeyAndType(keeta, name, publicKeyHex, address);
				checkPassphrase(keeta, algorithm, name, words, index, passphraseAddress);
			}
		}

		System.out.println("PARITY_RESULT:" + MAPPER.writeValueAsString(results));
		System.out.println("ACCOUNT_PARITY_OK");
	}

	/** Reconstruct from the private key; assert identity and both signing/encryption directions. */
	private static void roundTripPrivateKey(Keeta keeta, Algorithm algorithm, String name, String privateKeyHex,
		String address, String publicKeyHex, byte[] message, byte[] referenceSignature, byte[] plaintext,
		byte[] referenceCiphertext, ObjectNode result) {
		try (Account account = keeta.accountFromPrivateKey(privateKeyHex, algorithm)) {
			check(account.publicKeyString().equals(address), name + " private-key address must match the reference");
			check(account.publicKey().equalsIgnoreCase(publicKeyHex), name + " private-key public key must match");
			check(account.verify(message, referenceSignature), name + " must verify the reference signature");
			check(Arrays.equals(account.decrypt(referenceCiphertext), plaintext),
				name + " must decrypt the reference ciphertext");

			result.put("signatureHex", hexEncode(account.sign(message)));
			result.put("ciphertextHex", hexEncode(account.encrypt(plaintext)));
		}
	}

	/** Reconstruct the read-only account from the raw public key; verify and encrypt-to. */
	private static void roundTripPublicKey(Keeta keeta, Algorithm algorithm, String name, String rawPublicKeyHex,
		String address, String publicKeyHex, byte[] message, byte[] referenceSignature, byte[] plaintext,
		ObjectNode result) {
		try (Account account = keeta.accountFromPublicKey(rawPublicKeyHex, algorithm)) {
			check(account.publicKeyString().equals(address), name + " public-key address must match the reference");
			check(account.publicKey().equalsIgnoreCase(publicKeyHex),
				name + " read-only public key must match the reference");
			check(account.verify(message, referenceSignature),
				name + " read-only account must verify the reference signature");

			result.put("ciphertextPubHex", hexEncode(account.encrypt(plaintext)));
		}
	}

	/** Reconstruct from the type-prefixed key hex; assert address and getter round-trip. */
	private static void roundTripPublicKeyAndType(Keeta keeta, String name, String publicKeyHex, String address) {
		try (Account account = keeta.accountFromPublicKeyAndType(publicKeyHex)) {
			check(account.publicKeyString().equals(address),
				name + " public-key-and-type address must match the reference");
			check(account.publicKeyAndTypeString().equals("0x" + publicKeyHex.toUpperCase()),
				name + " publicKeyAndTypeString must round-trip the reference key material");
		}
	}

	/** Reconstruct from the passphrase; assert the derived address matches the reference. */
	private static void checkPassphrase(Keeta keeta, Algorithm algorithm, String name, List<String> words,
		int index, String passphraseAddress) {
		try (Account account = keeta.accountFromPassphrase(words, index, algorithm)) {
			check(account.publicKeyString().equals(passphraseAddress),
				name + " passphrase address must match the reference");
		}
	}

	private static Algorithm algorithmFor(String name) {
		switch (name) {
			case "ed25519":
				return Algorithm.ED25519;
			case "ecdsa_secp256k1":
				return Algorithm.ECDSA_SECP256K1;
			case "ecdsa_secp256r1":
				return Algorithm.ECDSA_SECP256R1;
			default:
				throw new IllegalArgumentException("unsupported algorithm: " + name);
		}
	}

	private static byte[] hexDecode(String hex) {
		byte[] bytes = new byte[hex.length() / 2];
		for (int index = 0; index < bytes.length; index++) {
			bytes[index] = (byte) Integer.parseInt(hex.substring(index * 2, index * 2 + 2), 16);
		}

		return bytes;
	}

	private static String hexEncode(byte[] bytes) {
		StringBuilder builder = new StringBuilder(bytes.length * 2);
		for (byte value : bytes) {
			builder.append(Character.forDigit((value >> 4) & 0xF, 16));
			builder.append(Character.forDigit(value & 0xF, 16));
		}

		return builder.toString();
	}

	private static void check(boolean condition, String message) {
		if (!condition) {
			throw new IllegalStateException("parity assertion failed: " + message);
		}
	}

	private static String require(String key) {
		String value = System.getenv(key);
		if (value == null || value.isBlank()) {
			throw new IllegalStateException("missing required environment variable " + key);
		}

		return value;
	}
}
