package network.keeta.wasi.harness;

import java.math.BigInteger;
import java.util.List;

import network.keeta.wasi.Account;
import network.keeta.wasi.Algorithm;
import network.keeta.wasi.Certificate;
import network.keeta.wasi.Keeta;
import network.keeta.wasi.UserClient;

/**
 * End-to-end client-operations harness test for the bound Java SDK.
 *
 * Against a live reference node it drives the high-level {@link UserClient}
 * helpers and confirms their effects on-chain by reading ledger balances and
 * head hashes:
 *
 *   1. A base-token transfer: the funded account sends to a fresh recipient.
 *      On this network a send credits the recipient directly, so the funded
 *      balance must drop by the amount and the recipient balance must rise to
 *      it.
 *   2. Certificate management: a reference-issued certificate is verified
 *      valid, attached to the funded account, then removed, each advancing the
 *      funded head.
 */
public final class ClientOperations {
	/** The base-token amount transferred from the funded account to the recipient. */
	private static final BigInteger SEND_AMOUNT = BigInteger.valueOf(250_000L);

	/** The recipient derivation index off the trusted seed (a fresh, unopened account). */
	private static final int RECIPIENT_INDEX = 9;

	private ClientOperations() {
	}

	public static void main(String[] args) {
		String api = require("KEETA_API");
		long network = Long.parseLong(require("KEETA_NETWORK").trim());
		String trustedSeed = require("KEETA_TRUSTED_SEED");
		String baseToken = require("KEETA_BASE_TOKEN");
		String certificateDerHex = require("KEETA_CERT_DER");

		try (Keeta keeta = Keeta.load()) {
			UserClient client = keeta.connect(api, network);

			try (Account trusted = keeta.account(trustedSeed, 0, Algorithm.ED25519);
				 Account recipient = keeta.account(trustedSeed, RECIPIENT_INDEX, Algorithm.ED25519);
				 Account base = keeta.address(baseToken)) {
				transferRoundTrip(client, trusted, recipient, base);
				certificateRoundTrip(keeta, client, trusted, certificateDerHex);
			}
		}
	}

	/** Send base tokens to a fresh recipient and confirm both balances on-chain. */
	private static void transferRoundTrip(UserClient client, Account trusted, Account recipient, Account base) {
		BigInteger fundedBefore = balance(client, trusted, base);
		check(fundedBefore.compareTo(SEND_AMOUNT) >= 0, "funded account must hold enough base token to send");

		String hash = client.send(trusted, recipient, SEND_AMOUNT, base, "client-operations");
		System.out.println("[harness] sent transfer block " + hash);

		BigInteger fundedAfter = balance(client, trusted, base);
		BigInteger recipientAfter = balance(client, recipient, base);
		check(fundedAfter.equals(fundedBefore.subtract(SEND_AMOUNT)), "funded balance must drop by the sent amount");
		check(recipientAfter.equals(SEND_AMOUNT), "recipient balance must be credited by the send");

		System.out.println("[harness] SEND_OK funded " + fundedAfter + " recipient " + recipientAfter);
	}

	/** Verify, attach, then remove a reference-issued certificate on the funded account. */
	private static void certificateRoundTrip(Keeta keeta, UserClient client, Account trusted, String certificateDerHex) {
		// The reference issues a certificate whose validity window brackets the
		// present, so parsing it back must report it valid right now.
		try (Certificate certificate = keeta.certificateFromDer(hexDecode(certificateDerHex))) {
			check(certificate.validAt(System.currentTimeMillis()), "the reference certificate must be valid now");
		}

		String head = client.headHash(trusted);
		String afterAdd = client.modifyCertificateAdd(trusted, certificateDerHex, List.of());
		check(!afterAdd.equalsIgnoreCase(head), "the certificate add must advance the funded head");

		String hash = keeta.certificateHash(certificateDerHex);
		String afterRemove = client.modifyCertificateRemove(trusted, hash);
		check(!afterRemove.equalsIgnoreCase(afterAdd), "the certificate remove must advance the funded head");

		System.out.println("[harness] CERT_OK " + hash);
	}

	private static BigInteger balance(UserClient client, Account account, Account token) {
		String raw = client.balance(account, token).trim();
		String digits = raw.startsWith("0x") || raw.startsWith("0X") ? raw.substring(2) : raw;
		if (digits.isEmpty()) {
			return BigInteger.ZERO;
		}

		return new BigInteger(digits, 16);
	}

	private static byte[] hexDecode(String hex) {
		byte[] bytes = new byte[hex.length() / 2];
		for (int index = 0; index < bytes.length; index++) {
			bytes[index] = (byte) Integer.parseInt(hex.substring(index * 2, index * 2 + 2), 16);
		}

		return bytes;
	}

	private static void check(boolean condition, String message) {
		if (!condition) {
			throw new IllegalStateException("harness assertion failed: " + message);
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
