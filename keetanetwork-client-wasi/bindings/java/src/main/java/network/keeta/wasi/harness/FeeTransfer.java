package network.keeta.wasi.harness;

import java.math.BigInteger;
import java.util.List;

import network.keeta.wasi.Account;
import network.keeta.wasi.Algorithm;
import network.keeta.wasi.Block;
import network.keeta.wasi.Keeta;
import network.keeta.wasi.Operation;
import network.keeta.wasi.UserClient;

/**
 * End-to-end fee harness test exercising the bound Java SDK against a fee-enforcing
 * node.
 *
 * <p>The node charges a flat base-token fee on every transaction, so a fee-less
 * staple is rejected. This sends base tokens with a fee-aware transmit: the
 * sender originates a fee block paying the representative, proving the
 * {@code keeta_fee_send} path. It then confirms the recipient was credited and
 * the sender was debited the amount plus the fee.
 */
public final class FeeTransfer {
	private static final BigInteger AMOUNT = BigInteger.valueOf(100);

	private FeeTransfer() {
	}

	public static void main(String[] args) {
		String api = require("KEETA_API");
		long network = Long.parseLong(require("KEETA_NETWORK").trim());
		String trustedSeed = require("KEETA_TRUSTED_SEED");
		String baseTokenAddress = require("KEETA_BASE_TOKEN");
		BigInteger fee = new BigInteger(require("KEETA_FEE").trim());

		try (Keeta keeta = Keeta.load()) {
			UserClient client = keeta.connect(api, network);

			try (Account trusted = keeta.account(trustedSeed, 0, Algorithm.ED25519);
				 Account recipient = keeta.account(trustedSeed, 7, Algorithm.ED25519);
				 Account base = keeta.address(baseTokenAddress)) {
				String head = client.headHash(trusted);
				check(head != null && !head.isBlank(), "funded account must have a head block");

				BigInteger senderBefore = parseHex(client.balance(trusted, base));

				Block.SignedBlock send;
				try (Operation op = keeta.send(recipient, AMOUNT, base, "");
					 Block.UnsignedBlock unsigned = keeta.builder()
						 .version(2).network(network).account(trusted).signer(trusted)
						 .previous(hexDecode(head)).date(System.currentTimeMillis())
						 .addOperation(op).build()) {
					send = unsigned.sign();
				}

				try (send) {
					// Fee-aware: a fee-less staple would be rejected by this node.
					client.transmit(List.of(send), trusted, base);
				}

				BigInteger recipientBalance = parseHex(client.balance(recipient, base));
				check(recipientBalance.equals(AMOUNT),
					"recipient must be credited the amount, got " + recipientBalance);

				BigInteger senderAfter = parseHex(client.balance(trusted, base));
				BigInteger debited = senderBefore.subtract(senderAfter);
				check(debited.equals(AMOUNT.add(fee)),
					"sender must be debited amount plus fee (" + AMOUNT.add(fee) + "), got " + debited);

				System.out.println("[harness] FEE_OK debited=" + debited + " fee=" + fee);
			}
		}
	}

	private static BigInteger parseHex(String value) {
		check(value != null && !value.isBlank(), "expected a 0x-hex amount");
		String digits = value.startsWith("0x") || value.startsWith("0X") ? value.substring(2) : value;

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
