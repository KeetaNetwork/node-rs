package network.keeta.wasi.harness;

import java.math.BigInteger;
import java.util.List;

import network.keeta.wasi.Account;
import network.keeta.wasi.AdjustMethod;
import network.keeta.wasi.Algorithm;
import network.keeta.wasi.Block;
import network.keeta.wasi.IdentifierType;
import network.keeta.wasi.Keeta;
import network.keeta.wasi.KeetaException;
import network.keeta.wasi.Operation;
import network.keeta.wasi.Permissions;
import network.keeta.wasi.TransmitOptions;
import network.keeta.wasi.UserClient;

/**
 * End-to-end fee harness test exercising the bound Java SDK against a fee-enforcing
 * node.
 *
 * <p>The node charges a flat base-token fee on every transaction. Three
 * probes cover the fee paths:
 *
 * <ol>
 * <li>The sender pays its own fee through {@code TransmitOptions.withFeeSigner},
 * proving the {@code keeta_staple_fee_sends} path.</li>
 * <li>A storage account (no key of its own) pays the fee with its trusted
 * owner signing the fee block through
 * {@code TransmitOptions.withFeeBlockFrom}, proving the delegated
 * account/signer split.</li>
 * <li>A transmit paying no fee fails with a typed {@code FEE_REQUIRED}
 * before anything is published.</li>
 * </ol>
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
				 Account storageRecipient = keeta.account(trustedSeed, 8, Algorithm.ED25519);
				 Account base = keeta.accountFromPublicKeyString(baseTokenAddress)) {
				String head = client.headHash(trusted);
				check(head != null && !head.isBlank(), "funded account must have a head block");
				check(client.baseToken().publicKeyString().equals(base.publicKeyString()),
					"the derived base token must match the node's");

				senderPaysOwnFee(keeta, client, trusted, recipient, base, fee);
				storageAccountPaysFee(keeta, client, trusted, storageRecipient, base, fee);
				feeRequiredIsTyped(keeta, client, trusted, recipient, base);
			}
		}
	}

	/**
	 * A transmit paying no fee must fail with a typed {@code FEE_REQUIRED}
	 * before anything is published: the recipient's balance is unchanged
	 * after. Probes the worst case, a factory that declines by returning
	 * {@code null}.
	 */
	private static void feeRequiredIsTyped(Keeta keeta, UserClient client, Account trusted, Account recipient,
		Account base) {
		BigInteger recipientBefore = parseHex(client.balance(recipient, base));

		Block.SignedBlock send = sendBlock(keeta, client, trusted, recipient, AMOUNT, base);
		try (send) {
			TransmitOptions declines = TransmitOptions.defaults().withGenerateFeeBlock((c, staple, priority) -> null);
			client.transmit(List.of(send), declines);
			check(false, "a transmit paying no fee must throw FEE_REQUIRED");
		} catch (KeetaException exception) {
			check("FEE_REQUIRED".equals(exception.code()),
				"a transmit paying no fee must fail with FEE_REQUIRED, got " + exception.code());
		}

		BigInteger recipientAfter = parseHex(client.balance(recipient, base));
		check(recipientAfter.equals(recipientBefore), "a refused transmit must not move funds");
		System.out.println("[harness] FEE_REQUIRED_OK");
	}

	/**
	 * The sender pays its own required fee: the sender is debited the amount
	 * plus the fee and the recipient is credited the amount.
	 */
	private static void senderPaysOwnFee(Keeta keeta, UserClient client, Account trusted, Account recipient,
		Account base, BigInteger fee) {
		BigInteger senderBefore = parseHex(client.balance(trusted, base));

		Block.SignedBlock send = sendBlock(keeta, client, trusted, recipient, AMOUNT, base);
		try (send) {
			// Fee-aware: this node rejects a fee-less staple.
			client.transmit(List.of(send), TransmitOptions.defaults().withFeeSigner(trusted));
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

	/**
	 * A storage account pays the required fee while its trusted owner signs
	 * the fee block: the sender is debited only the amount and the storage
	 * account exactly the fee.
	 */
	private static void storageAccountPaysFee(Keeta keeta, UserClient client, Account trusted, Account recipient,
		Account base, BigInteger fee) {
		BigInteger funding = fee.multiply(BigInteger.TEN);
		TransmitOptions trustedPays = TransmitOptions.defaults().withFeeSigner(trusted);

		String head = client.headHash(trusted);
		try (Account storage = trusted.generateIdentifier(IdentifierType.STORAGE, hexDecode(head), 0)) {
			createStorage(keeta, client, trusted, storage, head, trustedPays);
			grantHold(keeta, client, trusted, storage, base, trustedPays);

			Block.SignedBlock fund = sendBlock(keeta, client, trusted, storage, funding, base);
			try (fund) {
				client.transmit(List.of(fund), trustedPays);
			}

			BigInteger senderBefore = parseHex(client.balance(trusted, base));
			BigInteger storageBefore = parseHex(client.balance(storage, base));

			Block.SignedBlock send = sendBlock(keeta, client, trusted, recipient, AMOUNT, base);
			try (send) {
				// Delegated: the storage account pays, its owner signs.
				client.transmit(List.of(send), TransmitOptions.defaults().withFeeBlockFrom(storage, trusted));
			}

			BigInteger senderDebit = senderBefore.subtract(parseHex(client.balance(trusted, base)));
			check(senderDebit.equals(AMOUNT),
				"sender must be debited only the amount when storage pays the fee, got " + senderDebit);

			BigInteger storageDebit = storageBefore.subtract(parseHex(client.balance(storage, base)));
			check(storageDebit.equals(fee),
				"storage payer must be debited exactly the fee (" + fee + "), got " + storageDebit);

			BigInteger recipientBalance = parseHex(client.balance(recipient, base));
			check(recipientBalance.equals(AMOUNT),
				"recipient must be credited the amount, got " + recipientBalance);

			System.out.println("[harness] STORAGE_FEE_OK storageDebit=" + storageDebit + " fee=" + fee);
		}
	}

	/** Publish the block creating {@code storage} under {@code trusted}. */
	private static void createStorage(Keeta keeta, UserClient client, Account trusted, Account storage,
		String head, TransmitOptions trustedPays) {
		try (Operation create = keeta.createIdentifier(storage);
			 Block.UnsignedBlock unsigned = keeta.builder()
				 .version(2).network(client.network()).account(trusted).signer(trusted)
				 .previous(hexDecode(head)).date(System.currentTimeMillis())
				 .addOperation(create).build();
			 Block.SignedBlock block = unsigned.sign()) {
			client.transmit(List.of(block), trustedPays);
		}
	}

	/**
	 * Grant {@code storage} the {@code STORAGE_CAN_HOLD} permission for the
	 * base token (a storage account may only hold tokens it is explicitly
	 * permitted to), signed by the trusted owner since storage accounts carry
	 * no key of their own.
	 */
	private static void grantHold(Keeta keeta, UserClient client, Account trusted, Account storage, Account base,
		TransmitOptions trustedPays) {
		try (Permissions hold = keeta.permissions(Permissions.STORAGE_CAN_HOLD);
			 Operation grant = keeta.modifyPermissions(base, hold, AdjustMethod.SET);
			 Block.UnsignedBlock unsigned = keeta.builder()
				 .version(2).network(client.network()).account(storage).signer(trusted)
				 .opening().date(System.currentTimeMillis())
				 .addOperation(grant).build();
			 Block.SignedBlock block = unsigned.sign()) {
			client.transmit(List.of(block), trustedPays);
		}
	}

	/** Build and sign a send of {@code amount} base tokens atop {@code from}'s current head. */
	private static Block.SignedBlock sendBlock(Keeta keeta, UserClient client, Account from, Account to,
		BigInteger amount, Account base) {
		String head = client.headHash(from);
		check(head != null && !head.isBlank(), "sender must have a head block");

		try (Operation op = keeta.send(to, amount, base, "");
			 Block.UnsignedBlock unsigned = keeta.builder()
				 .version(2).network(client.network()).account(from).signer(from)
				 .previous(hexDecode(head)).date(System.currentTimeMillis())
				 .addOperation(op).build()) {
			return unsigned.sign();
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
