package network.keeta.wasi.harness;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;

import network.keeta.wasi.Account;
import network.keeta.wasi.AdjustMethod;
import network.keeta.wasi.Algorithm;
import network.keeta.wasi.Block;
import network.keeta.wasi.IdentifierType;
import network.keeta.wasi.Keeta;
import network.keeta.wasi.Operation;
import network.keeta.wasi.Permissions;
import network.keeta.wasi.UserClient;

/**
 * End-to-end token-issuance harness test exercising the bound Java SDK against a node.
 *
 * <p>Creates a fresh token, mints supply into it with {@code TOKEN_ADMIN_SUPPLY},
 * and credits a holder with {@code TOKEN_ADMIN_MODIFY_BALANCE} - all in one
 * atomic staple - then confirms the on-chain supply counter and holder balance.
 */
public final class TokenSupply {
	private static final BigInteger MINT = BigInteger.valueOf(1000);

	private TokenSupply() {
	}

	public static void main(String[] args) {
		String api = require("KEETA_API");
		long network = Long.parseLong(require("KEETA_NETWORK").trim());
		String trustedSeed = require("KEETA_TRUSTED_SEED");

		try (Keeta keeta = Keeta.load()) {
			UserClient client = keeta.connect(api, network);

			try (Account trusted = keeta.account(trustedSeed, 0, Algorithm.ED25519);
				 Account holder = keeta.account(trustedSeed, 5, Algorithm.ED25519)) {
				String trustedHead = client.headHash(trusted);
				check(trustedHead != null && !trustedHead.isBlank(), "funded account must have a head block");

				try (Account token = trusted.generateIdentifier(IdentifierType.TOKEN, hexDecode(trustedHead), 0)) {
					System.out.println("[harness] minting token " + token.publicKeyString());

					mint(keeta, client, trusted, token, holder, network, trustedHead);

					BigInteger supply = parseHex(client.supply(token));
					check(supply.equals(MINT), "supply counter must equal the minted amount, got " + supply);

					BigInteger held = parseHex(client.balance(holder, token));
					check(held.equals(MINT), "holder balance must equal the credited amount, got " + held);

					System.out.println("[harness] TOKEN_OK supply=" + supply + " held=" + held);
				}
			}
		}
	}

	/**
	 * Publish one atomic staple that creates {@code token} under {@code trusted},
	 * opens it with {@code MINT} supply, and credits {@code holder} that amount.
	 */
	private static void mint(Keeta keeta, UserClient client, Account trusted, Account token, Account holder,
		long network, String trustedHead) {
		String metadata = Base64.getEncoder().encodeToString("{\"decimalPlaces\":6}".getBytes(StandardCharsets.UTF_8));

		try (Operation create = keeta.createIdentifier(token);
			 Block.UnsignedBlock createUnsigned = keeta.builder()
				 .version(2).network(network).account(trusted).signer(trusted)
				 .previous(hexDecode(trustedHead)).date(System.currentTimeMillis())
				 .addOperation(create).build();
			 Block.SignedBlock createBlock = createUnsigned.sign();

			 Permissions access = keeta.permissions(Permissions.ACCESS);
			 Operation supply = keeta.tokenAdminSupply(MINT, AdjustMethod.ADD);
			 Operation info = keeta.setInfo("TSUP", "TestSupplyToken", metadata, access);
			 Block.UnsignedBlock openUnsigned = keeta.builder()
				 .version(2).network(network).account(token).signer(trusted)
				 .opening().date(System.currentTimeMillis())
				 .addOperation(supply).addOperation(info).build();
			 Block.SignedBlock openBlock = openUnsigned.sign();

			 Operation credit = keeta.tokenAdminModifyBalance(token, MINT, AdjustMethod.ADD);
			 Block.UnsignedBlock holderUnsigned = keeta.builder()
				 .version(2).network(network).account(holder).signer(trusted)
				 .opening().date(System.currentTimeMillis())
				 .addOperation(credit).build();
			 Block.SignedBlock holderBlock = holderUnsigned.sign()) {

			client.transmit(List.of(createBlock, openBlock, holderBlock));
			System.out.println("[harness] published mint staple token=" + openBlock.hashHex());
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
