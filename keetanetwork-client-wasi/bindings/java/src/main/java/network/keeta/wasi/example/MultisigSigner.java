package network.keeta.wasi.example;

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
 * End-to-end multisig token example exercising the bound Java SDK against a node.
 */
public final class MultisigSigner {
	private MultisigSigner() {
	}

	public static void main(String[] args) {
		String api = require("KEETA_API");
		long network = Long.parseLong(require("KEETA_NETWORK").trim());
		String trustedSeed = require("KEETA_TRUSTED_SEED");
		String baseToken = require("KEETA_BASE_TOKEN");

		try (Keeta keeta = Keeta.load()) {
			UserClient client = keeta.connect(api, network);

			String version = client.nodeVersion();
			check(!version.isBlank(), "node must report a version");
			System.out.println("[example] node version " + version.trim());

			try (Account trusted = keeta.account(trustedSeed, 0, Algorithm.ED25519);
				 Account base = keeta.address(baseToken);
				 Account signer1 = keeta.account(trustedSeed, 1, Algorithm.ED25519);
				 Account signer2 = keeta.account(trustedSeed, 2, Algorithm.ED25519);
				 Account signer3 = keeta.account(trustedSeed, 3, Algorithm.ED25519)) {
				System.out.println("[example] funded account " + trusted.address());
				System.out.println("[example] base balance " + client.balance(trusted, base).trim());

				String openingHead = client.headHash(trusted);
				check(openingHead != null && !openingHead.isBlank(), "funded account must have a head block");

				try (Account multisig = trusted.generateMultisigIdentifier(hexDecode(openingHead), 0)) {
					System.out.println("[example] multisig account " + multisig.address());

					String afterMultisig = createMultisig(keeta, client, trusted, multisig, List.of(signer1, signer2, signer3), network, openingHead);
					check(client.headHash(trusted).equalsIgnoreCase(afterMultisig), "create-multisig block must be the funded head");

					try (Account customToken = trusted.generateIdentifier(IdentifierType.TOKEN,
						hexDecode(afterMultisig), 0)) {
						System.out.println("[example] custom token " + customToken.address());

						String afterToken = createToken(keeta, client, trusted, customToken, network, afterMultisig);
						check(client.headHash(trusted).equalsIgnoreCase(afterToken), "create-token block must be the funded head");

						String afterGrant = grantTokenAdmin(keeta, client, trusted, customToken, multisig, network);
						check(client.headHash(customToken).equalsIgnoreCase(afterGrant), "grant block must be the token head");

						String minted = multisigMint(keeta, client, customToken, multisig, List.of(signer1, signer2), network, afterGrant);
						String tokenHead = client.headHash(customToken);
						check(tokenHead.equalsIgnoreCase(minted), "multisig-signed block must be the token head");
						check(!tokenHead.equalsIgnoreCase(afterGrant), "token head must advance after the multisig mint");

						System.out.println("[example] MULTISIG_OK " + minted);
					}
				}
			}
		}
	}

	/** Create the multisig identifier and grant it admin on the funded account; returns the funded head. */
	private static String createMultisig(Keeta keeta, UserClient client, Account funded, Account multisig,
		List<Account> signers, long network, String headHex) {
		Block.SignedBlock block;
		try (Operation create = keeta.createMultisig(multisig, signers, 2);
			 Permissions admin = keeta.permissions(Permissions.ADMIN);
			 Operation grant = keeta.modifyPermissions(multisig, admin, AdjustMethod.SET);
			 Block.UnsignedBlock unsigned = keeta.builder()
				 .version(2)
				 .network(network)
				 .account(funded)
				 .signer(funded)
				 .previous(hexDecode(headHex))
				 .date(System.currentTimeMillis())
				 .addOperation(create)
				 .addOperation(grant)
				 .build()) {
			block = unsigned.sign();
		}

		return publish(client, block, "create-multisig");
	}

	/** Create the custom token identifier from the funded account; returns the funded head. */
	private static String createToken(Keeta keeta, UserClient client, Account funded, Account customToken,
		long network, String headHex) {
		Block.SignedBlock block;
		try (Operation create = keeta.createIdentifier(customToken);
			 Block.UnsignedBlock unsigned = keeta.builder()
				 .version(2)
				 .network(network)
				 .account(funded)
				 .signer(funded)
				 .previous(hexDecode(headHex))
				 .date(System.currentTimeMillis())
				 .addOperation(create)
				 .build()) {
			block = unsigned.sign();
		}

		return publish(client, block, "create-token");
	}

	/** Open the token by granting the multisig admin over it (signed by the funded creator); returns the token head. */
	private static String grantTokenAdmin(Keeta keeta, UserClient client, Account funded, Account customToken,
		Account multisig, long network) {
		Block.SignedBlock block;
		try (Permissions admin = keeta.permissions(Permissions.ADMIN);
			 Operation grant = keeta.modifyPermissions(multisig, admin, AdjustMethod.SET);
			 Block.UnsignedBlock unsigned = keeta.builder()
				 .version(2)
				 .network(network)
				 .account(customToken)
				 .signer(funded)
				 .opening()
				 .date(System.currentTimeMillis())
				 .addOperation(grant)
				 .build()) {
			block = unsigned.sign();
		}

		return publish(client, block, "grant-token-admin");
	}

	/** Sign the token's {@code SET_INFO} with the multisig quorum and transmit it; returns the token head. */
	private static String multisigMint(Keeta keeta, UserClient client, Account customToken, Account multisig,
		List<Account> quorum, long network, String headHex) {
		String metadata = Base64.getEncoder().encodeToString("{\"decimalPlaces\":6}".getBytes(StandardCharsets.UTF_8));
		Block.SignedBlock block;
		try (Permissions access = keeta.permissions(Permissions.ACCESS);
			 Operation setInfo = keeta.setInfo("TKNM", "TestMultisigTokenExample", metadata, access);
			 Block.UnsignedBlock unsigned = keeta.builder()
				 .version(2)
				 .network(network)
				 .account(customToken)
				 .signer(multisig, quorum)
				 .previous(hexDecode(headHex))
				 .date(System.currentTimeMillis())
				 .addOperation(setInfo)
				 .build()) {
			block = unsigned.sign();
		}

		return publish(client, block, "multisig-mint");
	}

	private static String publish(UserClient client, Block.SignedBlock block, String label) {
		try (block) {
			String hash = block.hashHex();
			client.transmit(block);
			System.out.println("[example] published " + label + " block " + hash);
			return hash;
		}
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
			throw new IllegalStateException("example assertion failed: " + message);
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
