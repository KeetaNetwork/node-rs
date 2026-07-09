package network.keeta.wasi;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import network.keeta.node.api.LedgerApi;
import network.keeta.node.api.NodeApi;
import network.keeta.node.api.VoteApi;
import network.keeta.node.invoker.ApiClient;
import network.keeta.node.invoker.ApiException;
import network.keeta.node.model.CreateVoteResponse;
import network.keeta.node.model.CreateVoteRequest;
import network.keeta.node.model.PublishVoteStapleRequest;
import network.keeta.node.model.Vote;

/**
 * A networked KeetaNet client bound to a node's REST API.
 */
public final class UserClient {
	private final Keeta keeta;
	private final KeetaNet net;
	private final long network;
	private final NodeApi nodeApi;
	private final LedgerApi ledgerApi;
	private final VoteApi voteApi;

	UserClient(Keeta keeta, String api, long network) {
		this.keeta = keeta;
		this.net = keeta.runtime();
		this.network = network;

		ApiClient client = new ApiClient();
		client.updateBaseUri(api.endsWith("/") ? api.substring(0, api.length() - 1) : api);
		this.nodeApi = new NodeApi(client);
		this.ledgerApi = new LedgerApi(client);
		this.voteApi = new VoteApi(client);
	}

	/** The network id this client is bound to (used when building blocks). */
	public long network() {
		return network;
	}

	/** The node software version string. */
	public String nodeVersion() {
		return attempt(() -> nodeApi.getNodeVersion().getNode(), "node version");
	}

	/** The {@code account} balance of {@code token} as a 0x-prefixed hexadecimal string. */
	public String balance(Account account, Account token) {
		return attempt(() -> ledgerApi.getAccountBalance(account.publicKeyString(), token.publicKeyString()).getBalance(), "balance");
	}

	/** The account's current head block hash (hex), or {@code null} for an unopened account. */
	public String headHash(Account account) {
		return attempt(() -> ledgerApi.getAccountState(account.publicKeyString()).getCurrentHeadBlock(), "account state");
	}

	/** Total supply of {@code token} as a 0x-prefixed hex string (token accounts only); {@code null} when absent. */
	public String supply(Account token) {
		return attempt(() -> {
			var info = ledgerApi.getAccountState(token.publicKeyString()).getInfo();
			return info == null ? null : info.getSupply();
		}, "token supply");
	}

	/**
	 * Publish a single signed block as its own staple.
	 */
	public void transmit(Block.SignedBlock block) {
		transmit(List.of(block));
	}

	/**
	 * Publish several signed blocks as one atomic staple, paying no fee.
	 */
	public void transmit(List<Block.SignedBlock> blocks) {
		transmit(blocks, null, null);
	}

	/**
	 * Publish {@code blocks} as one atomic staple. Request a temporary vote
	 * covering every block; when it declares a required fee and both
	 * {@code feeSigner} and {@code baseToken} are supplied, originate a fee block
	 * paying it.
	 */
	public void transmit(List<Block.SignedBlock> blocks, Account feeSigner, Account baseToken) {
		List<String> encoded = encode(blocks);
		String temporary = requestVote(encoded, null);

		Block.SignedBlock feeBlock = (feeSigner == null || baseToken == null)
			? null
			: buildFeeBlock(feeSigner, baseToken, blocks, temporary);

		try {
			List<Block.SignedBlock> all = blocks;
			List<String> encodedAll = encoded;
			if (feeBlock != null) {
				// The fee block joins the permanent round last; the node
				// recognizes it by its FEE purpose and escalates the temporary
				// votes over the original blocks.
				all = new ArrayList<>(blocks);
				all.add(feeBlock);
				encodedAll = encode(all);
			}

			String permanent = requestVote(encodedAll, temporary);
			publishStaple(all, permanent);
		} finally {
			if (feeBlock != null) {
				feeBlock.close();
			}
		}
	}

	private static List<String> encode(List<Block.SignedBlock> blocks) {
		List<String> encoded = new ArrayList<>(blocks.size());
		for (Block.SignedBlock block : blocks) {
			encoded.add(Base64.getEncoder().encodeToString(block.toBytes()));
		}

		return encoded;
	}

	/** Assemble the staple over {@code blocks} plus the permanent vote, and post it. */
	private void publishStaple(List<Block.SignedBlock> blocks, String permanentVoteBase64) {
		byte[] voteBytes = Base64.getDecoder().decode(permanentVoteBase64);
		int votePtr = net.write(voteBytes);
		int voteHandle = net.handle("keeta_vote_from_bytes", votePtr, voteBytes.length);
		try {
			int[] blockHandles = new int[blocks.size()];
			for (int index = 0; index < blockHandles.length; index++) {
				blockHandles[index] = blocks.get(index).handle();
			}

			int blocksPtr = net.writeHandles(blockHandles);
			int votesPtr = net.writeHandles(voteHandle);
			int stapleHandle = net.handle("keeta_vote_staple_build", blocksPtr, blockHandles.length * 4, votesPtr, 4,
				System.currentTimeMillis());
			byte[] staple = net.takeBytes(stapleHandle);
			String stapleBase64 = Base64.getEncoder().encodeToString(staple);

			attempt(() -> nodeApi.publishVoteStaple(new PublishVoteStapleRequest().votesAndBlocks(stapleBase64)),
				"publish");
		} finally {
			net.free("keeta_vote_free", voteHandle);
		}
	}

	/**
	 * Build and sign the fee block paying {@code temporaryVoteBase64}'s required
	 * fee in {@code baseToken}, chained atop {@code feeSigner}'s block in the
	 * staple (or its ledger head). Returns {@code null} when no fee is owed.
	 */
	private Block.SignedBlock buildFeeBlock(Account feeSigner, Account baseToken, List<Block.SignedBlock> blocks,
		String temporaryVoteBase64) {
		byte[] voteBytes = Base64.getDecoder().decode(temporaryVoteBase64);
		int votePtr = net.write(voteBytes);
		int voteHandle = net.handle("keeta_vote_from_bytes", votePtr, voteBytes.length);
		try {
			int feeOpHandle = net.callInt("keeta_fee_send", voteHandle, baseToken.handle(), 0, 0);
			if (feeOpHandle == 0) {
				return null;
			}

			String previous = feeBlockPrevious(feeSigner, blocks);
			Block.Builder builder = keeta.builder()
				.version(2)
				.network(network)
				.account(feeSigner)
				.signer(feeSigner)
				.purpose("fee")
				.date(System.currentTimeMillis());
			Block.Builder positioned = (previous == null || previous.isBlank())
				? builder.opening()
				: builder.previous(hexDecode(previous));

			try (Operation feeOp = new Operation(net, feeOpHandle);
				 Block.UnsignedBlock unsigned = positioned.addOperation(feeOp).build()) {
				return unsigned.sign();
			}
		} finally {
			net.free("keeta_vote_free", voteHandle);
		}
	}

	/** The fee block's previous: {@code feeSigner}'s last block in {@code blocks}, else its ledger head. */
	private String feeBlockPrevious(Account feeSigner, List<Block.SignedBlock> blocks) {
		String signerAddress = feeSigner.publicKeyString();
		String previous = null;
		for (Block.SignedBlock block : blocks) {
			try (Account account = block.account()) {
				if (account.publicKeyString().equals(signerAddress)) {
					previous = block.hashHex();
				}
			}
		}

		return previous == null ? headHash(feeSigner) : previous;
	}

	/**
	 * Send {@code amount} of {@code token} from {@code from} to {@code to},
	 * publishing the send as its own staple. On this network a send credits the
	 * recipient directly, so no follow-up receive is required for a plain
	 * transfer. Returns the published block hash.
	 */
	public String send(Account from, Account to, BigInteger amount, Account token, String external) {
		return publish(buildSigned(from, keeta.send(to, amount, token, external)));
	}

	/** Publish a {@code RECEIVE} on {@code who} for funds {@code from} another account. */
	public String receive(Account who, Account from, BigInteger amount, Account token, boolean exact, Account forward) {
		return publish(buildSigned(who, keeta.receive(from, amount, token, exact, forward)));
	}

	/** Attach {@code certificateDerHex} (hex-DER) plus optional intermediates to {@code account}. */
	public String modifyCertificateAdd(Account account, String certificateDerHex, List<String> intermediates) {
		return publish(buildSigned(account, keeta.manageCertificateAdd(certificateDerHex, intermediates)));
	}

	/** Remove the certificate identified by 32-byte hex {@code hash} from {@code account}. */
	public String modifyCertificateRemove(Account account, String hash) {
		return publish(buildSigned(account, keeta.manageCertificateRemove(hash)));
	}

	/**
	 * Build and sign a single-operation block on {@code account}, positioning it
	 * as an opening block for an unopened account or atop its current head
	 * otherwise. The operation handle is consumed here.
	 */
	private Block.SignedBlock buildSigned(Account account, Operation operation) {
		String head = headHash(account);
		boolean opening = head == null || head.isBlank();
		Block.Builder builder = keeta.builder()
			.version(2)
			.network(network)
			.account(account)
			.signer(account)
			.date(System.currentTimeMillis());
		Block.Builder positioned = opening ? builder.opening() : builder.previous(hexDecode(head));

		try (Operation owned = operation;
			 Block.UnsignedBlock unsigned = positioned.addOperation(owned).build()) {
			return unsigned.sign();
		}
	}

	private String publish(Block.SignedBlock block) {
		try (block) {
			String hash = block.hashHex();
			transmit(block);
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

	private String requestVote(List<String> blocksBase64, String priorVoteBase64) {
		// Round one must omit `votes` entirely: an empty array is read as "other
		// votes defined" and fails the minority-weight check. Passing null leaves
		// the optional field unset, so the generated client (mapper NON_NULL)
		// drops it from the body. Round two attaches the temporary vote so the
		// representative escalates it.
		CreateVoteRequest request = new CreateVoteRequest()
			.blocks(blocksBase64)
			.votes(priorVoteBase64 == null ? null : List.of(priorVoteBase64));
		CreateVoteResponse response = attempt(() -> voteApi.createVote(request), "vote");
		Vote vote = response.getVote();

		if (vote == null || vote.get$Binary() == null) {
			throw new KeetaException("VOTE_DECLINED", "node returned no vote");
		}

		return vote.get$Binary();
	}

	private static <T> T attempt(NodeCall<T> call, String what) {
		try {
			return call.run();
		} catch (ApiException exception) {
			throw new KeetaException("NODE_ERROR",
				what + " returned HTTP " + exception.getCode() + ": " + exception.getResponseBody());
		}
	}

	@FunctionalInterface
	private interface NodeCall<T> {
		T run() throws ApiException;
	}
}
