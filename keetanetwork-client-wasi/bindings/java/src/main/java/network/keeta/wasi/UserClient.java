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
	private final Account baseToken;
	private final NodeApi nodeApi;
	private final LedgerApi ledgerApi;
	private final VoteApi voteApi;

	UserClient(Keeta keeta, String api, long network) {
		this.keeta = keeta;
		this.net = keeta.runtime();
		this.network = network;
		this.baseToken = new Account(net, net.handle("keeta_base_token", network));

		String baseUri = api;
		if (baseUri.endsWith("/")) {
			baseUri = baseUri.substring(0, baseUri.length() - 1);
		}

		ApiClient client = new ApiClient();
		client.updateBaseUri(baseUri);
		this.nodeApi = new NodeApi(client);
		this.ledgerApi = new LedgerApi(client);
		this.voteApi = new VoteApi(client);
	}

	/** The network id this client is bound to (used when building blocks). */
	public long network() {
		return network;
	}

	/** The network's base token (the implicit fee currency), derived from the network id. */
	public Account baseToken() {
		return baseToken;
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
			if (info == null) {
				return null;
			}

			return info.getSupply();
		}, "token supply");
	}

	/**
	 * Publish a single signed block as its own staple.
	 */
	public void transmit(Block.SignedBlock block) {
		transmit(List.of(block));
	}

	/**
	 * Publish several signed blocks as one atomic staple, paying no fee: a
	 * vote requiring one fails with {@code FEE_REQUIRED}.
	 */
	public void transmit(List<Block.SignedBlock> blocks) {
		transmit(blocks, TransmitOptions.defaults());
	}

	/**
	 * Publish {@code blocks} as one atomic staple. When {@code options}
	 * carries a fee-block factory it is invoked with the temporary round, and
	 * any block it returns joins the permanent round and the staple. Without
	 * a factory, a vote requiring a fee fails with {@code FEE_REQUIRED}
	 * before anything is published.
	 */
	public void transmit(List<Block.SignedBlock> blocks, TransmitOptions options) {
		List<String> encoded = encode(blocks);
		String temporary = requestVote(encoded, null);

		GenerateFeeBlock factory = options.generateFeeBlock();
		if (factory == null && feesRequired(temporary)) {
			throw new KeetaException("FEE_REQUIRED", "votes require a fee but no fee-block factory was supplied");
		}

		Block.SignedBlock feeBlock = null;
		if (factory != null) {
			feeBlock = factory.generate(this, new FeeRound(blocks, temporary, options.feeTokenPriority()));
		}

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
			long currentTime = System.currentTimeMillis();
			int stapleHandle = net.handle("keeta_vote_staple_build", blocksPtr, blockHandles.length * 4, votesPtr, 4,  currentTime);
			byte[] staple = net.takeBytes(stapleHandle);
			String stapleBase64 = Base64.getEncoder().encodeToString(staple);

			attempt(() -> nodeApi.publishVoteStaple(new PublishVoteStapleRequest().votesAndBlocks(stapleBase64)), "publish");
		} finally {
			net.free("keeta_vote_free", voteHandle);
		}
	}

	/**
	 * Build and sign a fee block paying {@code round}'s required fee:
	 * {@code account}'s balance pays, {@code signer} signs.
	 */
	public Block.SignedBlock buildFeeBlock(FeeRound round, Account account, Account signer) {
		int voteHandle = voteHandle(round.temporaryVoteBase64());
		try {
			int feeOpHandle = feeSend(voteHandle, round.feeTokenPriority());
			if (feeOpHandle == 0) {
				return null;
			}

			String previous = tipHashFor(account, round.blocks());
			if (previous == null) {
				previous = headHash(account);
			}

			Block.Builder builder = keeta.builder()
				.version(2)
				.network(network)
				.account(account)
				.signer(signer)
				.purpose("fee")
				.date(System.currentTimeMillis());
			Block.Builder positioned = positionAfter(builder, previous);

			try (Operation feeOp = new Operation(net, feeOpHandle);
				 Block.UnsignedBlock unsigned = positioned.addOperation(feeOp).build()) {
				return unsigned.sign();
			}
		} finally {
			net.free("keeta_vote_free", voteHandle);
		}
	}

	/** Decode a base64 vote into a guest vote handle. */
	private int voteHandle(String voteBase64) {
		byte[] voteBytes = Base64.getDecoder().decode(voteBase64);
		int votePtr = net.write(voteBytes);

		return net.handle("keeta_vote_from_bytes", votePtr, voteBytes.length);
	}

	/** Whether the base64 vote obliges a fee block. */
	private boolean feesRequired(String voteBase64) {
		int voteHandle = voteHandle(voteBase64);
		try {
			return net.callInt("keeta_fees_required", voteHandle) != 0;
		} finally {
			net.free("keeta_vote_free", voteHandle);
		}
	}

	/**
	 * The fee-paying operation handle the vote requires in the base token,
	 * honoring the {@code priority} token preference; 0 when no fee is owed.
	 */
	private int feeSend(int voteHandle, List<Account> priority) {
		int priorityPtr = 0;
		int priorityLen = 0;
		if (!priority.isEmpty()) {
			int[] priorityHandles = new int[priority.size()];
			for (int index = 0; index < priorityHandles.length; index++) {
				priorityHandles[index] = priority.get(index).handle();
			}

			priorityPtr = net.writeHandles(priorityHandles);
			priorityLen = priorityHandles.length * 4;
		}

		return net.callInt("keeta_fee_send", voteHandle, baseToken.handle(), priorityPtr, priorityLen);
	}

	/** {@code payer}'s last block hash (hex) among {@code blocks}, or {@code null} when absent. */
	private String tipHashFor(Account payer, List<Block.SignedBlock> blocks) {
		int[] blockHandles = new int[blocks.size()];
		for (int index = 0; index < blockHandles.length; index++) {
			blockHandles[index] = blocks.get(index).handle();
		}

		int blocksPtr = net.writeHandles(blockHandles);
		int tipHandle = net.callInt("keeta_blocks_tip_for", blocksPtr, blockHandles.length * 4, payer.handle());

		if (tipHandle == 0) {
			return null;
		}

		return net.takeString(tipHandle);
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
		Block.Builder builder = keeta.builder()
			.version(2)
			.network(network)
			.account(account)
			.signer(account)
			.date(System.currentTimeMillis());
		Block.Builder positioned = positionAfter(builder, head);

		try (Operation owned = operation;
			 Block.UnsignedBlock unsigned = positioned.addOperation(owned).build()) {
			return unsigned.sign();
		}
	}

	/**
	 * Position {@code builder} atop {@code previous}, or as an opening block
	 * when the account has no chain yet ({@code previous} null or blank).
	 */
	private static Block.Builder positionAfter(Block.Builder builder, String previous) {
		if (previous == null || previous.isBlank()) {
			return builder.opening();
		}

		return builder.previous(hexDecode(previous));
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
		List<String> priorVotes = null;
		if (priorVoteBase64 != null) {
			priorVotes = List.of(priorVoteBase64);
		}

		CreateVoteRequest request = new CreateVoteRequest()
			.blocks(blocksBase64)
			.votes(priorVotes);
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
