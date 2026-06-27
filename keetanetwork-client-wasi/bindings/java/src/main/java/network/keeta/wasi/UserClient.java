package network.keeta.wasi;

import java.util.Base64;
import java.util.List;

import network.keeta.node.api.LedgerApi;
import network.keeta.node.api.NodeApi;
import network.keeta.node.api.VoteApi;
import network.keeta.node.invoker.ApiClient;
import network.keeta.node.invoker.ApiException;
import network.keeta.node.model.CreateVote200Response;
import network.keeta.node.model.CreateVoteRequest;
import network.keeta.node.model.PublishVoteStapleRequest;
import network.keeta.node.model.Vote;

/**
 * A networked KeetaNet client bound to a node's REST API.
 */
public final class UserClient {
	private final KeetaNet net;
	private final long network;
	private final NodeApi nodeApi;
	private final LedgerApi ledgerApi;
	private final VoteApi voteApi;

	UserClient(Keeta keeta, String api, long network) {
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
		return attempt(() -> ledgerApi.getAccountBalance(account.address(), token.address()).getBalance(), "balance");
	}

	/** The account's current head block hash (hex), or {@code null} for an unopened account. */
	public String headHash(Account account) {
		return attempt(() -> ledgerApi.getAccountState(account.address()).getCurrentHeadBlock(), "account state");
	}

	/**
	 * Publish a signed block: request a temporary vote, escalate it to a
	 * permanent vote, assemble the staple in the core module, and post it.
	 */
	public void transmit(Block.SignedBlock block) {
		String blockBase64 = Base64.getEncoder().encodeToString(block.toBytes());
		String temporary = requestVote(blockBase64, null);
		String permanent = requestVote(blockBase64, temporary);

		byte[] voteBytes = Base64.getDecoder().decode(permanent);
		int votePtr = net.write(voteBytes);
		int voteHandle = net.handle("keeta_vote_from_bytes", votePtr, voteBytes.length);
		try {
			int blocksPtr = net.writeHandles(block.handle());
			int votesPtr = net.writeHandles(voteHandle);
			int stapleHandle = net.handle("keeta_vote_staple_build", blocksPtr, 4, votesPtr, 4, System.currentTimeMillis());
			byte[] staple = net.takeBytes(stapleHandle);
			String stapleBase64 = Base64.getEncoder().encodeToString(staple);

			attempt(() -> nodeApi.publishVoteStaple(new PublishVoteStapleRequest().votesAndBlocks(stapleBase64)),
				"publish");
		} finally {
			net.free("keeta_vote_free", voteHandle);
		}
	}

	private String requestVote(String blockBase64, String priorVoteBase64) {
		// Round one must omit `votes` entirely: an empty array is read as "other
		// votes defined" and fails the minority-weight check. Passing null leaves
		// the optional field unset, so the generated client (mapper NON_NULL)
		// drops it from the body. Round two attaches the temporary vote so the
		// representative escalates it.
		CreateVoteRequest request = new CreateVoteRequest()
			.blocks(List.of(blockBase64))
			.votes(priorVoteBase64 == null ? null : List.of(priorVoteBase64));
		CreateVote200Response response = attempt(() -> voteApi.createVote(request), "vote");
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
