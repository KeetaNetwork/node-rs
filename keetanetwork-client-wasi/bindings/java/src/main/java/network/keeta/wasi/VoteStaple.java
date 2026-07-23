package network.keeta.wasi;

/**
 * A validated vote staple: the blocks of a round plus the votes endorsing
 * them, with the staple invariants (block/vote matching, validity window,
 * canonical ordering) already enforced by the core module. Handed to a
 * {@link GenerateFeeBlock} factory mid-transmit as the temporary round.
 */
public final class VoteStaple implements AutoCloseable {
	private final KeetaNet net;
	private final int handle;

	VoteStaple(KeetaNet net, int handle) {
		this.net = net;
		this.handle = handle;
	}

	int handle() {
		return handle;
	}

	@Override
	public void close() {
		net.free("keeta_vote_staple_free", handle);
	}
}
