package network.keeta.wasi;

import java.util.List;

/**
 * The temporary-round context handed to a {@link GenerateFeeBlock} factory:
 * the blocks being published, the node's temporary vote declaring the fee,
 * and the caller's fee-token preferences.
 */
public final class FeeRound {
	private final List<Block.SignedBlock> blocks;
	private final String temporaryVoteBase64;
	private final List<Account> feeTokenPriority;

	FeeRound(List<Block.SignedBlock> blocks, String temporaryVoteBase64, List<Account> feeTokenPriority) {
		this.blocks = blocks;
		this.temporaryVoteBase64 = temporaryVoteBase64;
		this.feeTokenPriority = feeTokenPriority;
	}

	/** The blocks of the temporary round the fee block will join. */
	public List<Block.SignedBlock> blocks() {
		return blocks;
	}

	/** The node's temporary vote (base64) declaring the required fee. */
	public String temporaryVoteBase64() {
		return temporaryVoteBase64;
	}

	/** Preferred fee tokens, highest priority first; may be empty. */
	public List<Account> feeTokenPriority() {
		return feeTokenPriority;
	}
}
