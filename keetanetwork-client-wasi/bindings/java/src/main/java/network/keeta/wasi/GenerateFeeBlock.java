package network.keeta.wasi;

/**
 * Caller-supplied fee-block factory, invoked mid-transmit with the temporary
 * round; the returned block joins the permanent round and the staple.
 * Receives the transmitting client so it can chain through
 * {@link UserClient#buildFeeBlock(FeeRound, Account, Account)}. Return
 * {@code null} to publish without a fee block (no fee owed).
 */
@FunctionalInterface
public interface GenerateFeeBlock {
	Block.SignedBlock generate(UserClient client, FeeRound round);
}
