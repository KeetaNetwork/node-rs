package network.keeta.wasi;

import java.util.List;

/**
 * Factory invoked mid-transmit when {@link TransmitOptions} carries one: build
 * and sign the block paying the fee the temporary-round {@code staple}
 * demands, honoring the {@code feeTokenPriority} preference. Return
 * {@code null} to pay nothing. See
 * {@link UserClient#buildFeeBlock(VoteStaple, Account, Account, List)} for the
 * common implementation.
 */
@FunctionalInterface
public interface GenerateFeeBlock {
	Block.SignedBlock generate(UserClient client, VoteStaple staple, List<Account> feeTokenPriority);
}
