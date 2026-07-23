package network.keeta.wasi;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Publish-time options for {@link UserClient#transmit(List, TransmitOptions)}.
 * Fee payment is a {@link GenerateFeeBlock} factory;
 * {@link #withFeeSigner(Account)} and
 * {@link #withFeeBlockFrom(Account, Account)} cover the common shapes.
 */
public final class TransmitOptions {
	private final List<Account> feeTokenPriority = new ArrayList<>();
	private GenerateFeeBlock generateFeeBlock;

	private TransmitOptions() {
	}

	/** Options paying no fee: a vote requiring one fails with {@code FEE_REQUIRED}. */
	public static TransmitOptions defaults() {
		return new TransmitOptions();
	}

	/**
	 * Append a token to the fee-token preference order, highest priority
	 * first, used when a fee is payable in several tokens.
	 */
	public TransmitOptions addFeeTokenPriority(Account token) {
		this.feeTokenPriority.add(token);
		return this;
	}

	/** Pay any required fee from {@code signer}, signing for itself. */
	public TransmitOptions withFeeSigner(Account signer) {
		return withFeeBlockFrom(signer, signer);
	}

	/**
	 * Pay any required fee from {@code account}, signed by {@code signer}
	 * (delegated signing, e.g. a storage account whose owner signs). For a
	 * payer that signs for itself, prefer {@link #withFeeSigner(Account)}.
	 */
	public TransmitOptions withFeeBlockFrom(Account account, Account signer) {
		this.generateFeeBlock = (client, round) -> client.buildFeeBlock(round, account, signer);
		return this;
	}

	/** Install a hand-written fee-block factory for exotic payment flows. */
	public TransmitOptions withGenerateFeeBlock(GenerateFeeBlock factory) {
		this.generateFeeBlock = factory;
		return this;
	}

	List<Account> feeTokenPriority() {
		return Collections.unmodifiableList(feeTokenPriority);
	}

	GenerateFeeBlock generateFeeBlock() {
		return generateFeeBlock;
	}
}
