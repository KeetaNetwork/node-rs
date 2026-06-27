package network.keeta.wasi;

import java.util.List;

/**
 * A KeetaNet block and its construction pipeline: a fluent {@link Builder}
 * yields an {@link UnsignedBlock}, which signs into a {@link SignedBlock} ready
 * for transmission.
 */
public final class Block {
	private Block() {
	}

	/** Fluent builder for an unsigned block. */
	public static final class Builder implements AutoCloseable {
		private final KeetaNet net;
		private int handle;

		Builder(KeetaNet net) {
			this.net = net;
			this.handle = net.handle("keeta_builder_new");
		}

		/** Set the block version ({@code 1} or {@code 2}). */
		public Builder version(int version) {
			return step(net.handle("keeta_builder_with_version", consume(), version));
		}

		/** Set the network id. */
		public Builder network(long network) {
			return step(net.handle("keeta_builder_with_network", consume(), network));
		}

		/** Set the originating account. */
		public Builder account(Account account) {
			return step(net.handle("keeta_builder_with_account", consume(), account.handle()));
		}

		/** Set a single-account signer. */
		public Builder signer(Account signer) {
			return step(net.handle("keeta_builder_with_signer", consume(), signer.handle()));
		}

		/** Set a multisig signer: the multisig address plus the members producing signatures. */
		public Builder signer(Account multisig, List<Account> signers) {
			int[] handles = new int[signers.size()];
			for (int index = 0; index < handles.length; index++) {
				handles[index] = signers.get(index).handle();
			}

			int signersPtr = net.writeHandles(handles);
			return step(net.handle("keeta_builder_with_multisig_signer", consume(), multisig.handle(), signersPtr, handles.length * 4));
		}

		/** Set the previous block hash (32 bytes). */
		public Builder previous(byte[] previousHash) {
			int previousPtr = net.write(previousHash);
			return step(net.handle("keeta_builder_with_previous", consume(), previousPtr, previousHash.length));
		}

		/** Mark the block as an account opening (no previous). */
		public Builder opening() {
			return step(net.handle("keeta_builder_as_opening", consume()));
		}

		/** Set the block timestamp (Unix milliseconds). */
		public Builder date(long unixMillis) {
			return step(net.handle("keeta_builder_with_date", consume(), unixMillis));
		}

		/** Append an operation. */
		public Builder addOperation(Operation operation) {
			return step(net.handle("keeta_builder_with_operation", consume(), operation.handle()));
		}

		/** Build and validate the unsigned block, consuming this builder. */
		public UnsignedBlock build() {
			int unsigned = net.handle("keeta_builder_build", consume());
			return new UnsignedBlock(net, unsigned);
		}

		private int consume() {
			if (handle == 0) {
				throw new KeetaException("FREED_HANDLE", "block builder has been consumed");
			}

			int current = handle;
			handle = 0;

			return current;
		}

		private Builder step(int next) {
			this.handle = next;
			return this;
		}

		@Override
		public void close() {
			if (handle != 0) {
				net.free("keeta_builder_free", handle);
				handle = 0;
			}
		}
	}

	/** An unsigned block awaiting signatures from its required signers. */
	public static final class UnsignedBlock implements AutoCloseable {
		private final KeetaNet net;
		private int handle;

		UnsignedBlock(KeetaNet net, int handle) {
			this.net = net;
			this.handle = handle;
		}

		/** The hash (hex) the signers sign. */
		public String hashHex() {
			return net.takeString(net.handle("keeta_unsigned_hash", handle()));
		}

		/** Sign with the private keys held by the required signers, sealing the block. */
		public SignedBlock sign() {
			if (handle == 0) {
				throw new KeetaException("FREED_HANDLE", "unsigned block has been consumed");
			}

			int signed = net.handle("keeta_unsigned_sign", handle);
			handle = 0;

			return new SignedBlock(net, signed);
		}

		private int handle() {
			if (handle == 0) {
				throw new KeetaException("FREED_HANDLE", "unsigned block has been consumed");
			}

			return handle;
		}

		@Override
		public void close() {
			if (handle != 0) {
				net.free("keeta_unsigned_free", handle);
				handle = 0;
			}
		}
	}

	/** A signed block ready for transmission. */
	public static final class SignedBlock implements AutoCloseable {
		private final KeetaNet net;
		private int handle;

		SignedBlock(KeetaNet net, int handle) {
			this.net = net;
			this.handle = handle;
		}

		int handle() {
			if (handle == 0) {
				throw new KeetaException("FREED_HANDLE", "signed block has been closed");
			}

			return handle;
		}

		/** The block hash (hex). */
		public String hashHex() {
			return net.takeString(net.handle("keeta_block_hash", handle()));
		}

		/** The raw transport bytes. */
		public byte[] toBytes() {
			return net.takeBytes(net.handle("keeta_block_to_bytes", handle()));
		}

		@Override
		public void close() {
			if (handle != 0) {
				net.free("keeta_block_free", handle);
				handle = 0;
			}
		}
	}
}
