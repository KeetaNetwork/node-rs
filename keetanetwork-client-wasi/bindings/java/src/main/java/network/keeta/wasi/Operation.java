package network.keeta.wasi;

/**
 * A block operation ({@code SET_REP}, {@code SET_INFO}, {@code CREATE_IDENTIFIER},
 * {@code MODIFY_PERMISSIONS}, ...) held as a guest handle.
 */
public final class Operation implements AutoCloseable {
	private final KeetaNet net;
	private int handle;

	Operation(KeetaNet net, int handle) {
		this.net = net;
		this.handle = handle;
	}

	int handle() {
		if (handle == 0) {
			throw new KeetaException("FREED_HANDLE", "operation has been closed");
		}

		return handle;
	}

	@Override
	public void close() {
		if (handle != 0) {
			net.free("keeta_op_free", handle);
			handle = 0;
		}
	}
}
