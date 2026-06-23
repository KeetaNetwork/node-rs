package network.keeta.wasi;

/**
 * A permission set held as a guest handle, built from base flag names. 
 */
public final class Permissions implements AutoCloseable {
	public static final String ACCESS = "access";
	public static final String OWNER = "owner";
	public static final String ADMIN = "admin";
	public static final String UPDATE_INFO = "update_info";
	public static final String SEND_ON_BEHALF = "send_on_behalf";
	public static final String TOKEN_ADMIN_CREATE = "token_admin_create";
	public static final String TOKEN_ADMIN_SUPPLY = "token_admin_supply";
	public static final String TOKEN_ADMIN_MODIFY_BALANCE = "token_admin_modify_balance";
	public static final String STORAGE_CREATE = "storage_create";
	public static final String STORAGE_CAN_HOLD = "storage_can_hold";
	public static final String STORAGE_DEPOSIT = "storage_deposit";
	public static final String PERMISSION_DELEGATE_ADD = "permission_delegate_add";
	public static final String PERMISSION_DELEGATE_REMOVE = "permission_delegate_remove";
	public static final String MANAGE_CERTIFICATE = "manage_certificate";
	public static final String MULTISIG_SIGNER = "multisig_signer";

	private final KeetaNet net;
	private int handle;

	Permissions(KeetaNet net, int handle) {
		this.net = net;
		this.handle = handle;
	}

	int handle() {
		if (handle == 0) {
			throw new KeetaException("FREED_HANDLE", "permissions have been closed");
		}

		return handle;
	}

	@Override
	public void close() {
		if (handle != 0) {
			net.free("keeta_permissions_free", handle);
			handle = 0;
		}
	}
}
