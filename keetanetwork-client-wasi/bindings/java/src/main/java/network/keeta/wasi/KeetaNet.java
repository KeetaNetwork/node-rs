package network.keeta.wasi;

import com.dylibso.chicory.runtime.ExportFunction;
import com.dylibso.chicory.runtime.Instance;
import com.dylibso.chicory.runtime.Memory;
import com.dylibso.chicory.runtime.Store;
import com.dylibso.chicory.wasi.WasiOptions;
import com.dylibso.chicory.wasi.WasiPreview1;
import com.dylibso.chicory.wasm.Parser;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;

/**
 * The KeetaNet WASI runtime: it loads the {@code wasm32-wasip1} core module on
 * the pure-JVM Chicory engine and exposes the flat handle-based C ABI as typed
 * Java helpers.
 */
public final class KeetaNet implements AutoCloseable {
	private final WasiPreview1 wasi;
	private final Instance instance;
	private final Memory memory;

	private KeetaNet(WasiPreview1 wasi, Instance instance) {
		this.wasi = wasi;
		this.instance = instance;
		this.memory = instance.memory();
	}

	/**
	 * Load the core module from an explicit filesystem path.
	 */
	public static KeetaNet load(Path module) {
		WasiOptions options = WasiOptions.builder().inheritSystem().build();
		WasiPreview1 wasi = WasiPreview1.builder().withOptions(options).build();
		Store store = new Store().addFunction(wasi.toHostFunctions());
		Instance instance = store.instantiate("keeta", Parser.parse(module.toFile()));
		KeetaNet keeta = new KeetaNet(wasi, instance);
		keeta.initializeReactor();
		return keeta;
	}

	/**
	 * Load the core module from the {@code keeta.wasi.module} system property or
	 * the {@code WASI_P1_MODULE} environment variable.
	 */
	public static KeetaNet load() {
		String path = System.getProperty("keeta.wasi.module", System.getenv("WASI_P1_MODULE"));
		if (path == null || path.isBlank()) {
			throw new KeetaException("MISSING_MODULE",
				"set -Dkeeta.wasi.module=<path> or WASI_P1_MODULE to the wasm32-wasip1 module");
		}

		return load(new File(path).toPath());
	}

	/** Run the reactor module's {@code _initialize} start, ignoring its absence. */
	private void initializeReactor() {
		try {
			instance.export("_initialize").apply();
		} catch (RuntimeException ignored) {
			// A command-style module has no `_initialize`; nothing to run.
		}
	}

	// --- flat-ABI marshalling (package-private; used by the typed wrappers) ---

	/** Invoke an export, returning its first result (0 for void/empty results). */
	long call(String name, long... args) {
		ExportFunction fn = instance.export(name);
		long[] out = fn.apply(args);
		return (out == null || out.length == 0) ? 0 : out[0];
	}

	int callInt(String name, long... args) {
		return (int) call(name, args);
	}

	/** Invoke an object-producing export, throwing the guest's coded error on a null handle. */
	int handle(String name, long... args) {
		int handle = (int) call(name, args);
		if (handle == 0) {
			throw lastError(name);
		}

		return handle;
	}

	/** Copy bytes into a fresh guest buffer; returns the pointer. */
	int write(byte[] data) {
		int ptr = (int) call("keeta_alloc", data.length);

		memory.write(ptr, data);
		return ptr;
	}

	int writeUtf8(String value) {
		return write(value.getBytes(StandardCharsets.UTF_8));
	}

	/** Write a buffer of little-endian {@code i32} handles; returns the pointer. */
	int writeHandles(int... handles) {
		byte[] buffer = new byte[handles.length * 4];
		for (int index = 0; index < handles.length; index++) {
			int value = handles[index];
			buffer[index * 4] = (byte) value;
			buffer[index * 4 + 1] = (byte) (value >> 8);
			buffer[index * 4 + 2] = (byte) (value >> 16);
			buffer[index * 4 + 3] = (byte) (value >> 24);
		}

		return write(buffer);
	}

	/** Read and release a bytes handle's payload. */
	byte[] takeBytes(long bytesHandle) {
		int handle = (int) bytesHandle;
		int ptr = callInt("keeta_bytes_ptr", handle);
		int len = callInt("keeta_bytes_len", handle);
		byte[] data = memory.readBytes(ptr, len);

		call("keeta_bytes_free", handle);

		return data;
	}

	String takeString(long bytesHandle) {
		return new String(takeBytes(bytesHandle), StandardCharsets.UTF_8);
	}

	/** The wasm length of an object's address payload, used by callers needing a length. */
	int length(byte[] data) {
		return data.length;
	}

	/** Read the pending coded error and surface it as a {@link KeetaException}. */
	KeetaException lastError(String operation) {
		long codeHandle = call("keeta_last_error_code");
		long messageHandle = call("keeta_last_error_message");
		String code = codeHandle == 0 ? "UNKNOWN" : takeString(codeHandle);
		String message = messageHandle == 0 ? operation + " failed" : takeString(messageHandle);

		return new KeetaException(code, message);
	}

	void free(String freeExport, int handle) {
		if (handle != 0) {
			call(freeExport, handle);
		}
	}

	@Override
	public void close() {
		wasi.close();
	}
}
