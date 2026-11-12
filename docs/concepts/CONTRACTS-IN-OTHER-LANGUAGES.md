# Contracts in other languages

## Abstract

This page shows how to build a Keeta contract without Rust, with the C compiler and assembler that ship in Solana's platform tools. It states what `keetanetwork-contract-engine` requires of a program, how a program calls host functions, and the build flags that keep a C program correct. The binary interface itself lives in `keetanetwork-contract-std/src/abi.rs`, and this page links to it rather than repeating it.

## Purpose

You read this page when you want to write a contract in C, in sBPF assembly, or in another language whose compiler targets sBPF through LLVM. After reading, you can build a program that `Engine::store_code` accepts, read the input the engine passes, call host functions, and avoid the build mistakes that only show up when the contract runs. Read the [Rust contract guide](../../keetanetwork-contract-std/docs/README.md) for the Rust SDK, and the [contract engine README](../../keetanetwork-contract-engine/README.md) for the account model and what each host function does.

## What the engine accepts

`Engine::store_code` loads and verifies a program with `solana-sbpf` and the settings in `Core::new` in `keetanetwork-contract-engine/src/vm.rs`. A program in any language must have the following properties.

| Property | Requirement | What happens otherwise |
| --- | --- | --- |
| Size | At most `EngineConfig::max_code_size` bytes (512 KiB by default, the same as the node's `CONTRACT_DEPLOY` limit) | `code is … bytes, more than the …-byte limit` at store time, before the file is parsed |
| File format | An ELF64 shared object for `EM_BPF`, linked, not an object file | `invalid code: ELF error: Failed to parse ELF file` at store time |
| sBPF version | Version 3, which the ELF header records as `e_flags` `0x3` | `Detected sbpf_version required by the executable which are not enabled` at store time |
| Layout | Read-only data at address `0`, code at `0x1_0000_0000`, and no writable data, as the linker script below arranges | `Invalid ELF program header` at store time. A writable static fails the link with `relocation refers to a symbol in a discarded section` |
| Entry point | The ELF entry address (`e_entry`) is the function the engine runs | An entry address of `0` gives `Failed to parse ELF file: invalid file header` at store time |
| Host functions | Every host function call uses a hash that the engine registers | `Engine::store_code` refuses the code and names the unknown hash |
| Undefined symbols | None. Every call targets code in the program or a registered host function | The program loads, but each call to the missing symbol faults when it runs (see the build rules below) |

## Entry and return

The engine calls the entry function with one argument in `r1`: a pointer to the input region at `INPUT_START` (`0x4_0000_0000`). The function returns a 64-bit value in `r0`.

- Return `0` to succeed. The engine keeps the account changes and ledger effects.
- Return any other value to fail. The whole call is undone. Call `keeta_error` with a message first, or the engine reports `returned error code <n>`.

The input layout, the account header layout and the limits are documented in the module rustdoc and constants of `keetanetwork-contract-std/src/abi.rs`. The offsets are in `abi::layout`. All integers are little-endian. Addresses take a 40-byte slot (34 bytes and zero padding), and amounts are 16-byte `u128` values.

The program may change the data and the data length (up to the capacity) of accounts whose header says both writable (offset `0`) and owned by the running contract (offset `1`). The engine checks every other byte of the input when the contract returns or invokes another contract, and fails the call if any of them changed.

The heap is 256 KiB at `HEAP_START` (`0x3_0000_0000`), zeroed for each invocation. A C program that needs dynamic memory keeps a bump pointer in the heap's first word, as `BumpAllocator` in `keetanetwork-contract-std/src/runtime.rs` does, because a program has no writable statics. The stack follows `solana-sbpf`'s `Config::default`, which allows 64 nested function calls of 4 KiB frames each.

## Host functions

sBPF v3 calls a host function with the `call` instruction and the 32-bit Murmur3 hash (seed `0`) of the function's name as the immediate. Arguments go in `r1` to `r5`, and the result comes back in `r0`. An address argument points to 34 bytes, and an amount argument points to a little-endian `u128`. A failing host function aborts the whole call, so each one returns only on success. `syscall_hash` in `keetanetwork-contract-std/src/abi.rs` computes the hashes, and the test `hashes_match_the_sbpf_loader` checks it against the loader.

| Name | Hash | C signature |
| --- | --- | --- |
| `keeta_log` | `0xd49119c4` | `uint64_t (const char *msg, uint64_t len)` |
| `keeta_attribute` | `0x65f74b62` | `uint64_t (const char *key, uint64_t key_len, const char *value, uint64_t value_len)` |
| `keeta_error` | `0x8c405832` | `uint64_t (const char *msg, uint64_t len)` |
| `keeta_set_return_data` | `0xbdca821b` | `uint64_t (const void *data, uint64_t len)` |
| `keeta_get_return_data` | `0xfb17285d` | `uint64_t (void *out, uint64_t max_len)`, which returns the full length |
| `keeta_sha256` | `0x445ee599` | `uint64_t (const uint64_t *slices, uint64_t count, uint8_t out[32])`, where `slices` holds `count` pairs of pointer and length |
| `keeta_send` | `0xd36af16c` | `uint64_t (const uint8_t to[34], const uint8_t token[34], const uint8_t amount[16], const char *external, uint64_t external_len)` |
| `keeta_balance` | `0xdafdd171` | `uint64_t (const uint8_t account[34], const uint8_t token[34], uint8_t out[16])` |
| `keeta_supply` | `0x08be8f54` | `uint64_t (const uint8_t token[34], uint8_t out[16])`, which returns `1` if the token exists and `0` otherwise |
| `keeta_set_info` | `0x7945b65b` | `uint64_t (const uint64_t fields[6])`, three pairs of pointer and length: name, description, metadata |
| `keeta_invoke` | `0x36d95b13` | `uint64_t (const uint8_t contract[34], const uint64_t *metas, uint64_t count, const void *data, uint64_t data_len)`, where `metas` holds `count` pairs of account index and writable flag |

The engine also provides the host functions that Solana's toolchain emits by itself. A C program uses them to implement the memory functions that the compiler calls.

| Name | Hash | C signature |
| --- | --- | --- |
| `abort` | `0xb6fc1a11` | `void (void)` |
| `sol_panic_` | `0x686093bb` | `void (const char *file, uint64_t len, uint64_t line, uint64_t column)` |
| `sol_log_` | `0x207559bd` | `void (const char *msg, uint64_t len)` |
| `sol_memcpy_` | `0x717cc4a3` | `void (void *dst, const void *src, uint64_t n)` |
| `sol_memmove_` | `0x434371f8` | `void (void *dst, const void *src, uint64_t n)` |
| `sol_memset_` | `0x3770fb22` | `void (void *dst, int c, uint64_t n)` |
| `sol_memcmp_` | `0x5fdcde31` | `void (const void *a, const void *b, uint64_t n, int32_t *out)` |

## Build a contract in C

### Get the toolchain

Install Anza's toolchain as the [Rust contract guide](../../keetanetwork-contract-std/docs/README.md) describes, then download the platform tools without building anything.

```bash
cargo-build-sbf --install-only
```

The tools land in `~/.cache/solana/<version>/platform-tools`, where `<version>` is the one `cargo-build-sbf --version` prints (`v1.57` at the time of writing). `llvm/bin` holds `clang` and `ld.lld`. The platform tools ship no C headers, so include only the compiler's own freestanding headers, such as `stdint.h`.

### Linker script

Save the following as `sbpf.ld`. It is the link script of the `sbpfv3-solana-solana` Rust target, which `cargo build-sbf` uses.

```text
SECTIONS
{
  .rodata 0x000000000 : SUBALIGN(8) {
    BYTE(0);
    *(.rodata*)
    *(.data.rel.ro*)
    . = ALIGN(8);
  } :rodata
  .text 0x100000000 : {
     *(.text*)
  } :text
  /DISCARD/ : {
      *(.comment*)
      *(.eh_frame*)
      *(*hash*)
      *(.bss*)
      *(.data*)
      *(.rel.dyn*)
      *(.dynamic)
      *(.dynsym)
      *(.dynstr)
    }
}

PHDRS
{
  rodata PT_LOAD FLAGS(4);
  text PT_LOAD FLAGS(1);
  other PT_NULL FLAGS(0);
}
```

To print it from the installed toolchain instead, run the platform tools' `rustc` with `RUSTC_BOOTSTRAP=1 rustc -Z unstable-options --target sbpfv3-solana-solana --print target-spec-json` and read its `link-script` field.

### Compile and link

```bash
TOOLS=~/.cache/solana/v1.57/platform-tools/llvm/bin
CFLAGS="--target=sbf-solana-solana -mcpu=v3 -O2 -ffreestanding -fvisibility=hidden"
$TOOLS/clang $CFLAGS -c counter.c -o counter.o
$TOOLS/clang $CFLAGS -c mem.c -o mem.o
$TOOLS/ld.lld -shared --Bdynamic -z notext -z defs --entry entrypoint -T sbpf.ld counter.o mem.o -o counter.so
```

| Flag | Why |
| --- | --- |
| `--target=sbf-solana-solana -mcpu=v3` | Emit sBPF v3, with host function calls by hash |
| `-ffreestanding` | There is no C library to link against |
| `-fvisibility=hidden` | Calls between functions bind inside the program. With default visibility, `ld.lld` leaves a call to an exported function such as `memcpy` unresolved in a shared object, and the call runs as an endless recursion |
| `-shared --Bdynamic -z notext` | Link a shared object, as the Rust target does |
| `-z defs` | Fail the link on any undefined symbol. Without it, a missing `memcpy` links, loads, and only fails at run time with `exceeded max BPF to BPF call depth` |
| `--entry entrypoint` | Set the ELF entry address to the `entrypoint` function |
| `-T sbpf.ld` | Place read-only data and code where the loader expects them, and discard writable data |

### Memory functions

The compiler turns struct copies and `__builtin_memcpy` and its relatives into calls to `memcpy`, `memmove`, `memset` and `memcmp`. Nothing in the platform tools defines those for C. Define them in `mem.c` on top of the engine's host functions.

```c
#include <stdint.h>

#define HOST(ret, name, hash, args) static ret(*const name) args = (ret(*) args)(hash)
HOST(void, sol_memcpy_, 0x717cc4a3, (void *, const void *, uint64_t));
HOST(void, sol_memmove_, 0x434371f8, (void *, const void *, uint64_t));
HOST(void, sol_memset_, 0x3770fb22, (void *, int, uint64_t));
HOST(void, sol_memcmp_, 0x5fdcde31, (const void *, const void *, uint64_t, int32_t *));

void *memcpy(void *d, const void *s, uint64_t n) { sol_memcpy_(d, s, n); return d; }
void *memmove(void *d, const void *s, uint64_t n) { sol_memmove_(d, s, n); return d; }
void *memset(void *d, int c, uint64_t n) { sol_memset_(d, c, n); return d; }
int memcmp(const void *a, const void *b, uint64_t n) { int32_t r; sol_memcmp_(a, b, n, &r); return r; }
```

### A counter in C

The contract keeps a `u64` in its first account and returns the new count. It is the C counterpart of the counter in the [Rust contract guide](../../keetanetwork-contract-std/docs/README.md), with the count stored as eight little-endian bytes instead of borsh. The `HOST` macro declares each host function as a constant function pointer whose value is the hash, which the compiler turns into a host function call.

```c
#include <stdint.h>

#define HOST(ret, name, hash, args) static ret(*const name) args = (ret(*) args)(hash)
HOST(uint64_t, keeta_log, 0xd49119c4, (const char *, uint64_t));
HOST(uint64_t, keeta_error, 0x8c405832, (const char *, uint64_t));
HOST(uint64_t, keeta_set_return_data, 0xbdca821b, (const void *, uint64_t));

/* Offsets from keetanetwork-contract-std/src/abi.rs (abi::layout). */
#define FUND_COUNT 88
#define FUNDS 96
#define FUND_SIZE 56
#define ACCOUNT_WRITABLE 0
#define ACCOUNT_OWN 1
#define ACCOUNT_DATA_LEN 80
#define ACCOUNT_CAPACITY 88
#define ACCOUNT_HEADER 96

static uint64_t get_u64(const uint8_t *p) { uint64_t v; __builtin_memcpy(&v, p, 8); return v; }
static void put_u64(uint8_t *p, uint64_t v) { __builtin_memcpy(p, &v, 8); }

#define FAIL(message) return (keeta_error(message, sizeof(message) - 1), 1)

uint64_t entrypoint(uint8_t *input) {
	uint8_t *at = input + FUNDS + get_u64(input + FUND_COUNT) * FUND_SIZE;
	uint64_t accounts = get_u64(at);
	uint8_t *counter = at + 8;
	if (accounts < 1) FAIL("list the counter account");
	if (!counter[ACCOUNT_WRITABLE] || !counter[ACCOUNT_OWN]) FAIL("the counter must be this contract's and writable");
	if (get_u64(counter + ACCOUNT_CAPACITY) < 8) FAIL("no room for the counter");

	uint8_t *data = counter + ACCOUNT_HEADER;
	uint64_t count = get_u64(counter + ACCOUNT_DATA_LEN) == 8 ? get_u64(data) : 0;
	put_u64(counter + ACCOUNT_DATA_LEN, 8);
	put_u64(data, count + 1);
	keeta_log("counted", 7);
	keeta_set_return_data(data, 8);
	return 0;
}
```

Call it with one writable account of its own, such as `state_id(["counter"])`, and empty instruction data. Each call returns `1`, `2`, `3` and so on. Called with the account read-only, the call fails with `the counter must be this contract's and writable`.

## Build a contract in assembly

The same `clang` assembles sBPF. Link the object with the same `ld.lld` command as for C.

```asm
	.globl entrypoint
	.text
entrypoint:
	lddw r1, message
	mov64 r2, 14
	call 0xd49119c4        # keeta_log
	mov64 r0, 0
	exit

	.section .rodata
message:
	.ascii "hello from asm"
```

```bash
$TOOLS/clang --target=sbf-solana-solana -mcpu=v3 -c hello.s -o hello.o
$TOOLS/ld.lld -shared --Bdynamic -z notext -z defs --entry entrypoint -T sbpf.ld hello.o -o hello.so
```

## Other LLVM languages

A compiler for another language produces a contract when it can emit LLVM's `sbf` target with CPU `v3`, and when its output links with the command above. The language's runtime must also live without writable statics, without a C library, and within the heap and stack above. This page tests C and assembly only.

## Check a build

1. Run `llvm-readelf -h counter.so` and check `Flags: 0x3` and an entry point address at or above `0x100000000`.
2. Run `llvm-objdump -d counter.so` and check that no instruction reads `call -0x1`. That instruction is an unresolved call.
3. Check the program with `Engine::store_code`, deploy it with `MemoryHost::deploy` and run it with `Engine::run_ledger_call`, as the [Rust contract guide](../../keetanetwork-contract-std/docs/README.md) describes for Rust programs. The steps do not depend on the source language.

`keeta-contract deploy <file.so>` in anchor-contracts deploys any program. `keeta-contract build --verifiable`, `keeta-contract verify` and `keeta-contract interface` run Cargo, so verifiable builds and interface export exist only for Rust contracts.

## Falsified by

A change to the loader settings in `Core::new` or to `register_host_functions` in `keetanetwork-contract-engine/src/vm.rs`. A change to the input layout, the memory map or the host function names in `keetanetwork-contract-std/src/abi.rs`. A platform tools release that changes the `sbpfv3-solana-solana` link script, the `sbf` target name, or the C toolchain it ships. A change to `keeta-contract` that builds or verifies programs without Cargo.
