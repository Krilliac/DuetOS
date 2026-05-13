# Kernel Utilities

> **Audience:** Kernel hackers — anyone reaching for a helper before
> writing a new one
>
> **Execution context:** Kernel — every helper is freestanding; no heap
> allocations on the hot path
>
> **Maturity:** v0 — all helpers KAT-tested at boot where verifiable

## Overview

[`kernel/util/`](../../kernel/util/) holds the freestanding pieces that
don't belong to any particular subsystem but that every subsystem reaches
for. The contract for everything in this tree:

- **No allocator calls on the hot path.** Callers pass the output buffer.
- **No `KLOG` on the hot path.** Errors return through `Result<T, E>`.
- **No global mutable state** except where explicitly documented (the
  random pool is the only one).
- **Hosted-buildable** where it can be — the codec parsers and the
  `Result` type compile cleanly in the hosted test harness so they get
  unit-test coverage without a QEMU boot.

The point of keeping a tight, freestanding `util` tree is that anything
in it can be called from anywhere in the kernel without context restrictions
(allocator, IRQ, panic path). If a helper would need to touch the heap or
the log, it does not belong here.

## Inventory

### Numerics, Types, Asserts

| File | Purpose |
|------|---------|
| [`types.h`](../../kernel/util/types.h) | Fixed-width integer aliases (`u8..u64`, `i8..i64`, `uptr`, `usize`, `isize`). The kernel-wide naming convention. |
| [`saturating.h`](../../kernel/util/saturating.h) | Saturating arithmetic — `SatAddU64`, `SatSubU64`, etc. Avoid wrap on counters. |
| [`debug_assert.h`](../../kernel/util/debug_assert.h) | `DEBUG_ASSERT(cond)` (compile-out in release), `DEBUG_UNREACHABLE()`. |
| [`build_config.h`](../../kernel/util/build_config.h) | Compile-time feature gates (`DUETOS_KLOG_COMPILE_FLOOR`, etc.). |
| [`cache.h`](../../kernel/util/cache.h) | Cache-line size, alignment helpers, prefetch wrappers. |
| [`nospec.h`](../../kernel/util/nospec.h) | Speculation-barrier helpers (`ArrayIndexNospec` patterns). |

### Result and Error Handling

| File | Purpose |
|------|---------|
| [`result.h`](../../kernel/util/result.h) + [`result.cpp`](../../kernel/util/result.cpp) | The kernel's `Result<T, E>` type. The standard "success-or-error" carrier. |

The `Result<T, E>` type is the kernel's answer to "no exceptions, no
sentinels." Every fallible API returns `Result<T, ErrorCode>` and call
sites use `RESULT_TRY` / `RESULT_TRY_ASSIGN` to short-circuit:

```cpp
util::Result<u64> ParseHex(const char*);

auto MaybeProcess(const char* arg)
{
    u64 value;
    RESULT_TRY_ASSIGN(value, ParseHex(arg));  // returns Err on failure
    return process_value(value);
}
```

See [Coding Standards](../tooling/Coding-Standards.md) for the prefer-Result
rule (no `-1` / `nullptr` / `false` sentinels in new code).

### String, Unicode, Symbols

| File | Purpose |
|------|---------|
| [`string.h`](../../kernel/util/string.h) + `.cpp` | `StringLength`, `StringCat`, `StringEq`, `StringSplit`, format helpers. Kernel-safe — no syscalls. |
| [`unicode.h`](../../kernel/util/unicode.h) + `.cpp` | UTF-8 ↔ UTF-32 encode/decode, validation. Used by every path that touches PE paths, file paths, registry strings. |
| [`symbols.h`](../../kernel/util/symbols.h) / `symbols.cpp` / `symbols_stub.cpp` | Kernel symbol table lookup (`SymbolForAddress`, `AddressForSymbol`). Used by stack walkers, the inspect tool, GDB server. |
| [`datetime.h`](../../kernel/util/datetime.h) + `.cpp` | Gregorian ↔ Julian; ISO-8601 format/parse; broken-down time. Used by the clock app and log timestampers. |

### Compression and Image Codecs

| File | Purpose |
|------|---------|
| [`deflate.h`](../../kernel/util/deflate.h) + `.cpp` | Raw DEFLATE inflate (RFC 1951). The base of PNG IDAT and gzip. |
| [`gzip.h`](../../kernel/util/gzip.h) + `.cpp` | gzip + zlib container parsers wrapping DEFLATE. |
| [`png.h`](../../kernel/util/png.h) + `.cpp` | PNG decoder — palette + truecolour, 8/16-bit, alpha, interlace. Used by `imageview` + wallpaper loader. |
| [`jpeg.h`](../../kernel/util/jpeg.h) + `.cpp` | JPEG baseline decoder. |
| [`bmp.h`](../../kernel/util/bmp.h) + `.cpp` | BMP decoder + encoder (encoder used by `screenshot`). |
| [`tga.h`](../../kernel/util/tga.h) + `.cpp` | TGA decoder, for the small set of legacy assets that ship in TGA. |

All codecs decode into a caller-provided `Image{width, height, bpp,
pixels}` buffer. None of them allocate; if the caller's buffer is too
small the decoder returns `Err{ErrorCode::Overflow}`. Selection guide:

| Want | Use |
|------|-----|
| Decode any PNG / JPEG / BMP / TGA the user threw at us | `imageview` does the format detection wrapper |
| Encode a framebuffer snapshot | `Bmp` (the only format with an encoder) |
| Decompress a gzip blob (e.g. fonts) | `Gzip` |
| Decompress an in-memory PNG | `Png` (calls `Deflate` internally) |

### Hashes / Checksums

| File | Purpose |
|------|---------|
| [`crc32.h`](../../kernel/util/crc32.h) + `.cpp` | IEEE 802.3 CRC-32. Used by tripwire (region snapshot), PE checksums, the fix journal record hash. |
| [`adler32.h`](../../kernel/util/adler32.h) + `.cpp` | Adler-32 (RFC 1950). Used by zlib container verification. |
| [`base64.h`](../../kernel/util/base64.h) + `.cpp` | RFC 4648 base64 encode/decode. |

`util/crc32` is the only non-cryptographic checksum in the tree. For
cryptographic hashing, reach for [`kernel/crypto/`](Crypto.md) —
SHA-256, HMAC, BLAKE2b. The split is intentional: anyone reading the
import list of a crypto-sensitive call should not see `util/crc32`
unless the call is genuinely about integrity-without-authentication.

### Randomness

| File | Purpose |
|------|---------|
| [`random.h`](../../kernel/util/random.h) + `.cpp` | Kernel PRNG seeded from RDRAND, HPET reads, IRQ-timing jitter, and virtio-rng if present. Pool-backed; `RandomU32`/`U64` are spinlock-guarded. `RandomMix` accepts external entropy (e.g. virtio-rng output). |

`util/random` is the **only** PRNG in the tree. Subsystems that want
randomness pull from it; the security tree's nonce + salt generators
do as well. Replacing it requires a Roadmap entry — see
[Roadmap](../reference/Roadmap.md).

## What Doesn't Belong Here

If the helper:

- Allocates from the kernel heap → it goes in the subsystem that owns the
  allocation (e.g. handle tables go in `kernel/ipc/`).
- Touches a device → it goes in `kernel/drivers/`.
- Calls `KLOG` from its hot path → rewrite to return an error first, log
  at the call site that has context.
- Holds global state across boots → it goes in a subsystem with a
  persistence story, not in `util/`.

## Capability Gates

None. Every helper here is pure arithmetic / parsing / formatting. The
capability gates live at the subsystems that *use* the helpers (e.g.
the screenshot syscall is gated on `kCapFsWrite`, not on `Bmp::Encode`).

## Threading and Locking

| Helper | Thread-safety |
|--------|---------------|
| Numerics, asserts | Inline; thread-safe. |
| `Result<T, E>` | Value-type; thread-safety follows the contained types. |
| String, Unicode, format | Stateless; thread-safe. |
| Codecs (PNG / JPEG / BMP / TGA) | Stateless; reentrant. |
| `Crc32`, `Adler32`, `Base64` | Stateless. |
| `Datetime` | Stateless. |
| `Symbols` | RWLock-guarded — read fast path. |
| `Random` | Spinlock-guarded pool. |

## Known Limits / GAPs

- **No PNG encoder.** Decoder only; the `screenshot` app uses BMP for
  this reason.
- **No JPEG encoder.** Decoder only.
- **Datetime is integer-second only.** Sub-second precision lives in
  [`timekeeper`](Time.md), not here.
- **String formatting is not printf-compatible.** Use the kernel-native
  `Format()` helpers; printf-style strings are intentionally absent
  to keep the binary small.

## Related Pages

- [Coding Standards](../tooling/Coding-Standards.md) — `Result<T, E>`
  usage, naming
- [Crypto Primitives](Crypto.md) — when to pick crypto over `util` hashes
- [Diagnostics](Diagnostics.md) — every diagnostic surface consumes
  `Symbols`, `Datetime`, `Random`
- [Rust Subsystems](../tooling/Rust-Subsystems.md) — `img_meta_rust`
  crate (image metadata extraction)
