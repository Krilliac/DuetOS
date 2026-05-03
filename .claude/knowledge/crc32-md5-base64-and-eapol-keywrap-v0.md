# CRC32 hoist + MD5 + Base64 + EAPOL M3 AES-KW integration v0

_Type: Observation + Decision._
_Status: Active. All four slices pure compute or thin integration; KATs verified at boot + via host harness before pushing._
_Last updated: 2026-05-03._

## What landed

Four bounded slices that close out small porting-candidate rows
plus the natural follow-on from the AES + AES-KW landing
(see `aes-and-keywrap-v0.md`).

### 1. CRC32 hoist — `kernel/util/crc32.{h,cpp}`

The IEEE 802.3 reflected CRC-32 (poly 0xEDB88320, 0xFFFFFFFF
init + final XOR) used to live as a private `Crc32` inside
`kernel/fs/gpt.cpp`. It's now in `kernel/util/crc32.{h,cpp}` for
reuse by future PNG decoders, ZIP / gzip parsers, ext4 metadata
checksums (with seed = ~0), etc. `gpt.cpp` brings it in via
`using duetos::util::Crc32;` so its existing call sites stay
unchanged.

Boot KAT covers:
- `"123456789"` → `0xCBF43926` (universal CRC-32 reference).
- Empty input → 0.
- Single `0x00` byte → `0xD202EF8D`.
- Single `0xFF` byte → `0xFF000000`.

### 2. MD5 — `kernel/net/wireless/crypto/md5.{h,cpp}`

RFC 1321 implementation. Same context-update-final shape as the
existing SHA-1 / SHA-256 modules. Header carries an explicit
deprecation notice — MD5 is broken; v0 ships it for legacy
interop only (HMAC-MD5 for NTLMv1, legacy TLS_RSA_WITH_*_MD5
parser side, .iso MD5SUMS verification). New crypto code MUST
use SHA-256.

Boot KAT covers all 7 RFC 1321 Appendix A.5 vectors:
empty / `"a"` / `"abc"` / `"message digest"` / lowercase alphabet /
mixed-case alphanumeric / 80 digits.

### 3. Base64 — `kernel/util/base64.{h,cpp}`

RFC 4648 standard alphabet (`A-Z a-z 0-9 + /`) with `=` padding.
URL-safe alphabet (`-` and `_`) and the no-padding variant aren't
supported in v0; add when a consumer asks. Decode is strict — any
non-alphabet byte that isn't whitespace / `=` fails the call.
Whitespace (space, tab, `\r`, `\n`) is silently skipped to
tolerate MIME-style line breaks.

`Base64EncodedLen` and `Base64DecodedMaxLen` are constexpr so
callers can stack-allocate output buffers. `Base64Decode` returns
`bool` + writes the actual decoded length through a pointer arg
(false on bad input, undersized output, or truncation).

Boot KAT covers:
- All 7 RFC 4648 §10 vectors (`""` through `"foobar"`, exercising
  every padding configuration: 0 / 1 / 2 `=` characters).
- MIME-style whitespace tolerance (`"Zm9v\r\nYmFy"` → `"foobar"`).
- Bad-input rejection: non-alphabet character, truncated input,
  `=` before alphabet, output buffer too small.

### 4. EAPOL M3 AES-KW integration — `kernel/net/wireless/fourway.cpp`

Closes the natural follow-on from the AES + AES-KW slice: a real
802.11 AP wraps M3 KeyData with AES Key Wrap under the KEK
(upper half of the PTK). Before this slice the supplicant
detected `KeyInfo.Encrypted` and rejected with `Unsupported`,
keeping the PTK so unicast traffic worked but discarding the GTK.

`FourWayProcessIncoming` now:

1. If `KeyInfo.Encrypted` is set, validates `key_data_len ≥ 24`
   and `key_data_len % 8 == 0`.
2. Allocates a 256-byte stack-local `unwrapped[]` scratch (covers
   GTK + IGTK + 802.11i pad). Plaintext that doesn't fit is
   refused — kernel-stack budget over arbitrary M3 acceptance.
3. Expands the KEK (first 16 bytes of the PTK) into an `AesCtx`
   and calls `AesKeyUnwrap`. An integrity-check failure marks
   the context `Failed`, bumps `mic_failures`, and returns
   `Corrupt` — the same posture as a MIC mismatch, since either
   indicates an attacker-modified M3.
4. Walks the unwrapped buffer with the existing `ExtractGtkKde`
   for the GTK. The 802.11i pad (`0xDD 0x00 …`) is naturally
   skipped because the walker rejects KDE entries with `len < 6`.
5. Plain (non-Encrypted) M3 still works exactly as before — the
   unwrap branch only fires when the bit is set.

The `FourWaySelfTest` was extended with a second handshake whose
M3 ships an AES-KW-wrapped KeyData under the freshly-derived
KEK, asserting:
- AES-KW unwrap succeeds and the recovered GTK is byte-identical
  to the pre-wrap KDE bytes.
- A tampered ciphertext (one bit flipped in the wrapped IV)
  causes unwrap to fail, marks the context `Failed`, and
  increments `mic_failures` — the integrity guarantee is
  observable end-to-end.

## Why now

Three porting-candidates rows + one natural follow-on:

- `CRC32 hoist out of gpt.cpp` — ~50 LOC, broad cleanup. Marked
  LANDED in `porting-candidates-v0.md`.
- `MD5 (RFC 1321)` — ~100 LOC, legacy interop. Marked LANDED.
- `Base64 encode/decode (RFC 4648)` — ~100 LOC, generally useful
  (HTTP auth, MIME, Win32 `CryptStringToBinary`). Marked LANDED.
- AES-KW into EAPOL M3 — explicitly listed as the next bounded
  slice in `aes-and-keywrap-v0.md` "Follow-up not in this slice".

Together the four slices close the smallest open primitives in
the inventory and unblock the encrypted M3 path that the
wireless control tier had been calling out as
`Unsupported`-on-encounter.

## Wireless-control-tier impact

The Encrypted-bit M3 rejection note in
`wireless-control-tier-v0.md` is now stale — that path goes
through `AesKeyUnwrap` and either succeeds or reports an
integrity failure exactly the same shape as a MIC fail. The
remaining real-HW blockers for end-to-end Wi-Fi association are
DMA-coherent allocation (`mm::AllocDmaCoherent`) and per-vendor
MSI/MSI-X IRQ wiring; both are HW-gated, not software-gated.

## Verification

- **Boot self-tests**: KAT vectors from each module's reference
  spec. Mismatch panics with the offending vector name.
- **Host check**: `/tmp/md5_base64_check.cpp` standalone harness
  compiles all three util / crypto TUs (CRC32 + MD5 + Base64)
  against a panic.h shim and runs every KAT before commit. The
  AES + AES-KW host harness from the previous slice still
  passes.
- **Build flavors**: `x86_64-release` and `x86_64-debug-fast`
  both build clean with zero warnings.
- The fourway ciphered-M3 KAT runs at boot; tamper detection
  asserts that flipping a bit in the wrapped IV causes
  `AesKeyUnwrap` to return false and the supplicant to mark
  state Failed with `mic_failures` bumped.

## Files

- `kernel/util/crc32.{h,cpp}` — hoisted module (~80 LOC).
- `kernel/util/base64.{h,cpp}` — encode + decode + 12-case KAT
  (~280 LOC).
- `kernel/net/wireless/crypto/md5.{h,cpp}` — MD5 + 7-case KAT
  (~225 LOC).
- `kernel/net/wireless/fourway.cpp` — M3 unwrap branch + ciphered
  KAT (~80 LOC delta).
- `kernel/fs/gpt.cpp` — local Crc32 deleted, `using` import
  added.
- `kernel/core/main.cpp` — three new `DUETOS_BOOT_SELFTEST`
  lines + three new `#include`s.

Total: ~720 LOC across five new files plus light edits to two
existing TUs.
