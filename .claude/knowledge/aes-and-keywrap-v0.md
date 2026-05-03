# AES-128/256 + AES Key Wrap (RFC 3394) v0

_Type: Observation + Decision._
_Status: Active. Pure compute, KAT-verified at boot._
_Last updated: 2026-05-03._

## What landed

Two coupled crypto primitives in `kernel/crypto/`:

- **`aes.{h,cpp}`** — AES-128 + AES-256 block cipher per FIPS 197.
  - `AesCtx` holds up to 240 bytes of round keys plus `num_rounds`
    (10 for AES-128, 14 for AES-256). Caller-owned, zero allocation.
  - `AesKeyExpand128` / `AesKeyExpand256` produce the round-key
    schedule via the standard `RotWord + SubWord + Rcon` recurrence.
    AES-256 hits the extra `SubWord`-only branch every 8 words at
    `i % Nk == 4`, exactly as FIPS 197 §5.2 specifies.
  - `AesEncryptBlock` / `AesDecryptBlock` implement the round loop
    over the 16-byte state with `SubBytes + ShiftRows + MixColumns
    + AddRoundKey` (and inverses). Plain table-driven, no T-tables;
    ~12x smaller in `.rodata` than a T-table form, slower but well
    inside the budget for the v0 caller (Wi-Fi key unwrap on
    association is not a per-frame operation).
  - `AesSelfTest` verifies three FIPS 197 vectors at boot:
    - Appendix B (AES-128 worked example: key `2B7E…`, plaintext
      `3243F6A8…`, cipher `3925841D…`).
    - Appendix C.1 (AES-128 with key `00..0F`, plaintext `00..FF`).
    - Appendix C.3 (AES-256 with key `00..1F`, plaintext `00..FF`).
    Every vector exercises encrypt + decrypt round-trip.

- **`aes_keywrap.{h,cpp}`** — AES Key Wrap per RFC 3394.
  - `AesKeyWrap` / `AesKeyUnwrap` operate on 8-byte semi-blocks
    using a caller-supplied (pre-expanded) `AesCtx`. Both AES-128
    and AES-256 KEKs are accepted (the inner block primitive picks
    the round count from `ctx.num_rounds`).
  - The construction is the standard 6-pass loop with
    `t = n*j + i` index-XOR bookkeeping. Output buffer doubles as
    scratch storage so the algorithm runs in-place against the
    caller's buffer with no extra heap or large stack allocation.
  - Cap of 64 semi-blocks (512 bytes plaintext / 520 bytes
    ciphertext) covers every 802.11 EAPOL-KeyData payload (GTK +
    optional IGTK + padding never exceeds a few hundred bytes).
    Bump if a future caller needs more.
  - `AesKeyWrapSelfTest` verifies four cases at boot:
    - RFC 3394 §4.1 — 128-bit KEK, 16-byte plaintext (n=2).
    - RFC 3394 §4.3 — 256-bit KEK, 16-byte plaintext (n=2).
    - RFC 3394 §4.6 — 256-bit KEK, 32-byte plaintext (n=4 — exercises
      the inner loop more heavily).
    - **Tamper detection**: flipping the high byte of the wrapped
      IV must cause unwrap to return false. This is the property
      that buys 802.11 its integrity guarantee — without it an
      attacker who swaps in a forged GTK would be silently
      accepted.
    - **Bad-input rejection**: zero length, non-multiple-of-8,
      single semi-block (n=1, RFC 3394 requires n ≥ 2), and a
      ciphertext smaller than 24 bytes are all rejected.

Self-tests gated by `DUETOS_BOOT_SELFTESTS`. Wired from
`core/main.cpp` immediately after the existing
`PrfSelfTest()` line (so AES sits beside its sibling 802.11i
primitives in the boot self-test order).

## Why now

The `feature-gaps-end-user-v0.md` landscape calls out P0 #4
"Wi-Fi connect-to-SSID" as PARTIAL — every component lands but the
encrypted GTK delivery in EAPOL M3 is gated on AES Key Wrap, and
that depended on AES not being in the tree. The
`wireless-control-tier-v0.md` notes that "AES key wrap (RFC 3394)
for encrypted M3 key data" is one of two real-HW blockers
(alongside DMA-coherent allocation and per-vendor MSI/MSI-X IRQ
wiring). This slice closes the AES Key Wrap half of that blocker.

It also closes the `porting-candidates-v0.md` rows:

- `AES-128/256 block cipher` (FIPS 197).
- `AES key wrap (RFC 3394)`.

## Design notes

- **No AES-192**: nothing in the tree wants it. WPA2 / WPA3 cipher
  suites use AES-128 (CCMP-128, GCMP-128) and AES-256 (CCMP-256,
  GCMP-256); TLS suites that take 192-bit keys are extremely rare
  and not on our roadmap. Adding it later is a four-line change
  in `AesKeyExpand` plus a `kAes192*` constant block.
- **No AES-NI hardware path** in v0. The CPUID bit (`AESNI`) is
  already probed by `arch::CpuMitigationsGet` so a future slice
  can gate hardware acceleration; the software path stays as the
  fallback for non-AES-NI silicon and for KAT verification.
- **Side-channel posture**: the table-driven implementation is
  vulnerable to cache-timing leaks (same as Linux's reference
  software AES). For the WPA2 4-way handshake this is fine — the
  KEK is generated fresh per association and the attack surface
  is small. When a TLS data-plane consumer lands the AES-NI path
  becomes mandatory; record this as a follow-up.
- **In-place safety**: both `AesEncryptBlock` and `AesDecryptBlock`
  copy input into a 16-byte scratch state before producing output,
  so `out == in` is supported. `AesKeyWrap` / `AesKeyUnwrap`
  document the in-place semantics: output buffer is also scratch.
- **Stack budget**: keywrap allocates two 16-byte AES-block scratch
  buffers (`block_in` / `block_out`) plus a few 64-bit accumulators.
  No recursion. No VLAs. ~64 bytes of stack worst case — well
  under the kernel-stack budget.

## Verification

- **Boot self-test**: KAT vectors from FIPS 197 Appendix B/C and
  RFC 3394 §4.1/§4.3/§4.6. Mismatch panics with the offending
  vector name in the message string.
- **Host check**: a standalone host harness at `/tmp/` (compiles
  the kernel TUs directly via include-path shim) confirmed the
  KAT vectors all match before the kernel build was performed.
  The kernel-side tests reproduce the same property at boot.
- **Build flavors**: `x86_64-release` and `x86_64-debug-fast` both
  build clean with zero warnings.

## Follow-up not in this slice

1. **Wire keywrap into the EAPOL M3 KeyData decryption path** —
   LANDED 2026-05-03. See
   `crc32-md5-base64-and-eapol-keywrap-v0.md`. `FourWayProcessIncoming`
   detects `KeyInfo.Encrypted`, derives KEK = upper 16 bytes of
   PTK, runs `AesKeyUnwrap` against a 256-byte stack scratch,
   walks the decrypted KDEs through the existing `ExtractGtkKde`,
   and treats integrity failure as a MIC-equivalent fault
   (state→Failed + mic_failures++). Ciphered-M3 + tamper-detect
   KAT runs at boot.
2. **AES-NI hardware path**. CPUID-gated. Replace the namespace-
   private implementations of `AesEncryptBlock` / `AesDecryptBlock`
   with dispatch by feature bit at `AesKeyExpand*` time. The KAT
   self-test runs both paths; behaviour must be byte-identical.
3. **AES-CCM / AES-GCM** for actual frame encryption. A separate
   slice — keywrap is the lighter prerequisite that unblocks key
   delivery; per-frame encryption is mandatory for the data plane
   and opens its own design space (replay window, nonce
   management, Aad construction).

## Files

- `kernel/crypto/aes.h` — public surface (~65 LOC).
- `kernel/crypto/aes.cpp` — block + KAT (~330 LOC).
- `kernel/crypto/aes_keywrap.h` — public surface (~55 LOC).
- `kernel/crypto/aes_keywrap.cpp` — wrap/unwrap + KAT (~225 LOC).
- `kernel/core/main.cpp` — added two `DUETOS_BOOT_SELFTEST` lines + two `#include`s.

Total: ~675 LOC across four new files plus a tiny edit to main.cpp.
