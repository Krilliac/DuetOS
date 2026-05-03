# Kernel pure-compute utility libraries v0

_Type: Observation + Decision._
_Status: Active — 13 clean-room TUs in `kernel/util/`,
`kernel/crypto/`, and `kernel/drivers/gpu/` after the
2026-05-03 prune of unconsumed surfaces._
_Last updated: 2026-05-03 (post-prune)._

## Why this entry

The 2026-05-03 morning + afternoon + evening batches landed
24 clean-room TUs across `kernel/util/`, `kernel/crypto/`, and
`kernel/drivers/gpu/`. Then, per the user's directive ("fully
implement anything the OS legitimately needs, otherwise trash
it"), 14 of them were deleted in commit `1a236aa` because they
had no live consumer in tree and no realistic path to one in
the project's near-term scope (no TLS, no NTLM, no audio
backend, no initramfs, no Linux strftime thunks, no pre-CVT
CRT in the test fleet, etc.).

What remains is the set that EITHER drives a live caller in
tree today OR sits one slice away from one. Each row below
names that consumer.

## Inventory

| Library | Header / TU | Spec | Consumer in tree |
|---------|-------------|------|------------------|
| Unicode UTF-8 / UTF-16 | `kernel/util/unicode.{h,cpp}` | RFC 3629 + Unicode 15.0 §3.9 | `kernel/fs/exfat.cpp` + `kernel/fs/ntfs.cpp` filename decode |
| TGA 2.0 decoder + 32-bpp encoder | `kernel/util/tga.{h,cpp}` | Truevision TGA 2.0 | ImageView dispatch on `.TGA` (decoder); Ctrl+Alt+T screenshot path (encoder) |
| Gregorian↔Julian + ISO 8601 + Unix-epoch | `kernel/util/datetime.{h,cpp}` | Fliegel & Van Flandern (1968) + ISO 8601:2019 | klog wall-clock prefix (`SetLogWallClock`); Calendar app week-of-year title |
| BMP encoder + parser (32-bpp BI_RGB) | `kernel/util/bmp.{h,cpp}` | Microsoft BITMAPINFOHEADER | Screenshot writer + ImageView decoder |
| CRC32 (IEEE 802.3 reflected) | `kernel/util/crc32.{h,cpp}` | IEEE 802.3 | GPT header + entries CRC; PNG chunk CRC |
| Adler-32 | `kernel/util/adler32.{h,cpp}` | RFC 1950 §9 | zlib stream tail (validated when PNG IDAT inflates) |
| Base64 encode/decode | `kernel/util/base64.{h,cpp}` | RFC 4648 | (existing tree consumer; pre-2026-05-03) |
| DEFLATE inflater | `kernel/util/deflate.{h,cpp}` | RFC 1951 | zlib wrapper → PNG IDAT |
| GZIP + zlib stream wrappers | `kernel/util/gzip.{h,cpp}` | RFC 1952 + RFC 1950 | PNG IDAT decompression (`ZlibInflate`) |
| PNG decoder (8-bit RGB/RGBA) | `kernel/util/png.{h,cpp}` | RFC 2083 / W3C PNG 2nd Ed. | ImageView dispatch on `.PNG` |
| AES + AES Key Wrap | `kernel/crypto/aes.{h,cpp}` + `aes_keywrap.{h,cpp}` | FIPS 197 + RFC 3394 | Wireless 4-way handshake KEK / GTK unwrap |
| HMAC-SHA1 + HMAC-SHA256 | `kernel/crypto/hmac.{h,cpp}` | RFC 2104 | Wireless PBKDF2 / PRF (HMAC-SHA1); password hashing (HMAC-SHA256) |
| SHA-1, SHA-256, PBKDF2, PRF | `kernel/crypto/{sha1,sha256,pbkdf2,prf}.{h,cpp}` | FIPS 180-4 / RFC 7914 / 802.11 PRF-X | Wireless 4-way handshake; password hashing |
| DPMS state machine | `kernel/drivers/gpu/dpms.{h,cpp}` | VESA DPMS + X.Org DPMS | Settings shutdown/reboot transitions |
| EDID + CVT + CEA-861 (existing) | `kernel/drivers/gpu/{edid,cvt,cea861}.{h,cpp}` | VESA E-EDID + CVT 1.1/1.2 + CEA-861-E/F | mode-set when GPU drivers want to program a panel |

## Conventions every TU follows

1. **No allocation, no global state.** Every routine takes
   caller-provided buffers and returns a length or a Result-like
   bool. The kernel callers can drop these into IRQ-safe contexts
   without worrying about heap pressure.

2. **Reject-by-default for v0.** When the spec admits a feature
   (e.g. PNG palette colour-type, BMP RLE, TGA RLE) that no
   consumer needs, the parser surfaces the rejection cleanly via
   `info.ok = false` rather than half-implementing it.

3. **Named consumer or it doesn't ship.** A library lives in
   tree only if a caller exists today or will exist in the same
   slice that introduces it. The 2026-05-03 prune removed every
   library that violated this rule.

4. **One KAT entry covers structural negatives, not every field
   permutation.** Self-tests assert the contract, not the spec's
   full universe.

## Wiring summary

- `kernel/core/main.cpp` — `DUETOS_BOOT_SELFTEST` invocations
  for every `*SelfTest` symbol in the inventory (in declaration
  order).
- `kernel/fs/exfat.cpp`, `kernel/fs/ntfs.cpp` — share
  `duetos::util::Utf16CpToSafeAscii`. The two file systems
  use the same surrogate-pair-aware fold path.
- `kernel/apps/screenshot.cpp` — `BmpWriteHeader32` for
  `Ctrl+Alt+P`, `TgaWriteHeader32` for `Ctrl+Alt+T`.
- `kernel/apps/imageview.cpp` — `BmpParseHeader` (BMP path),
  `TgaParseHeader` + `TgaDecodeUncompressed` (TGA path),
  `PngParseHeader` + `PngDecode` (PNG path). Each format gets
  its own `Decode<Fmt>` helper inside ImageView.
- `kernel/log/klog.cpp` — `WallClockInit` samples the RTC at
  boot; live-emit prefix uses `DateTimeFromUnixSecs` +
  `FormatIso8601` when `SetLogWallClock(true)`.
- `kernel/apps/calendar.cpp` — `IsoYearWeek` for the
  `MAY 2026 - Wk 18`-style title.
- `kernel/apps/settings.cpp` — `DpmsSetState(Off)` before
  `AcpiShutdown` / `KernelReboot`.
- `kernel/security/password_hash.cpp` — `HmacSha256` +
  `Pbkdf2HmacSha256` underpin every account password verify.
- `kernel/net/wireless/*` — `HmacSha1` + `Pbkdf2HmacSha1` +
  `Sha1Hash` + `AesKeyWrapUnwrap` underpin the WPA2-Personal
  4-way handshake.

## Out of scope (deliberate, deleted on 2026-05-03)

The following 14 TUs were deleted because they had no live
consumer in tree:

- `kernel/crypto/chacha20poly1305` (TLS 1.3 ciphersuite — TLS not in tree)
- `kernel/crypto/aes_gcm` (TLS, WPA3-GCMP — neither wired)
- `kernel/crypto/aes_ccm` (WPA2-CCMP TX/RX — unwired, HW-untested)
- `kernel/crypto/sha512` (TLS SHA-384 transcript)
- `kernel/crypto/md5` (only valid consumer was HMAC-MD5)
- `crypto/hmac::HmacMd5 / HmacSha384 / HmacSha512` (no caller)
- `kernel/util/posix_tz` + `kernel/util/tzif` (Linux strftime thunks not in tree)
- `kernel/util/wav` (no audio backend)
- `kernel/util/cpio` (no initramfs)
- `kernel/util/tar` (no install-seed model)
- `kernel/util/lz4` (no compressed assets)
- `kernel/util/psf` (no `setfont` userland app)
- `kernel/drivers/gpu/gtf` (CVT covers every panel in scope; no pre-CVT CRT)

If a future slice creates a real consumer, the deleted TU can
be re-introduced from git history alongside its first caller in
the same commit. Don't pre-pay the implementation cost of
speculation.

## See also

- `porting-candidates-v0.md` — the LANDED row table + the
  remaining open work the OS legitimately needs (currently
  GPT write, FAT32 mkfs, AHCI write, virtio-blk).
- `imageview-bmp-v0.md` — the kernel app that consumes BMP +
  TGA + PNG.

## Resume prompt

> Read `kernel-util-libraries-v0.md`. The 13 TUs listed here
> all have live in-tree consumers. The "Out of scope" list at
> the bottom is what was deleted on 2026-05-03 and should NOT
> be re-introduced without a named first caller in the same
> commit.
