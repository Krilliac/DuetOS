# Kernel pure-compute utility libraries v0

_Type: Observation + Decision._
_Status: Active — 17 clean-room TUs landed across two same-day
batches in `kernel/util/`, `kernel/crypto/`, and `kernel/drivers/gpu/`._
_Last updated: 2026-05-03 (afternoon batch)._

## Why this entry

Six bounded clean-room slices landed on
`claude/cleanup-stale-documents-2lhGO` in one batch, each
implementing a public spec, each gated by a boot KAT, and each
small enough to be a single TU. The aggregate is too granular to
deserve one knowledge file per library, so they live here as
one cross-referenced inventory. Each library appears as a LANDED
row in `porting-candidates-v0.md`.

The pattern is identical to the AES / AES-KW / Base64 / MD5 /
CRC32 batch that landed earlier on 2026-05-03 and was captured
in `crc32-md5-base64-and-eapol-keywrap-v0.md`: pure compute,
KAT-verified at boot, no allocation, no global state, callers
arrive in follow-up slices.

## Inventory

### Morning batch (six TUs)

| Library | Header / TU | Spec | KAT count | Eventual consumer |
|---------|-------------|------|-----------|-------------------|
| HMAC-MD5 | `kernel/crypto/hmac.{h,cpp}` (extended) | RFC 2104 + RFC 1321 | 3 (RFC 2202 vectors 1, 2, 6) | NTLMv1 / HTTP Digest auth |
| Unicode UTF-8 / UTF-16 | `kernel/util/unicode.{h,cpp}` | RFC 3629 + Unicode 15.0 §3.9 | 14 (encode + decode round-trips for all length classes; 5 negative UTF-8; 3 negative UTF-16; UTF-16LE buffer smoke) | exfat / ntfs filename decode (active); future Win32 wide-string thunks |
| TGA 2.0 decoder | `kernel/util/tga.{h,cpp}` | Truevision TGA 2.0 | 7 (32-bpp + 24-bpp round-trips, 5 negative cases) | ImageView (active) |
| Gregorian ↔ Julian + ISO 8601 | `kernel/util/datetime.{h,cpp}` | Fliegel & Van Flandern (1968) + ISO 8601:2019 | 17 (4 JDN refs, 3 round-trips, 4 DOW, 3 ISO-week incl. 2020/53 boundary, format+parse round-trip, 3 tolerance forms, 5 rejections) | calendar week-of-year display, klog wall-clock timestamps, Linux ABI strftime/strptime |
| BMP encoder + parser | `kernel/util/bmp.{h,cpp}` | Microsoft BITMAPINFOHEADER | 5 (top-down + bottom-up round-trips, bad-sig / DIB<40 / oversize rejections) | screenshot writer (active), ImageView decoder (active) |
| CPIO newc walker | `kernel/util/cpio.{h,cpp}` | POSIX.1-1988 SVR4 portable (070701/070702) | 5 (2-entry happy path, bad magic, truncated header, missing trailer, visitor early-stop) | future initramfs unpacker |

### Afternoon batch (eleven slices, including the KPTI close-out)

| Library | Header / TU | Spec | KAT count | Eventual consumer |
|---------|-------------|------|-----------|-------------------|
| KPTI close-out (loud-WARN on `RDCL_NO=0`) | `kernel/arch/x86_64/cpu_mitigations.cpp` (extended) | n/a | n/a (settled decision) | n/a — full KPTI deliberately not built; see `kpti-meltdown-decision-v0.md` |
| ChaCha20 + Poly1305 + AEAD | `kernel/crypto/chacha20poly1305.{h,cpp}` | RFC 8439 §2.3 / §2.5 / §2.8 | 3 RFC 8439 reference vectors (§2.4.2 keystream, §2.5.2 MAC, §2.8.2 AEAD with tag + ciphertext + decrypt round-trip + 2 tamper-rejects) | TLS 1.3 `TLS_CHACHA20_POLY1305_SHA256` |
| AES-GCM (128/256) | `kernel/crypto/aes_gcm.{h,cpp}` | NIST SP 800-38D | 4 NIST 800-38D test cases (1, 2, 3, 13) including ciphertext + tag + decrypt + tamper | 802.11 GCMP (WPA3), TLS 1.2/1.3 AES-GCM, sealed storage |
| POSIX TZ string parser | `kernel/util/posix_tz.{h,cpp}` | POSIX.1-2008 §8.3 | 6 happy-path forms + 9 negative cases | Linux ABI strftime/strptime/mktime/localtime |
| WAV (RIFF) parser/writer | `kernel/util/wav.{h,cpp}` | Microsoft WAVE / RIFF | 3 round-trips + tolerant LIST-skip + 5 negatives | future sound-effect player (HDA / AC'97) |
| TAR ustar walker | `kernel/util/tar.{h,cpp}` | POSIX.1-2001 ustar | happy 2-entry + 4 negatives | distribution tarball extraction |
| LZ4 raw-block decoder | `kernel/util/lz4.{h,cpp}` | LZ4 spec | 3 happy paths (literals, overlap match, length extension) + 4 negatives | future kernel-image self-decompression, .lz4-compressed archives |
| GTF timing generator | `kernel/drivers/gpu/gtf.{h,cpp}` | VESA GTF 1.1 | 2 well-known modes (640×480@60, 1024×768@70) + 3 negatives | mode-set fall-back for legacy monitors that pre-date CVT |
| DPMS state machine | `kernel/drivers/gpu/dpms.{h,cpp}` | VESA DPMS + X.Org DPMS | full state-machine walk including hook veto + bookkeeper-only mode | screensaver, power-policy / lid-switch, Win32 SetMonitorPowerSetting |
| PSF1 / PSF2 font parser | `kernel/util/psf.{h,cpp}` | Linux PSF v1 + v2 | PSF1-256, PSF1-512+unicode, PSF2-100, 3 negatives | future `setfont`-style userland app |
| TGA 32-bpp encoder | `kernel/util/tga.{h,cpp}` (extended) | Truevision TGA 2.0 | encode-then-decode 2×2 mosaic round-trip + out-cap negative | ImageView (decoder side already wired); screenshot extension |

## Conventions every TU follows

1. **No allocation, no global state.** Every routine takes
   caller-provided buffers and returns a length or a Result-like
   bool. The kernel callers can drop these into IRQ-safe contexts
   without worrying about heap pressure.

2. **Reject-by-default for v0.** When the spec admits a feature
   (e.g. TGA RLE, CPIO old-binary, BMP RLE) that we don't need
   yet, the parser surfaces the rejection cleanly via `info.ok =
   false` rather than half-implementing it. Future slices light
   up the rejected path explicitly.

3. **Boot KAT is the live caller.** A library can land before
   any production caller exists as long as the KAT exercises
   every code path. Examples: HMAC-MD5 (NTLM not landed),
   datetime (logging hasn't switched to ISO 8601 yet), CPIO
   (initramfs unpacker not landed). This is the same pattern AES
   and AES-KW used earlier.

4. **One KAT entry covers structural negatives, not every
   field permutation.** Self-tests assert the contract, not the
   spec's full universe. If a future bug surfaces, add a vector
   to the existing self-test, don't write a new one.

## Wiring

- `kernel/core/main.cpp` — `DUETOS_BOOT_SELFTEST` invocations
  for `UnicodeSelfTest`, `BmpSelfTest`, `TgaSelfTest`,
  `DateTimeSelfTest`, `CpioSelfTest` (slot order matches
  declaration in this file). HMAC-MD5 vectors are inside the
  existing `HmacSelfTest`.
- `kernel/fs/exfat.cpp` and `kernel/fs/ntfs.cpp` — the per-TU
  `Utf16ToSafeAscii` helpers were collapsed onto
  `duetos::util::Utf16CpToSafeAscii`. The two file systems
  share the same code path now, with surrogate-pair-aware
  collapsing (which the BMP-only ad-hoc helpers couldn't do).
- `kernel/apps/screenshot.cpp` — `WriteBmpHeader` is gone;
  callers go through `duetos::util::BmpWriteHeader32(out, w, h,
  top_down=true)`. The DIB-height sign flip is now an explicit
  flag, no longer hard-coded inside the encoder.
- `kernel/apps/imageview.cpp` — local `BmpInfo` + `ParseBmpHeader`
  replaced by `using duetos::util::BmpInfo` + a one-line inline
  shim over `BmpParseHeader`. Existing decode paths and the
  4×4 self-test compile unchanged. Also gains a TGA dispatch
  branch via `kernel/util/tga` for any `.TGA` file in the FAT32
  root (full-file-load capped at 4 MiB, NN-downsample into the
  thumbnail).

## Out of scope (deliberate, future slices)

- TGA RLE (image type 10), colormapped (1), grayscale (3), 16
  bpp. Parser rejects all of them.
- BMP 24-bpp / 16-bpp / palette / RLE. ImageView's parser
  flags these and the status line shows the reason. Encoder
  is 32-bpp BI_RGB only.
- CPIO old-binary (070707) and old-ASCII variants. Parser
  rejects them.
- Unicode normalization (NFC / NFD), case folding,
  bidirectional algorithm, Unicode 15 case-folding tables —
  each its own porting-candidates row.
- ISO 8601 time-zone offsets (+HH:MM). Parser rejects.
  Separate row: POSIX TZ string parser.

## See also

- `porting-candidates-v0.md` — landed-row table; this entry is
  the long-form companion.
- `crc32-md5-base64-and-eapol-keywrap-v0.md` — the earlier
  same-day batch (CRC32 hoist, MD5, Base64, EAPOL keywrap).
- `aes-and-keywrap-v0.md` — same-day AES + AES-KW batch.
- `imageview-bmp-v0.md` — the kernel app that consumes both
  `kernel/util/bmp` and `kernel/util/tga`.

## Resume prompt

> Read `.claude/knowledge/kernel-util-libraries-v0.md`. Six
> clean-room utility TUs landed: HMAC-MD5, Unicode UTF-8/UTF-16,
> TGA decoder, datetime (Gregorian↔JDN + ISO 8601), BMP encoder
> + parser, CPIO newc walker. Each has a boot KAT. Pick a
> follow-up consumer to wire in next: NTLMv1 thunk for HMAC-MD5;
> Win32 wide-string conversion for Unicode; klog ISO 8601
> timestamps for datetime; initramfs unpacker for CPIO.
