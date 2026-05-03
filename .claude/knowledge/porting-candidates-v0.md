# Porting / re-creation candidates v0

_Type: Plan + Observation._
_Status: Active — pruned 2026-05-03 to "what the OS legitimately
needs." Speculative rows removed; deletion rationale per
`Out of scope` below._
_Last updated: 2026-05-03 (post-prune)._

This file used to enumerate ~80 clean-room porting candidates by
category. Most were speculative — they had no consumer in tree
and no realistic path to one in the project's near-term scope.
The current pillars (run PE binaries on commodity x86_64,
boot from FAT32, run typical desktop apps) are well served by
the kernel as it stands; what remains here is the small set of
slices that genuinely move that scope forward.

When you land one, mark its row "LANDED YYYY-MM-DD → <commit>".

## Resume prompt

> Read `.claude/knowledge/porting-candidates-v0.md`. Either pick
> a row from `Open work` (each has a named in-tree consumer),
> add a row whose consumer you can name, or stop. The
> `Out of scope` list below is *not* a TODO — those rows were
> deliberately pruned because the project does not need them.
> If your task makes one of them suddenly needed, raise it as a
> new entry with the consumer named.

## Status — landed slices that survive the prune

| Date | Row | Knowledge file |
|------|-----|----------------|
| 2026-05-01 | EDID 1.3/1.4 base-block parser | `edid-parser-v0.md` |
| 2026-05-01 | CVT 1.1 / 1.2 RBv1 timing generator | `cvt-cea861-v0.md` |
| 2026-05-01 | CEA-861 EDID extension parser (HDMI VSDB / video / audio / HDR) | `cvt-cea861-v0.md` |
| 2026-05-03 | AES-128 / AES-256 block cipher (FIPS 197) | `aes-and-keywrap-v0.md` |
| 2026-05-03 | AES Key Wrap (RFC 3394) | `aes-and-keywrap-v0.md` |
| 2026-05-03 | CRC32 hoist out of `gpt.cpp` (IEEE 802.3 reflected) | `crc32-md5-base64-and-eapol-keywrap-v0.md` |
| 2026-05-03 | Base64 encode/decode (RFC 4648) | `crc32-md5-base64-and-eapol-keywrap-v0.md` |
| 2026-05-03 | Unicode UTF-8 / UTF-16 codepoint conversions (RFC 3629 + Unicode 15) | `kernel-util-libraries-v0.md` (collapses exfat+ntfs ad-hoc helpers) |
| 2026-05-03 | TGA 2.0 uncompressed 24/32-bpp decoder + 32-bpp encoder | `kernel-util-libraries-v0.md` (ImageView + Ctrl+Alt+T screenshot) |
| 2026-05-03 | Gregorian↔Julian-Day + ISO 8601 + Unix-epoch helpers | `kernel-util-libraries-v0.md` (klog wall-clock prefix + Calendar week display) |
| 2026-05-03 | BMP encoder + parser util TU (32-bpp BI_RGB) | `kernel-util-libraries-v0.md` (screenshot writer + ImageView decoder) |
| 2026-05-03 | DPMS state machine + driver-hook surface | `kernel-util-libraries-v0.md` (Settings shutdown/reboot transitions) |
| 2026-05-03 | Adler-32 (RFC 1950 §9) | `kernel-util-libraries-v0.md` (zlib stream tail validation) |
| 2026-05-03 | DEFLATE inflater (RFC 1951) | `kernel-util-libraries-v0.md` (PNG IDAT decompression) |
| 2026-05-03 | GZIP container + zlib stream wrapper (RFC 1952 + RFC 1950) | `kernel-util-libraries-v0.md` (PNG IDAT decompression) |
| 2026-05-03 | PNG decoder (RFC 2083, 8-bit RGB/RGBA) | `kernel-util-libraries-v0.md` (ImageView dispatch on `.PNG`) |

## Status — deleted slices (originally landed, then pruned 2026-05-03)

The following 14 TUs landed earlier on 2026-05-03 but were
removed in commit `1a236aa` because they had no live consumer
in the tree and no realistic path to one in the project's
near-term scope. Recoverable from git history if a future slice
needs them.

| TU | Spec | Why deleted |
|----|------|-------------|
| HMAC-MD5 (RFC 2104+1321) | RFC 2202 | No NTLMv1, no HTTP Digest in tree |
| MD5 (RFC 1321) | FIPS-deprecated | Only consumer was HMAC-MD5 |
| SHA-384 / SHA-512 (FIPS 180-4) | FIPS 180-4 | TLS not in tree; no consumer |
| HMAC-SHA384 / HMAC-SHA512 | RFC 4231 | Same — built on SHA-512 |
| AES-GCM (NIST SP 800-38D) | NIST SP 800-38D | TLS not in tree, WPA3-GCMP TX/RX unwired |
| AES-CCM (NIST SP 800-38C) | NIST SP 800-38C | WPA2-CCMP data-frame TX/RX unwired (HW-untested anyway) |
| ChaCha20 + Poly1305 + AEAD | RFC 8439 | TLS 1.3 not in tree |
| POSIX TZ string parser | POSIX.1-2008 §8.3 | Linux strftime thunk not in tree |
| TZif binary timezone parser | RFC 8536 | Same |
| WAV / RIFF parser+writer | Microsoft WAVEFORMATEX | No audio backend in tree |
| CPIO newc walker | POSIX.1-1988 SVR4 | No initramfs in tree |
| TAR ustar walker | POSIX.1-2001 | No tar-based install seed |
| LZ4 raw-block decoder | LZ4 spec | No lz4 assets in tree |
| PSF1 / PSF2 font parser | Linux PSF v1+v2 | No `setfont` userland app |
| GTF (VESA Generalized Timing Formula 1.1) | VESA GTF 1.1 | CVT covers every panel in scope; no pre-CVT CRT in fleet |

## Open work — slices the OS legitimately needs

Each row below names an explicit in-tree consumer that exists
*today* and is gated on this slice landing.

| Slice | Spec | Consumer in tree | Est. LOC |
|-------|------|------------------|----------|
| **GPT partition write surface** | UEFI GPT | `disk-installer-plan.md` (P2 #16) — no installer can land without `GptInitDisk` / `GptWritePartition` | ~400 |
| **FAT32 mkfs / format** | Microsoft FAT spec | Same — needs to lay down BPB / FAT region / root cluster on a blank partition | ~300 |
| **AHCI write path** | AHCI 1.3 + SATA | The existing AHCI read driver in tree; FAT32 writes would route through AHCI on real SATA media | ~300 |
| **virtio-blk + virtio-rng** | virtio 1.2 | QEMU testing throughput — current dev path is NVMe-in-QEMU, virtio-blk would let us test the storage stack against a second backend | ~400 |

Anything else that wants to land needs a **named in-tree
consumer**. "Future TLS will need this" is not a consumer; if a
TLS slice is approved, the matching crypto primitives can be
re-introduced as part of *that* slice with their first caller
in the same commit.

## Out of scope — deliberately not tracked

The following categories were enumerated in earlier revisions
of this file and have been pruned. They are out of scope until
the project's pillars expand:

- **Display / GPU beyond the EDID + CVT + DPMS already landed**:
  DisplayID, CTA-861-G, DDC/I²C transport, DisplayPort AUX. All
  gated on a per-vendor GPU driver that doesn't exist.
- **Audio**: AC'97, HDA, WAV, Vorbis, OGG, FLAC, MP3. Gated on
  the audio backend, which isn't in tree.
- **Filesystems beyond the read-only tier already landed**:
  ISO 9660 / UDF / F2FS / Btrfs / 9P / virtio-fs / NFSv3 / SMBv2.
  Gated on a per-FS workload that doesn't exist.
- **Crypto beyond AES + AES-KW + SHA-1 + SHA-256 + HMAC-SHA1/256
  + PBKDF2-SHA1/256**: Curve25519 / Ed25519 / TLS 1.2 / TLS 1.3 /
  DoH / HTTP/2 / WebSocket / mDNS / SSDP / DHCPv6 / SLAAC /
  ICMPv6 NDP / IPv6 stack / EAP-PEAP / EAP-TTLS / WPA3-SAE.
  Each is gated on a higher-level subsystem (TLS client, IPv6
  stack, enterprise Wi-Fi) that isn't in scope.
- **Time + i18n beyond the Gregorian↔Julian + ISO 8601 already
  landed**: TZif / POSIX TZ / Unicode case folding / PCRE.
  Gated on the Linux strftime thunks, which aren't in tree.
- **Compression beyond DEFLATE + GZIP + zlib + Adler-32 + CRC32
  already landed**: ZIP / Cabinet (.cab) / Zstandard / LZ4.
  Gated on a workload (PNG already covered, no other compressed
  asset in tree).
- **Image formats beyond BMP + TGA + PNG already landed**:
  GIF / JPEG / WebP. Each is 1500+ LOC; gated on a real consumer.
- **Font formats beyond the existing TTF**: PCF / PSF1 / PSF2.
  Gated on a `setfont`-style userland app.
- **Linux ABI gaps**: ptrace / userfaultfd / io_uring / BPF /
  eBPF / landlock / seccomp-bpf / mremap MREMAP_FIXED /
  clock_adjtime / rseq / splice. Each is gated on a Linux ELF
  caller exercising it.
- **Win32 / NT facade gaps**: NtCreateSection (file-backed) /
  ALPC / ETW / Mailslot / NamedPipe (full) / NtSetInformationFile
  (full) / KTM transactions / WNF / AdjustPrivileges proper.
  Each is gated on a PE caller exercising it.
- **ACPI / power**: AML interpreter (subset), EC, S3 sleep, S0ix
  modern standby, P-states. Each is hardware-touching with no
  current test machine that would benefit.
- **Boot / firmware beyond UEFI loader already landed**:
  EFI runtime services, EFI variables, PE32+ EFI loader rework.
  Gated on a firmware feature that isn't in scope.

If any of these become needed, add them back with a named
consumer. Don't pre-pay the implementation cost of speculation.
