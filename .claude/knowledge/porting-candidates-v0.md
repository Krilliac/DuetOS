# Porting / re-creation candidates v0

_Type: Plan + Observation._
_Status: Active — open list. Each session can pick from this._
_Last updated: 2026-05-03._

This file enumerates discrete features whose primary work is
**clean-room porting from a public spec** rather than novel
architecture work. Items here have:

1. **A public spec** (no IP entanglement, no NDA),
2. **A clean-room path** (Linux/FreeBSD/Wine/ReactOS prior art is
   reference-only, never the source of code),
3. **An eventual consumer** in DuetOS (a feature gap, a Linux ABI
   call, a Win32 thunk, etc), and
4. **Bounded size** — each row is one slice's worth of work
   (≈200–600 LOC).

When you land one, mark its row "LANDED YYYY-MM-DD → <commit-hash>"
and record the knowledge entry that supersedes it. Do not delete
rows: history of considered-but-not-picked is itself useful data
for the next session.

## Resume prompt

> Read `.claude/knowledge/porting-candidates-v0.md`. Pick a row that
> matches the current session's interest (display / audio / storage /
> net / crypto / FS / time / archives). The row gives you the spec,
> the prior art, the eventual consumer, and the size estimate.
> Commit with a "LANDED" note in this file before pushing.

## Status — landed slices

| Date | Row | Knowledge file |
|------|-----|----------------|
| 2026-05-01 | EDID 1.3/1.4 base-block parser | `edid-parser-v0.md` |
| 2026-05-01 | CVT 1.1 / 1.2 RBv1 timing generator | this slice (see commit) |
| 2026-05-01 | CEA-861 EDID extension parser (HDMI VSDB / video / audio / HDR) | this slice (see commit) |
| 2026-05-03 | AES-128 / AES-256 block cipher (FIPS 197) | `aes-and-keywrap-v0.md` |
| 2026-05-03 | AES Key Wrap (RFC 3394) | `aes-and-keywrap-v0.md` |
| 2026-05-03 | CRC32 hoist out of `gpt.cpp` (IEEE 802.3 reflected) | `crc32-md5-base64-and-eapol-keywrap-v0.md` |
| 2026-05-03 | MD5 (RFC 1321) — legacy interop only | `crc32-md5-base64-and-eapol-keywrap-v0.md` |
| 2026-05-03 | Base64 encode/decode (RFC 4648) | `crc32-md5-base64-and-eapol-keywrap-v0.md` |
| 2026-05-03 | HMAC-MD5 (RFC 2104 + RFC 1321) — legacy interop | `crc32-md5-base64-and-eapol-keywrap-v0.md` (extended) |
| 2026-05-03 | Unicode UTF-8 / UTF-16 codepoint conversions (RFC 3629 + Unicode 15) | `kernel/util/unicode.{h,cpp}` (collapses exfat+ntfs ad-hoc helpers) |
| 2026-05-03 | TGA 2.0 uncompressed 24/32-bpp decoder (Truevision TGA) | `kernel/util/tga.{h,cpp}` (RLE deferred to v1; ImageView wiring deferred to follow-up slice) |
| 2026-05-03 | Gregorian↔Julian-Day + ISO 8601 datetime parser/printer (Fliegel & Van Flandern + ISO 8601:2019) | `kernel/util/datetime.{h,cpp}` |
| 2026-05-03 | BMP encoder + parser util TU (32-bpp BI_RGB) — pulled out of screenshot.cpp + imageview.cpp into `kernel/util/bmp` | `kernel/util/bmp.{h,cpp}` |

## Display + GPU

| Slice | Spec | Prior art (reference only) | Consumer | Est. LOC |
|-------|------|----------------------------|----------|----------|
| ~~EDID 1.3/1.4 base block~~ LANDED 2026-05-01 | VESA E-EDID A2 | Linux drm_edid, X.Org | P2 #12 | ~600 |
| ~~CVT timing generator~~ LANDED 2026-05-01 | VESA CVT 1.1/1.2 | libxcvt, X.Org cvt(1) | mode-set | ~400 |
| ~~CEA-861 ext block~~ LANDED 2026-05-01 | CEA-861-E/F | Linux drm_edid_cea | HDMI audio, HDR | ~600 |
| **GTF (Generalized Timing Formula)** — pre-CVT timings | VESA GTF 1.1 | X.Org gtf(1) | legacy CRT modes | ~250 |
| **DisplayID 1.3 / 2.0** — successor to EDID | VESA DisplayID | Linux drm_displayid | post-2014 monitors | ~500 |
| **CTA-861-G / 861-H VIC table extension** | CTA-861-G | Linux drm_edid | HDMI 2.1 modes | ~200 |
| **DPMS state machine** | VESA DPMS | X.Org DPMS ext | screen-saver, power | ~150 |
| **Mode-pool dedup + best-fit selector** | (DuetOS-internal) | Linux drm_modes.c | mode-set syscall | ~300 |
| **DDC/I²C bit-banged transport** | VESA DDC2B | Linux drm_dp_helper | feeds EDID | per-vendor |
| **AUX channel for DisplayPort** | DP 1.4 | Linux drm_dp_aux | DP modes | per-vendor |

## Audio

| Slice | Spec | Prior art | Consumer | Est. LOC |
|-------|------|-----------|----------|----------|
| **AC'97 codec init + BDL** | AC'97 spec rev 2.3 | FreeBSD `ich.c`, ALSA `intel8x0` | P0 #2 | ~600 |
| **HDA controller reset + CORB/RIRB** | Intel HDA spec | ALSA hda_controller, FreeBSD hda | P0 #2 | ~700 |
| **HDA codec verb table** | Intel HDA spec §7.3 | ALSA hda_codec | P0 #2 | ~300 |
| **WAV (RIFF) parser/writer** | RFC + Microsoft WAVEFORMATEX | libsndfile | sound effects | ~150 |
| **Vorbis comment parser** | Xiph spec | libvorbis | metadata | ~120 |
| **OGG container** | RFC 3533 | libogg | streaming | ~250 |
| **FLAC stream decoder** | xiph FLAC spec | libFLAC | lossless audio | ~600 |
| **MP3 frame decoder** (LayerIII) | ISO 11172-3 | libmpg123, dr_mp3 | audio playback | ~1500 |

## Storage + Filesystems

| Slice | Spec | Prior art | Consumer | Est. LOC |
|-------|------|-----------|----------|----------|
| **AHCI write path** | AHCI 1.3 + SATA spec | Linux libata, FreeBSD ahci | already-built read path | ~300 |
| **ext4 write path** | ext4 wiki | Linux fs/ext4 | subsystems-status gap | ~2000 |
| **ext4 journaling (jbd2)** | ext3 / ext4 journal spec | Linux fs/jbd2 | crash safety | ~1500 |
| **NTFS read parsing completion** | NTFS spec (Anderson) | Linux fs/ntfs3, ntfs-3g | Windows interop | ~1500 |
| **NTFS write path** | (same) | (same) | (same) | ~2000 |
| **ISO 9660 / Joliet / Rock Ridge** | ECMA-119 + RFC 4101 | Linux fs/isofs | mount CD-ROM | ~400 |
| **UDF (DVD/Blu-ray)** | OSTA UDF 2.60 | Linux fs/udf | mount DVDs | ~1200 |
| **F2FS read** | Samsung F2FS spec | Linux fs/f2fs | flash storage | ~1500 |
| **Btrfs read-only** | btrfs wiki | Linux fs/btrfs | enthusiast FS | ~2500 |
| **9P (Plan 9 protocol)** | 9P2000 RFC | Linux fs/9p, FreeBSD virtfs | QEMU virtfs | ~400 |
| **virtio-blk** | virtio 1.2 spec | Linux drivers/block/virtio_blk | QEMU storage | ~300 |
| **virtio-rng** | virtio 1.2 spec | Linux drivers/char/hw_random | entropy source | ~80 |
| **virtio-fs** | virtio 1.2 spec | Linux fs/fuse/virtio_fs | host-shared FS | ~600 |
| **TPM 2.0 (TIS interface)** | TCG PC Client TIS | Linux drivers/char/tpm | secure boot, sealed storage | ~500 |

## Networking + Crypto

| Slice | Spec | Prior art | Consumer | Est. LOC |
|-------|------|-----------|----------|----------|
| ~~AES-128/256 block cipher~~ LANDED 2026-05-03 | FIPS 197 | OpenSSL, ARM Cryptolib | Wi-Fi, future TLS | ~250 |
| **AES-GCM / AES-CCM modes** | NIST SP 800-38D | mbedTLS | Wi-Fi WPA3 / TLS | ~200 |
| ~~AES key wrap (RFC 3394)~~ LANDED 2026-05-03 | RFC 3394 | mbedTLS, BoringSSL | Wi-Fi M3 GTK | ~100 |
| ~~MD5~~ LANDED 2026-05-03 | RFC 1321 | mbedTLS | legacy interop | ~100 |
| **ChaCha20 + Poly1305** | RFC 8439 | BoringSSL | TLS 1.3 ciphersuite | ~250 |
| _(see Landed slices: MD5 — RFC 1321, 2026-05-03)_ | | | | |
| **Curve25519 / X25519** | RFC 7748 | TweetNaCl | Wi-Fi WPA3-SAE, TLS | ~300 |
| **Ed25519 signature verify** | RFC 8032 | TweetNaCl | code-sign verify | ~400 |
| ~~CRC32 hoist out of `gpt.cpp`~~ LANDED 2026-05-03 | IEEE 802.3 polynomial | (already present) | broad cleanup | ~50 |
| ~~Base64 encode/decode~~ LANDED 2026-05-03 | RFC 4648 | musl, glibc | HTTP auth, MIME | ~100 |
| ~~HMAC-MD5~~ LANDED 2026-05-03 | RFC 2104 + RFC 1321 | mbedTLS | NTLM (when added) | ~80 |
| **TLS 1.2 client (no cert verify)** | RFC 5246 | mbedTLS | https:// | ~3000 |
| **TLS 1.3 client** | RFC 8446 | mbedTLS, BoringSSL | https:// | ~3500 |
| **DNS-over-TLS / DoH** | RFC 8484 | systemd-resolved | secure DNS | ~250 |
| **HTTP/2 client** | RFC 7540 | nghttp2 | modern HTTPS | ~2000 |
| **WebSocket framing** | RFC 6455 | (own) | live-update apps | ~300 |
| **mDNS responder + querier** | RFC 6762 + 6763 | Avahi, Bonjour | service discovery | ~600 |
| **SSDP (UPnP discovery)** | UPnP Forum | gupnp | local-net discovery | ~300 |
| **DHCPv6** | RFC 8415 | systemd-networkd | IPv6 | ~500 |
| **SLAAC (IPv6 stateless)** | RFC 4862 | Linux net/ipv6 | IPv6 | ~300 |
| **ICMPv6 NDP** | RFC 4861 | Linux net/ipv6 | IPv6 | ~400 |
| **IPv6 stack proper** | RFC 8200 | Linux net/ipv6 | subsystems-status gap | ~1500 |
| **SMBv2 client (read-only)** | MS-SMB2 | Linux fs/cifs | Windows file sharing | ~2000 |
| **NFSv3 client** | RFC 1813 | Linux fs/nfs | UNIX file sharing | ~1500 |
| **CDC-NCM (USB Ethernet)** | USB IF NCM 1.0 | Linux drivers/net/usb/cdc_ncm | newer phones | ~400 |
| **EAP-PEAP / EAP-TTLS** | RFC 5247 | wpa_supplicant | enterprise Wi-Fi | ~600 |
| **WPA3-SAE handshake** | IEEE 802.11-2020 | hostapd | modern Wi-Fi | ~500 |
| **TFTP client** | RFC 1350 | (own) | PXE / firmware download | ~150 |

## Time + Internationalisation

| Slice | Spec | Prior art | Consumer | Est. LOC |
|-------|------|-----------|----------|----------|
| **TZif (Olson zoneinfo) parser** | RFC 8536 (TZif v3) | musl `__tzset.c`, glibc tzfile.c | Linux ABI gap | ~300 |
| **POSIX TZ string parser** | POSIX.1-2008 §8.3 | musl | TZ env var | ~150 |
| **Gregorian↔ Julian day conversion** | (well-known) | musl, glibc | calendar app | ~80 |
| **ISO 8601 datetime parser/printer** | ISO 8601 | musl strftime | logging | ~200 |
| ~~Unicode UTF-8/UTF-16 conversions~~ LANDED 2026-05-03 | RFC 3629 + Unicode 15 §3.9 | musl mbtowc | Win32 wide strings, exfat/ntfs filename decode | ~300 |
| **Unicode case folding (Unicode 15)** | Unicode case-folding tables | ICU mini | text compare | ~500 |
| **PCRE-lite regex** | (subset of POSIX BRE) | musl regex.c | shell pattern match | ~600 |

## Archives + Compression

| Slice | Spec | Prior art | Consumer | Est. LOC |
|-------|------|-----------|----------|----------|
| **DEFLATE / RFC 1951 inflater** | RFC 1951 | tinfl.c, miniz | gzip, png, zip, kernel-image | ~600 |
| **GZIP container** | RFC 1952 | (above) | initramfs.gz, http content | ~100 |
| **CPIO archive (newc/odc)** | POSIX.1-1988 | Linux init/initramfs.c | initramfs prereq | ~150 |
| **TAR ustar / pax** | POSIX.1-2001 | libarchive | distribution tarballs | ~200 |
| **ZIP archive read-only** | PKWARE APPNOTE | minizip | Win32 install MSIs | ~250 |
| **Cabinet (.cab) read-only** | MS-CAB | libmspack | Windows install | ~600 |
| **LZ4 decoder** | LZ4 frame spec | lz4 ref | fast decompression | ~200 |
| **Zstandard decoder** | RFC 8478 | zstd lib | modern compression | ~1500 |

## Image + Font formats

| Slice | Spec | Prior art | Consumer | Est. LOC |
|-------|------|-----------|----------|----------|
| TGA decoder (uncompressed 24/32-bpp): LANDED 2026-05-03; encoder + RLE deferred | TGA 2.0 spec | stb_image | wallpapers, icons (ImageView wiring still TODO) | ~280 |
| ~~BMP encoder + parser util TU (32-bpp BI_RGB)~~ LANDED 2026-05-03 | Microsoft BITMAPINFOHEADER | stb_image | screenshot writer + ImageView | ~200 |
| **PNG decoder** | RFC 2083 | stb_image, libpng | image viewer | ~300 (+DEFLATE) |
| **PNG encoder** | RFC 2083 | (same) | screenshot upgrade | ~200 (+DEFLATE) |
| **GIF87a/89a decoder + LZW** | W3C GIF spec | stb_image | animated icons | ~400 |
| **JPEG baseline decoder** | ITU-T T.81 | stb_image, jpeg-turbo | photo viewer | ~1500 |
| **WebP decoder (lossless)** | RFC 9649 | libwebp | modern photo | ~1500 |
| **PSF1/PSF2 font parser** | linux Documentation/fb/, kbd-tools | linux console_psf | console font customisation | ~120 |
| **PCF bitmap font parser** | X Logical Font Description | libXfont | classic X bitmap fonts | ~250 |
| **TrueType shaping enhancement** | OpenType spec | stb_truetype | smoother text rendering | (existing ttf.cpp) |

## Linux ABI gaps (subsystems-status.md cross-reference)

| Slice | Surface | Est. LOC |
|-------|---------|----------|
| **Real ptrace state machine** | PTRACE_TRACEME / ATTACH / DETACH / SETOPTIONS / CONT / SINGLESTEP | ~600 |
| **userfaultfd minimal** | UFFDIO_API / REGISTER / COPY | ~400 |
| **io_uring submission queue** | IORING_OP_READ/WRITE/SENDMSG | ~1500 |
| **BPF CLASSIC packet filter** | BPF_PROG_TYPE_SOCKET_FILTER | ~500 |
| **eBPF skeleton (hardcoded prog)** | bpf(BPF_PROG_LOAD) | ~800 |
| **landlock restrict-self** | LANDLOCK_RULE_PATH_BENEATH | ~300 |
| **seccomp-bpf filter execution** | SECCOMP_SET_MODE_FILTER | ~500 |
| **mremap MREMAP_FIXED** | (extends current mremap) | ~150 |
| **clock_adjtime / adjtimex** | struct timex / NTP discipline | ~250 |
| **rseq (restartable sequences)** | (currently -ENOSYS facade) | ~400 |
| **splice / tee real zero-copy file↔pipe** | (currently pipe→pipe only) | ~300 |

## Win32 / NT facade gaps (subsystems-status.md cross-reference)

| Slice | Surface | Est. LOC |
|-------|---------|----------|
| **NtCreateSection (file-backed)** | section→file mapping with offset+length view | ~400 |
| **NtCreatePort / Connect / Request / Reply** | LPC / ALPC backbone | ~800 |
| **EtwTrace*** | NtTrace / TraceEvent | ~600 |
| **NtCreateMailslot** | mailslot file path | ~200 |
| **NtCreateNamedPipeFile (full)** | named-pipe semantics | ~400 |
| **NtSetInformationFile** beyond FilePositionInformation | rename / disposition / EOF / link / mode-page | ~600 |
| **KTM transactions** | NtCreateTransaction etc. | ~1000 |
| **WNF** (Windows Notification Facility) | NtRegisterWnfStateName | ~400 |
| **AdjustPrivileges proper** | Token privileges → kernel cap mapping | ~200 |

## ACPI / power

| Slice | Spec | Prior art | Consumer | Est. LOC |
|-------|------|-----------|----------|----------|
| **AML interpreter (subset)** | ACPI 6.5 §20 | ACPICA | Battery, suspend | ~3000 |
| **EC (Embedded Controller)** | ACPI 6.5 §12 | Linux drivers/acpi/ec | brightness, battery | ~500 |
| **S3 sleep / wake** | ACPI §16 | Linux kernel/power | suspend | ~700 |
| **S0ix modern standby** | Microsoft platform reference | Linux x86 platform | laptop sleep | ~500 |
| **Performance states (P-states)** | ACPI §8.4 | Linux cpufreq | power management | ~400 |

## Boot + Firmware

| Slice | Spec | Prior art | Consumer | Est. LOC |
|-------|------|-----------|----------|----------|
| **EFI runtime services calls** | UEFI 2.10 | EDK2 | reset, get-time, variable | ~300 |
| **EFI variables read/write** | UEFI 2.10 | EDK2 | boot config | ~250 |
| **PE32+ EFI loader (kernel)** | UEFI PE32+ | EDK2 | UEFI boot path | ~400 |
| **GPT partition write** | UEFI GPT | gdisk | P2 #16 disk installer | ~400 |
| **FAT32 mkfs** | Microsoft FAT spec | mkfs.fat | P2 #16 | ~300 |

## How to pick

A row qualifies for a session when:

1. The reference spec is reachable (no NDA, public document).
2. The eventual consumer in DuetOS is named (don't pick rows that
   are pure speculation — that's CLAUDE.md "Anti-Bloat" violation).
3. The size estimate fits one slice (split if it's > 800 LOC).
4. Pre-existing kernel infrastructure isn't blocking — for instance
   AC'97 audio is gated on a DMA-coherent allocator that doesn't
   exist; the row stays in the table but the per-slice plan needs to
   include the prerequisite (`mm::AllocDmaCoherent`).

## Lifecycle

When you land a row:

1. Add a "LANDED YYYY-MM-DD" prefix in the table.
2. Cross-link the new knowledge file by name (not URL).
3. Update `feature-gaps-end-user-v0.md` (if user-visible) or
   `subsystems-status.md` (if ABI-related).
4. Commit this file in the same PR as the slice.

When all rows in a category are LANDED, you can graduate that
category section into its own knowledge file and remove from here —
but only if the category really is exhausted. (For example, Display
+ GPU still has ~10 unstruck rows; not graduating it.)

## Out-of-scope items deliberately not listed

- **JPEG / WebP / H.264 / H.265 decoders** beyond stub-level — these
  are 10k+ LOC each and gated on hardware acceleration to be
  practical. Defer until a Vulkan ICD lands and a real video player
  is on the board.
- **OpenGL ES 3.x ICD** — Vulkan-first per CLAUDE.md project pillars.
- **Bluetooth full stack** — listed as P2 #18 in feature-gaps but
  spans HCI + L2CAP + RFCOMM + GATT + profiles, each its own slice.
  Don't pull in until the use case lands first (mouse / headset).
- **Printing** — P2 #19; same reason.
- **DRM (cinema-DRM, not the Linux DRM module)** — explicitly
  rejected per project goals; no Widevine, no PlayReady, no FairPlay.
