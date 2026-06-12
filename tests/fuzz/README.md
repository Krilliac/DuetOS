# DuetOS — untrusted-input parser fuzz harness

Compile and run libFuzzer-driven fuzzers against the DuetOS code paths
that consume attacker-controlled bytes: the wireless data-decode parsers
(EAPOL key parser, vendor firmware envelope parsers), the PE/COFF and
ELF64 executable loaders' parse/validate surface, the on-disk
parsers for untrusted disk/USB bytes (GPT partition table; FAT32,
exFAT, NTFS, ext4 volumes), and the network L2/L3/L4 RX ingest
path (Ethernet/ARP/IPv4/ICMP/UDP/TCP). The fuzzers run on the
host (Linux/macOS clang), not on the target — they exercise the same
source files the kernel builds, with a small `host_shim/` providing stub
implementations of the kernel-only headers (serial output, klog macros,
KASSERT, spinlock, and the PeLoad-only mm/proc/win32 surface). The shim's
klog macros are variadic no-ops covering every `KLOG_*` the real
`kernel/log/klog.h` defines, so a kernel-side arity change cannot
silently drop a parser from coverage.

## What's covered

| Fuzzer | Target parser |
|--------|---------------|
| `fuzz_eapol` | `EapolKeyParse(frame, len, &out)` — 802.1X key descriptor frame parser |
| `fuzz_iwl_fw` | `IwlFirmwareParse(blob, size, &out)` — Intel iwlwifi TLV envelope walker |
| `fuzz_rtl_fw` | `RtlFirmwareParse(blob, size, &out)` — Realtek rtlwifi/rtw88/rtw89 32-byte header |
| `fuzz_bcm_fw` | `BcmFirmwareParse(blob, size, &out)` — Broadcom b43 record stream |
| `fuzz_pe` | `PeValidate` / `PeReport` / `PeIsPe32` / `PeIsDynamicBase` / `PePreferredBaseOf` / `PeImageSizeOf` / `PeQuickSummaryTo` — the PE/COFF loader's pure parse/validate/diagnostic walkers (`pe_loader.cpp` + `pe_exports.cpp`), plus the `duetos_exec_meta` Rust prefix/image validator it delegates to |
| `fuzz_elf` | `ElfValidate` / `ElfEntry` / `ElfProgramHeaderInfo` / `ElfForEachPtLoad` — the ELF64 loader's pure header + PT_LOAD walkers (`elf_loader.cpp`), plus the `duetos_exec_meta` Rust ELF validator. Reuses the PE harness's Rust staticlib + stub TU (ElfLoad's mm deps overlap PeLoad's). |
| `fuzz_gpt` | `GptProbe` — the GPT partition-table parser (`fs/gpt.cpp`): Protective-MBR check, primary-header walk, CRC32 of header + 128×128 entry array, partition-entry / LBA-range loop. The libFuzzer input is served as a read-only disk via `host_shim/drivers/storage/block.h`; the real `util/crc32.cpp` is linked so both CRC gates are exercised. |
| `fuzz_fat32` | `Fat32Probe` — the FAT32 volume parser (`fs/fat32.cpp` + lookup/dir/read TUs): BPB sanity, FAT-chain walk, root-directory snapshot. Same read-only-disk shim as `fuzz_gpt`; `Fat32Shutdown()` resets the volume registry each input so coverage doesn't stall at `kMaxVolumes`. |
| `fuzz_exfat` | `ExfatProbe` — the exFAT volume parser (`fs/exfat.cpp` + the no_std `duetos_exfat` Rust crate: boot sector, geometry, dirent-set decoder). Same read-only-disk shim; Rust linked via the same rlib + panic=abort staticlib recipe as `duetos_exec_meta`. |
| `fuzz_ntfs` | `NtfsProbe` — the NTFS volume parser (`fs/ntfs.cpp` + the no_std `duetos_ntfs` Rust crate: boot sector, MFT record header, $FILE_NAME attribute walk). Same read-only-disk shim + Rust recipe as `fuzz_exfat`. |
| `fuzz_ext4` | `Ext4Probe` — the ext4 volume parser (`fs/ext4.cpp` + the no_std `duetos_ext4` Rust crate: superblock, group descriptor, inode, extent tree, dir entries). Same read-only-disk shim + Rust recipe; seeded with a real `mkfs.ext4` image so the deep inode/extent/dir walkers are reached. |
| `fuzz_net` | `NetStackInjectRx` — the L2/L3/L4 ingest chokepoint every NIC driver funnels RX frames through (`net/stack.cpp` + `firewall`/`socket`/`tcp`/`tcp_segment`/`tcp_timer` + the no_std `duetos_net_parsers` Rust DHCP/DNS option walkers): Ethernet → ARP / IPv4 → ICMP / UDP / TCP state machine, **and** the IPv6 peer (ethertype 0x86DD → `Ipv6HeaderParse` → ICMPv6 / UDP / TCP, `net/ipv6.cpp`). The libFuzzer input is the raw frame; seeded with valid ARP / IPv4+ICMP / +UDP / +TCP-SYN **and** IPv6+ICMPv6 / IPv6+UDP / IPv6+TCP-SYN frames (correct IPv4/ICMP + IPv6 upper-layer pseudo-header checksums). The IPv6 RX branch was wired into `NetStackInjectRx` but unseeded — effectively dark under fuzzing — until the IPv6 seeds landed. The harness runs `NetStackInit()` once at startup, exactly as kernel boot does, so the ARP/TCP hash buckets carry their empty sentinels (a never-initialised table makes the lookup walkers loop forever — that is a boot-order invariant, not a parser bug). |
| `fuzz_deflate` | `DeflateInflate(src, src_len, dst, dst_cap)` — the RFC 1951 inflater (`util/deflate.cpp`): stored / fixed-Huffman / dynamic-Huffman bit-stream, Huffman-table build, LZ77 back-reference window. Input is a raw DEFLATE stream (from a PNG IDAT / gzip / ZIP entry). Fixed output ceiling so a decompression bomb can't wedge the run. |
| `fuzz_gzip` | `GzipInflate` / `ZlibInflate` (`util/gzip.cpp` + `deflate`/`crc32`/`adler32`) — the RFC 1952 / RFC 1950 variable-length header walkers + CRC-32 / Adler-32 tail gates around the inflater. First input byte selects the wrapper so one corpus covers both. |
| `fuzz_zip` | `ZipOpen` / `ZipReadEntry` / `ZipExtractEntry` (`util/zip.cpp` + `deflate`) — EOCD scan, central-directory walk, local-file-header chase, stored/deflate extraction. Input is a whole in-memory ZIP archive. |
| `fuzz_bmp` | `BmpParseHeader` (`util/bmp.cpp` + the no_std `duetos_img_meta` Rust crate) — BITMAPFILEHEADER + DIB header (signature, DIB size, dimension cap, top-down flag). Rust linked via the same rlib + panic=abort staticlib recipe as `duetos_exec_meta`. |
| `fuzz_tga` | `TgaParseHeader` + `TgaDecodeUncompressed` (`util/tga.cpp` + `duetos_img_meta`) — 18-byte Truevision header walk then bounded uncompressed 24/32-bpp pixel copy + bottom-up row flip. |
| `fuzz_jpeg` | `JpegParseHeader` + `JpegDecode` (`util/jpeg.cpp` + `duetos_img_meta`) — SOI/segment hop to first SOF (Rust), then C++ DHT/DQT/SOS walk + baseline-DCT MCU reconstruction into bounded scratch + pixel buffers. |
| `fuzz_png` | `PngParseHeader` + `PngDecode` (`util/png.cpp` + `duetos_img_meta` + the real `gzip`/`deflate`/`crc32`/`adler32`) — signature + IHDR + IHDR-CRC (Rust), then IDAT chunk walk, zlib inflate, per-scanline filter unwind. Re-exercises the DEFLATE inflater on PNG-shaped input. |
| `fuzz_asn1` | `asn1::Read` / `ForEachInSequence` / `IntegerToBytesBE` / `OidEquals` (`crypto/asn1.cpp`) — DER TLV walker: tag + short/long-form length decode, child-overruns-parent check, one level of constructed recursion. Input is DER from a cert / RSA blob. |
| `fuzz_x509` | `x509::Parse` (`crypto/x509.cpp` + `asn1`/`bigint`/`rsa`) — DER X.509 v3: TBSCertificate, validity, subject CN, RSA SubjectPublicKeyInfo. Sits on the ASN.1 reader along the cert-shaped path. |
| `fuzz_fw_pkg` | `FwPackageLooksLike` + `FwPackageParse` (`loader/firmware_package.cpp` + the real `crypto/sha256`) — the 160-byte DuetOS firmware envelope (magic/version/family/flags/length + SHA-256 payload digest) wrapping a vendor blob. The digest gate is exercised, not stubbed. |
| `fuzz_pe_exports` | `PeParseExports` + `PeExportAt` / `PeExportLookupOrdinal` (`loader/pe_exports.cpp` + `util/string`) — IMAGE_EXPORT_DIRECTORY + EAT/ENT/EOT array walk, forwarder classification, name-table binary search. A distinct entry point from the PE loader (`fuzz_pe`). |
| `fuzz_vt` | `ParserFeed` (`util/vt_parser.cpp` + `util/unicode`) — the DEC ANSI state machine over a PTY byte stream: C0 controls, UTF-8 multi-byte join, bounded CSI param array, bounded OSC string with truncation flag. Non-null no-op callbacks installed so the CSI/OSC dispatch arms are reached. |
| `fuzz_acpi` | The seven `duetos_acpi` (Rust) firmware-table walkers (`acpi/acpi_rust/`): `duetos_acpi_parse_{rsdp,table_header,madt_entry_header,fadt,mcfg_entry,hpet,srat_memory_affinity}` — RSDP v1/v2 + 8-bit-additive checksum, the 36-byte generic table header, and the MADT / FADT / MCFG / HPET / SRAT bodies. One input drives every parser plus the chained MADT-subtable and SRAT-memory-affinity length walks. These bytes are firmware-supplied — fully attacker-controlled on a malicious VM host. Same rlib + panic=abort staticlib recipe as `fuzz_exfat`; links no kernel C++ TU. |
| `fuzz_ec` | `ParsePublicKey` (`net/ec.cpp` + `crypto/bigint`) — decodes an uncompressed SEC1 EC point (`0x04 \|\| X \|\| Y`) into two field-width big-integers, range-checks each against the field prime, and runs the on-curve test. Reached from `x509_verify.cpp` when a TLS peer presents an ECDSA/ECDH certificate, so the point bytes are attacker-chosen. Drives both P-256 and P-384 on every input; seeded with the on-curve NIST generator points so the fuzzer reaches the heavy on-curve bigint arithmetic past the prefix/length/range gates. |
| `fuzz_aml` | `AmlNamespaceBuild` + the post-walk byte consumers `AmlMethodBody` / `AmlNameValue` / `AmlReadS5` (`acpi/aml.cpp` + the no_std `duetos_aml` Rust crate) — the recursive AML bytecode walker over the DSDT/SSDT (PkgLength, NameString, Scope/Device/Method push, Buffer/Package, OperationRegion + Field lists) now lives in the memory-safe Rust crate; `aml.cpp` is a thin FFI caller. The harness serves the fuzz input as the DSDT by defining the `AcpiMapTable`/`DsdtAddress` accessors itself and drives the real public API, resetting global namespace state with `AmlNamespaceShutdown` between iterations — so it fuzzes the real integrated C++ orchestration + Rust walker path. **The original C++ walker had a 1-byte heap-OOB read in `ReadNameString` (a malformed `PkgLength` shorter than its own encoding underflowed `pkg_end - name_off`), found by this harness; the Rust port carries the same fix at all four package-length sites, and the namespace it builds from QEMU's DSDT is byte-for-byte identical to the C++ walker's (275 entries / 81 methods / 42 devices).** |
| `fuzz_cdcecm` | `CdcEcmProbe` → `ParseConfigDescriptor` + `ReadMacFromString` (`drivers/usb/cdc_ecm.cpp`) — the USB CDC-ECM config / interface / endpoint + CDC Ethernet Functional Descriptor walker and the 12-char ASCII-hex `iMACAddress` string-descriptor parser. The harness drives the real public `CdcEcmProbe()`; `host_shim/usbnet_stubs.cpp` serves the fuzz input as the stream of device control-IN replies the bring-up consumes (the `fuzz_aml` model) and resolves the mm/net/sched symbols the TU drags in. A deliberately one-frame DMA pool fails the rx/tx allocation pair just after the parsers run, so `BringUp` returns before it latches the file-local `online` flag — every input re-exercises the parsers. The rx bulk-poll loop (a `for(;;)` task) is not reached; CDC-ECM injects the RX transfer verbatim with no per-frame length arithmetic. |
| `fuzz_rndis` | `RndisProbe` → `RndisParseConfig` + `RndisInitialize` / `RndisSetU32Oid` / `RndisQueryMac` (`drivers/usb/rndis.cpp`) — the RNDIS config-descriptor walker plus the control-channel reply parsers (INITIALIZE_CMPLT / SET_CMPLT / QUERY_CMPLT). `RndisQueryMac` is the classic length/offset spot: it reads the MAC at `8 + InformationBufferOffset` behind an InfoBufferLength / Offset containment check. Same `usbnet_stubs.cpp` stream-fed control surface + one-frame pool as `fuzz_cdcecm`. The rndis-rx bulk deframer (the OTHER length/offset site — `MessageLength` vs `DataOffset + DataLength`) is a `for(;;)` task not reachable from the public probe; **a u32-wrap heap-OOB read found there while writing this harness was fixed in `rndis.cpp` `RxPollEntry` (a device could wrap `8 + DataOffset` / `abs + DataLength` past the containment check and steer a multi-gigabyte `NetStackInjectRx` read off `rx_buf`).** |

`fuzz_pe` links the real no_std `duetos_exec_meta` Rust crate (built as
an rlib + a panic=abort staticlib wrapper, so a Rust-side overflow/index
bug also aborts as a libFuzzer crash) and `host_shim/pe_stubs.cpp`, which
resolves the PeLoad-only kernel symbols — each stub aborts, so if a
"pure" validator ever reaches a kernel sink that divergence is itself a
recorded crash. `make run-pe` seeds the corpus from
`seeds/gen_pe_seeds.py` (minimal valid PE32+/PE32 images + the shipped
`windows-kill.exe`) so the fuzzer starts past the DOS/COFF prefix gate
and actually exercises the deep import/reloc/TLS/load-config/EAT walkers.

The IEEE 802.11 management-frame walker (`BeaconParse`) is **not** a
C++ harness here: its byte-level parsing now lives in the memory-safe
`duetos_wifi80211` Rust crate (`kernel/net/wifi80211_rust/`). The C++
`beacon.cpp` is a thin FFI caller with no raw-byte parsing left to
fuzz at this layer; the Rust walker is fuzzed via cargo-fuzz.

## Why these parsers

These are the DuetOS code paths that consume bytes from external,
attacker-controlled sources: vendor firmware blobs from `/lib/firmware/`,
on-air management frames from a wireless driver, arbitrary Windows
`.exe`/`.dll` and ELF images a guest hands the loaders (pillar #1), and
the partition table + filesystem on any disk/USB stick plugged in. The
loader/FS diagnostic + probe paths run on *rejected* inputs too — e.g.
`PeReport` walks a truncated PE before `PeValidate` gates the heavyweight
`PeLoad`, and `GptProbe`/`Fat32Probe` parse a hostile sector before any
mount. Fuzzing these catches OOB reads / pointer-arithmetic mistakes /
length-overflow bugs exactly where a malicious blob, rogue AP, crafted
executable, or doctored disk could deliver an attack surface. Several of
the byte-level walkers (PE/ELF prefix, exFAT, 802.11) are memory-safe
Rust crates; the harnesses link the real crates so a Rust panic
(overflow/index) also surfaces as a libFuzzer crash.

## Build and run

```bash
sudo apt-get install -y clang libclang-rt-dev   # clang ≥ 14 + libFuzzer/ASan rt
# fuzz_pe additionally needs `rustc` (the PE prefix/image gate is the
# no_std duetos_exec_meta Rust crate); the workspace's pinned nightly
# is fine.
make -C tests/fuzz                # build every C++ harness (incl. fuzz_pe)
make -C tests/fuzz run-eapol      # fuzz one for 60 s
make -C tests/fuzz run-iwl_fw
make -C tests/fuzz run-rtl_fw
make -C tests/fuzz run-bcm_fw
make -C tests/fuzz run-pe          # seeds the corpus first, then 60 s
make -C tests/fuzz run-elf         # seeds the corpus first, then 60 s
make -C tests/fuzz run-gpt         # seeds the corpus first, then 60 s
make -C tests/fuzz run-fat32       # seeds the corpus first, then 60 s
make -C tests/fuzz run-exfat       # seeds the corpus first, then 60 s
make -C tests/fuzz run-ntfs        # seeds the corpus first, then 60 s
make -C tests/fuzz run-ext4        # seeds the corpus first, then 60 s
make -C tests/fuzz run-net         # seeds the corpus first, then 60 s
make -C tests/fuzz run-deflate     # 60 s (no seed gate — raw bitstream)
make -C tests/fuzz run-gzip        # 60 s (no seed gate)
make -C tests/fuzz run-zip         # seeds the corpus first, then 60 s
make -C tests/fuzz run-bmp         # seeds the corpus first, then 60 s
make -C tests/fuzz run-tga         # seeds the corpus first, then 60 s
make -C tests/fuzz run-jpeg        # seeds the corpus first, then 60 s
make -C tests/fuzz run-png         # seeds the corpus first, then 60 s
make -C tests/fuzz run-asn1        # 60 s (no seed gate)
make -C tests/fuzz run-x509        # 60 s (no seed gate)
make -C tests/fuzz run-fw_pkg      # seeds the corpus first, then 60 s
make -C tests/fuzz run-pe_exports  # 60 s
make -C tests/fuzz run-vt          # 60 s (no seed gate)
make -C tests/fuzz run-acpi        # seeds the corpus first, then 60 s
make -C tests/fuzz run-aml         # seeds the corpus first, then 60 s
```

Each `run-*` target creates `corpus/<name>/` and lets libFuzzer
populate it with interesting inputs. Re-running picks up where the
previous run left off (corpus persistence). The single command that
builds **every** harness and runs them all in parallel — the CI
gate — is `make -C tests/fuzz fuzz-all` (or
`tools/test/fuzz-all.sh` directly; `FUZZ_SECONDS` / `FUZZ_JOBS`
tune the budget). Harnesses with a `seeds/gen_<name>_seeds.py`
get their corpus pre-seeded; the rest start cold.

## What the fuzzers will and won't catch

**Will catch:**
- Out-of-bounds reads on the input buffer.
- Length fields whose declared size overflows the buffer.
- Integer overflows in offset arithmetic.
- Infinite loops on malformed inputs.
- AddressSanitizer / UBSAN findings.

**Won't catch:**
- State-machine bugs in MLME or 4-way handshake (those are
  exercised by the in-kernel loopback test
  `kernel/net/wireless/test/wireless_e2e_test.cpp`).
- DMA-path bugs (no real DMA in fuzz harness).
- Per-vendor microcode upload errors (those need real silicon).
- Crypto correctness (covered by the in-kernel KAT self-tests).

## Reproducing a crash

When libFuzzer finds an interesting input, it writes
`crash-<sha1>` next to the binary:

```bash
./build/fuzz_eapol crash-deadbeef     # replay the failing input
```

Inspect the file with `xxd` to understand what the malformed frame
looked like, then fix the parser. Re-run the fuzzer to confirm the
crash is gone.
