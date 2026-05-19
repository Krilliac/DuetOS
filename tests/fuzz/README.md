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
| `fuzz_net` | `NetStackInjectRx` — the L2/L3/L4 ingest chokepoint every NIC driver funnels RX frames through (`net/stack.cpp` + `firewall`/`socket`/`tcp`/`tcp_segment`/`tcp_timer` + the no_std `duetos_net_parsers` Rust DHCP/DNS option walkers): Ethernet → ARP / IPv4 → ICMP / UDP / TCP state machine. The libFuzzer input is the raw frame; seeded with valid ARP / IPv4+ICMP / +UDP / +TCP-SYN frames (correct IP/ICMP checksums). The harness runs `NetStackInit()` once at startup, exactly as kernel boot does, so the ARP/TCP hash buckets carry their empty sentinels (a never-initialised table makes the lookup walkers loop forever — that is a boot-order invariant, not a parser bug). |

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
```

Each `run-*` target creates `corpus/<name>/` and lets libFuzzer
populate it with interesting inputs. Re-running picks up where the
previous run left off (corpus persistence).

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
