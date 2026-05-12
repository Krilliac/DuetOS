# Rust Subsystems

> **Audience:** Kernel hackers adding or maintaining Rust subsystem crates.
>
> **Execution context:** Kernel build tooling and kernel-linked Rust crates.
>
> **Maturity:** Stable foundation; sixteen production Rust subsystems live in the kernel tree.
>
> Production: DuetFS, USB HID, USB class config, DHCP / DNS / TCP-options byte-walkers, USB MSC SCSI responses, PNG / BMP / TGA header validators, ELF / PE-image validators, NTFS metadata walker, exFAT metadata walker, ext4 metadata walker, ACPI table walker, IEEE 802.11 management-frame walker, Bluetooth HCI walker, SMBIOS table walker, PCI / PCIe capability list walkers, and Multiboot2 info-structure walker.
>
> All sixteen crates have a current C++ caller; there are no skeleton crates left in this slice.

## Overview

Rust in DuetOS is a kernel subsystem tool, not a second application
framework. A Rust crate is appropriate when the subsystem owns a clear
boundary with attacker-controlled structured bytes or lifetime-heavy state,
such as DuetFS, USB class descriptors, or the TCP/IP stack. C++ remains the
orchestration language for the kernel image.

"Attacker-controlled bytes" means bytes that cross a trust boundary before the
kernel has parsed them: USB descriptors returned by a plugged-in device, network
packets from the wire, filesystem metadata from removable media, and PE/ELF
metadata from an executable image. The attacker is not assumed to have code
execution yet; the risk is that a malicious device or image can choose lengths,
offsets, counts, nesting depth, and tag ordering that stress every parser edge
case.

Rust is not magic sandboxing and it does not make an unsafe FFI boundary safe by
itself. It is useful here because the byte walkers can be written as
bounds-checked slice traversal with checked/saturating arithmetic, no ambient
aliasing, and no unchecked pointer increments in the parser core. In C++ the
same parser can be made correct, but every `ptr + len`, cast, packed-struct
view, and manual lifetime convention must stay correct forever; one missed
bounds check can become a kernel read/write primitive. DuetOS therefore keeps
C++ as the owning/orchestration layer and uses Rust selectively for narrow
parsers where memory-safety bugs are the main risk.

## Candidate priority

The first Rust slice covers DuetFS plus USB descriptor parsers, but it does
not exhaust the high-risk surface. Prioritize future Rust crates where the
subsystem is mostly byte parsing or state-machine validation and can expose a
small C ABI back to the C++ owner.

| Priority | Candidate | Why it is high risk | Rust boundary shape |
|----------|-----------|---------------------|---------------------|
| P0 | Network packet parsers (Ethernet / ARP / IPv4 / ICMP / UDP / TCP options, DHCP / DNS where applicable) | Remote peers control packet lengths, header offsets, fragmentation state, option lists, and checksummed payload shape. A parser bug is remotely reachable before auth. | Parse borrowed RX buffers into validated header/value structs; C++ keeps NIC rings, routing, timers, and socket ownership. |
| P0 | PE/COFF and ELF metadata readers | Executable images control section tables, data-directory RVAs, imports, relocations, TLS records, resources, and symbol/export tables. This sits directly on the project pillar of running PE binaries. | Rust validates image metadata and returns a relocation/import/load plan; C++ owns address-space mapping, capability checks, and process creation. |
| P0 | Read-only disk-format parsers not already in Rust (NTFS / exFAT / FAT32 / ext4 metadata walkers) | Removable or dual-boot disks control superblocks, directory entries, extents, runlists, timestamps, and string encodings. The kernel must reject malformed metadata without trusting lengths or offsets. | Rust turns blocks into validated directory / inode / extent records; C++ VFS owns handles, caching policy, block devices, and permissions. |
| P1 | Font and image decoders used by UI or boot assets (TTF, PNG, BMP/TGA where non-trivial) | Asset files can be supplied by themes, apps, or downloaded content and tend to contain nested tables, compressed streams, and attacker-chosen dimensions. | Rust decodes/validates metadata and bounded spans; C++ renderer owns surfaces, glyph cache, and GPU upload. |
| P1 | Protocol control-plane parsers (USB RNDIS/CDC control messages, Bluetooth HCI events, Wi-Fi management frames/EAPOL) | Devices or nearby radios control variable-length protocol records and state transitions. Bugs can be reached from hardware, radio, or network-adjacent inputs. | Rust parses envelopes and validates state-machine messages; C++ owns driver rings, DMA, IRQs, and kernel object lifetimes. |
| P2 | ACPI/SMBIOS/PCI capability-table readers | Firmware controls table lengths, offsets, checksums, and nested structures before the kernel has a normal trust base. Bugs are usually local/firmware-level, but they run very early. | Rust validates table walks into plain records; C++ owns boot sequencing, MMIO mapping, and architecture effects. |

Do **not** move code to Rust just because it is important. Scheduler paths,
address-space mutation, IRQ dispatch, DMA ring programming, and GPU command
submission are high-consequence but not automatically good Rust candidates: they
are dominated by hardware side effects, lock ordering, and existing C++ kernel
ownership. Rust is the best fit when the risky part can be isolated as
"bytes/state in, validated plan out."

The repository now has one shared Rust foundation **and actual Rust subsystem code**:

- `/rust-toolchain.toml` pins the nightly toolchain and bare-metal target.
- `/Cargo.toml` is the workspace root and owns the profiles for every Rust
  crate linked into the kernel.
- `/Cargo.lock` is tracked so dependency resolution is reproducible; CMake
  invokes cargo with `--locked`.
- `/.cargo/config.toml` selects `x86_64-unknown-none` and the `build-std`
  knobs needed by freestanding crates.
- `/kernel/rust/` is the single Rust staticlib link unit. Subsystem crates are
  rlibs; the aggregate staticlib pulls in `core` / `alloc` / panic runtime once
  so the C++ kernel link does not get duplicate Rust runtime objects.
- `/kernel/fs/duetfs/` is the native filesystem Rust subsystem.
- `/kernel/drivers/usb/hid_rust/` is the USB HID report-descriptor parser Rust
  subsystem; C++ HID APIs are wrappers over this parser.
- `/kernel/drivers/usb/class_rust/` parses USB configuration/interface/endpoint
  descriptor streams for MSC, hub, UVC, and Bluetooth class-driver binding.
- `/kernel/net/parsers_rust/` (`duetos_net_parsers`) wraps the DHCPv4 option
  walker and the DNSv1 name skipper. C++ callers in `kernel/net/stack.cpp`
  delegate `DhcpFindOption` and `DnsSkipName` through this crate.
- `/kernel/drivers/usb/msc_scsi_rust/` (`duetos_usb_msc_scsi`) parses USB MSC
  SCSI INQUIRY / READ CAPACITY(10) / GET CONFIGURATION header / READ TOC
  header / READ DISC INFORMATION responses. The C++ MSC driver
  (`kernel/drivers/usb/msc_scsi.cpp`) delegates its parse functions through
  this crate.
- `/kernel/util/img_meta_rust/` (`duetos_img_meta`) validates PNG, BMP,
  and TGA image headers. `kernel/util/png.cpp::PngParseHeader`,
  `kernel/util/bmp.cpp::BmpParseHeader`, and
  `kernel/util/tga.cpp::TgaParseHeader` delegate to this crate; the C++
  side keeps zlib inflate, scanline filter unwind, and pixel-copy.
- `/kernel/loader/exec_meta_rust/` (`duetos_exec_meta`) validates ELF64
  files (header + every PT_LOAD segment) and PE/COFF images
  (DOS stub + e_lfanew bounds + PE signature + AMD64 machine check +
  optional-header magic / section / file alignment + image-base
  low-half bound + section-table bounds + per-section raw extent fit).
  `kernel/loader/elf_loader.cpp::ElfValidate` and the body of
  `kernel/loader/pe_loader.cpp::ParseHeaders` (up to but not including
  the data-directory walks) delegate to this crate; the C++ side keeps
  data-directory checks, address-space mapping, capability checks, and
  process creation.
- `/kernel/fs/ntfs_rust/` (`duetos_ntfs`) parses NTFS boot sectors,
  MFT record headers, resident `$FILE_NAME` attributes, and runlist
  (mapping-pairs) entries. `kernel/fs/ntfs.cpp` delegates byte
  parsing to this crate; UTF-16 → ASCII translation stays in C++.
- `/kernel/fs/exfat_rust/` (`duetos_exfat`) parses exFAT VBRs,
  derives cluster geometry, walks the FAT chain (4-byte LE per
  cluster), and decodes dirent sets (File 0x85 + Stream-Extension
  0xC0 + FileName 0xC1 tuples). `kernel/fs/exfat.cpp` delegates
  byte parsing to this crate.
- `/kernel/fs/ext4_rust/` (`duetos_ext4`) parses ext2/3/4
  superblocks, group descriptors, inode records, extent headers,
  extent leaves / index nodes, and linux_dirent records.
  `kernel/fs/ext4.cpp` delegates byte parsing to this crate;
  block I/O, scratch management, and the depth>0 extent-tree DFS
  stay in C++.
- `/kernel/acpi/acpi_rust/` (`duetos_acpi`) parses RSDP v1 / v2,
  ACPI table headers, MADT entry headers, FADT body fields, MCFG
  entries, HPET descriptors, and SRAT memory-affinity entries.
  `kernel/acpi/acpi.cpp::AcpiInit` delegates the RSDP
  signature + checksum validation to the crate; `ParseFadt`
  cross-validates its packed-struct overlay against the Rust
  decoder.
- `/kernel/net/wifi80211_rust/` (`duetos_wifi80211`) parses 802.11
  frame headers, Beacon / Probe Response body prefixes, the IE
  (Information Element) list, and EAPOL-Key (4-way handshake)
  descriptors. `kernel/net/wireless/beacon.cpp::BeaconParse`
  delegates the frame header, body, and IE walks to the crate.
- `/kernel/net/hci_rust/` (`duetos_hci`) parses Bluetooth HCI
  event packets and the Command Complete, Command Status,
  Disconnection Complete, LE Meta, Read_Local_Version, and
  Read_BD_ADDR bodies. `kernel/net/bluetooth/hci.cpp` delegates
  the Read_Local_Version + Read_BD_ADDR rparam decoders to the
  crate.
- `/kernel/arch/x86_64/smbios_rust/` (`duetos_smbios`) decodes
  the 2.x (`_SM_` + `_DMI_`) and 3.x (`_SM3_`) entry-point
  anchors (signature + length + 8-bit checksum), then walks the
  variable-length structure table — each call returns the
  bounded `(formatted_offset, strings_offset, end_offset)`
  triple a C++ caller needs to advance to the next record. The
  trailing-strings walker enforces a 1 KiB per-string cap so a
  firmware that omits a NUL terminator can't make the walker
  run past the structure-table slice. `kernel/arch/x86_64/smbios.cpp`
  keeps the legacy-BIOS scan window (`PhysToVirt(0xF0000)` +
  16-byte stride), single-init guarding, the BIOS / system /
  chassis / processor field extraction, and the boot-log line.
- `/kernel/drivers/pci/caps_rust/` (`duetos_pci_caps`) walks both
  the standard capability list (8-bit "next" pointers, head at
  config-space offset 0x34) and the PCIe extended capability
  list (12-bit "next" pointers, head at ECAM offset 0x100).
  Each chain hop is bounded; self-loops, out-of-range pointers,
  unaligned next-offsets, and the all-zero "no ext caps"
  sentinel are clamped to end-of-list. `kernel/drivers/pci/pci.cpp`
  materialises the device's standard config into a 256-byte
  buffer and routes `PciFindCapability` through the crate. The
  new `PciFindExtCapability` entry point is ready for the
  MMCONFIG-routed read primitive that a future PCIe driver
  needing AER / SR-IOV / ATS will add.
- `/kernel/mm/multiboot2_rust/` (`duetos_multiboot2`) validates
  the Multiboot2 info-structure header and walks the tag list +
  the mmap entry array. The bootloader-controlled `total_size`
  is capped at 64 MiB; each tag's `size` field is validated to
  fit in the remaining slice; mmap-entry base+length overflow
  is rejected. `kernel/mm/frame_allocator.cpp::ForEachMmapEntry`
  delegates every cursor advance to the crate.
- `/cmake/DuetOSRust.cmake` exposes `duetos_add_rust_staticlib(...)`, used by
  `/kernel/rust/CMakeLists.txt` to build the aggregate Rust link unit.

## Lint + format policy

The workspace pins one `[workspace.lints]` block in `/Cargo.toml`; every
member crate inherits via `[lints] workspace = true`. The deny-set is
intentionally small (`unsafe_op_in_unsafe_fn`, `unused_must_use`,
`non_ascii_idents`, `clippy::todo`, `clippy::unimplemented`,
`clippy::dbg_macro`); `undocumented_unsafe_blocks` is documented as an
aspirational lint pending a SAFETY-comment backfill on the v0 crates.

Style follows idiomatic Rust (K&R braces, default control flow); the
C++ Allman convention does not bleed in. The pin lives in
`/rustfmt.toml`; the local CI preflight (`tools/dev/check-local.sh`)
runs `cargo fmt --check`, `cargo clippy -- -D warnings`, and a host
unit-test smoke (`tools/dev/cargo-host-test.sh`) against every crate
that ships `#[cfg(test)]` modules.

## Host unit tests

Workspace `.cargo/config.toml` forces `target = x86_64-unknown-none` +
`unstable.build-std`, which makes `cargo test` unusable directly (the
test harness needs std). `tools/dev/cargo-host-test.sh` works around
this by calling `rustc --test` directly against each crate's
`src/lib.rs`, building a hosted binary with the system libcore +
libstd. New crates that ship `#[cfg(test)]` modules add themselves to
the `HOST_TEST_CRATES` list at the top of the script.

## Contract for a new crate

1. Add the crate directory to the root `[workspace].members` list.
2. Keep the crate standalone: C++ may call Rust through a narrow C FFI, but do
   not create C++ → Rust → C++ → Rust chains.
3. Expose a hand-written C header in the crate's `include/` directory. Bindgen
   and cbindgen are intentionally not part of the kernel build.
4. Keep `unsafe` at the FFI wall. Convert raw C pointers into Rust references
   or slices once, validate null/empty cases first, then keep the parser core in
   safe Rust. Any internal `unsafe` block needs a one-line comment naming the
   kernel invariant that makes it sound.
5. Add the crate as a dependency of `/kernel/rust/Cargo.toml`. Do **not** link
   subsystem crates as independent staticlibs; multiple `build-std` staticlibs
   duplicate `core` / `alloc` symbols.
6. Add the hand-written header path to `kernel/CMakeLists.txt` if C++ code needs
   to include it directly, then expose C++ wrappers through the owning subsystem
   directory.

## CMake shape

Only `/kernel/rust/CMakeLists.txt` calls `duetos_add_rust_staticlib(...)`. It
builds the aggregate `duetos_kernel_rust` staticlib and tracks all subsystem
Rust sources as extra dependencies. `kernel/CMakeLists.txt` links that one `.a`
into both kernel ELF stages and includes each subsystem's hand-written C header
directory for C++ wrappers.

## Profiles

Profiles live only at the workspace root so every kernel-linked crate has the
same panic, LTO, optimization, and overflow-check behavior. Crate-local profile
sections are ignored by cargo once a workspace root exists, so do not add them
back to member crates. The panic handler lives in `/kernel/rust/src/panic.rs`;
subsystem rlibs must not define their own `#[panic_handler]`.
