# Rust Subsystems

> **Audience:** Kernel hackers adding or maintaining Rust subsystem crates.
>
> **Execution context:** Kernel build tooling and kernel-linked Rust crates.
>
> **Maturity:** Stable foundation; seven live Rust subsystems — DuetFS, USB HID, USB class config, DHCP/DNS byte-walkers, USB MSC SCSI responses, PNG/BMP header validators, and ELF/PE-prefix validators.

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
- `/kernel/util/img_meta_rust/` (`duetos_img_meta`) validates PNG and BMP
  image headers. `kernel/util/png.cpp::PngParseHeader` and
  `kernel/util/bmp.cpp::BmpParseHeader` delegate to this crate; the C++
  side keeps zlib inflate, scanline filter unwind, and pixel-copy.
- `/kernel/loader/exec_meta_rust/` (`duetos_exec_meta`) validates ELF64
  files (header + every PT_LOAD segment) and the PE/COFF prefix
  (DOS stub + e_lfanew bounds + PE signature + AMD64 machine check).
  `kernel/loader/elf_loader.cpp::ElfValidate` and the prefix of
  `kernel/loader/pe_loader.cpp::ParseHeaders` delegate to this crate;
  the C++ side keeps address-space mapping, capability checks, and
  process creation.
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
