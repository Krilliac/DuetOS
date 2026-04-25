#pragma once

#include "types.h"

/*
 * DuetOS — human-readable diagnostic decoders.
 *
 * The crash-dump and trap paths used to emit raw hex for every
 * register and the operator had to mentally translate what e.g.
 *
 *     cr0      : 0x80050033
 *     rflags   : 0x0000000000010202
 *     cs       : 0x08
 *
 * actually meant. These helpers add a human-readable bracket-list
 * after the hex so the meaning is on-screen, and add a few
 * convenience formatters (uptime in milliseconds, current task
 * label) that previously printed as opaque hex.
 *
 * Each Write* helper assumes COM1 is already initialised — they
 * call straight into arch::Serial*. No allocation, no locking,
 * safe from any context including panic / IRQ / trap.
 */

namespace duetos::core
{

/// Decode the architectural CR0 bits the kernel actually sets and
/// emit them as `[PE|MP|ET|NE|WP|AM|NW|CD|PG]`. Reserved-zero bits
/// are not labelled; if any of them are set the helper appends
/// `|RSVD` so the operator notices.
void WriteCr0Bits(u64 value);

/// Decode CR4 the same way: `[VME|PVI|TSD|DE|PSE|PAE|MCE|PGE|PCE|
/// OSFXSR|OSXMMEXCPT|UMIP|FSGSBASE|PCIDE|OSXSAVE|SMEP|SMAP|PKE|CET]`.
void WriteCr4Bits(u64 value);

/// Decode RFLAGS as `[CF|PF|AF|ZF|SF|TF|IF|DF|OF|IOPL=N|NT|RF|VM|AC|VIF|VIP|ID]`.
void WriteRflagsBits(u64 value);

/// Decode EFER as `[SCE|LME|LMA|NXE|SVME|FFXSR|TCE]`.
void WriteEferBits(u64 value);

/// Decode a segment selector into ring + table + index, e.g.
/// `[ring=0 GDT idx=1 (kernel-code)]`. Recognises the four canonical
/// selectors from `arch/x86_64/gdt.h`; unknown indices show as
/// `(unknown)`.
void WriteSegmentSelectorBits(u64 selector);

/// Decode a #PF error code into `[present|read|kernel|...]`. Same
/// flag set as `arch::DumpPageFaultFlags` (kept in sync); used by
/// the panic path so a value-of-the-fault dump line is human-readable.
void WritePageFaultErrBits(u64 err);

/// Compute a wall-time-since-boot millisecond figure from the best
/// available clock (HPET when up, scheduler-tick fallback) and
/// emit it as `123.456 ms` or `5.234 s`. Used in place of the raw
/// `uptime: 0x...` line in crash dumps.
void WriteUptimeReadable();

/// Emit the current task as `<name>#<id>` (e.g. `kboot#0`,
/// `idle-bsp#1`). Falls back to `<unknown>` when the scheduler
/// hasn't started yet, and `<noname>#<id>` when the task slot
/// exists but has no string name. Safe before SchedInit — uses
/// the same percpu accessor as the rest of the panic dump.
void WriteCurrentTaskLabel();

/// Decode CR3 as `pml4=0x... pcid=0x...`. The low 12 bits hold the
/// PCID when CR4.PCIDE=1; otherwise they're reserved-zero. We always
/// split the field so a stray bit there is visible.
void WriteCr3Decoded(u64 value);

/// Symbolize a value if and only if it falls in plausible kernel
/// code. Otherwise emit nothing. Used to annotate GPRs that may
/// (or may not) be holding function pointers.
void WriteSymbolIfCode(u64 value);

/// Decode an x86_64 page-table-entry flags word (Intel SDM Vol 3A
/// §4.5) as `[P|RW|US|PWT|PCD|A|D|PS/PAT|G|NX]`. Used by `mm/paging`
/// and any logger that prints PTE flags.
void WritePteFlags(u64 flags);

/// Coarse VA classification used by the crash-dump path to annotate
/// raw addresses (cr2 / rsp / rbp / rip) with the region they fall
/// into. Hex alone tells you the value; this tells you what the value
/// MEANS without forcing the operator to keep paging.h's memory map
/// in their head while reading a panic.
///
/// Order matters — `Classify` walks the most specific buckets first
/// (kernel image sections, kernel arenas) before falling back to the
/// coarse user/canonical/non-canonical buckets. Tags are stable
/// strings so a host-side parser can grep on them.
enum class VaRegion : u8
{
    Null,             // exactly 0
    LowNullPage,      // [0 .. 4 KiB)
    LowIdentityMap,   // (4 KiB .. 1 GiB) — boot-stack region pre-userland
    UserCanonicalLow, // [1 GiB .. 0x0000_8000_0000_0000)
    NonCanonical,     // canonical hole
    KernelCanonical,  // [0xFFFF_8000_0000_0000 .. 0xFFFF_FFFF_8000_0000)
    KernelText,       // [_text_start .. _text_end)
    KernelRodata,     // [_rodata_start .. _rodata_end)
    KernelData,       // [_data_start .. _data_end)
    KernelBss,        // [_bss_start .. _bss_end)
    KernelDirectMap,  // remainder of [kKernelVirtualBase .. kMmioArenaBase)
    KernelMmio,       // [kMmioArenaBase .. kKernelStackArenaBase)
    KernelStackArena, // [kKernelStackArenaBase .. end)
};

/// Return the region a VA falls in. Pure arithmetic + a couple of
/// linker-symbol comparisons; safe from any context.
VaRegion ClassifyVa(u64 va);

/// Stable short-name for a region (e.g. "k.text", "user-canonical").
/// Used in `[region=...]` annotations.
const char* VaRegionName(VaRegion region);

/// Convenience: emit ` [region=NAME]` to serial. Caller does NOT
/// pre-emit a separator — this writes its own leading space. No
/// trailing newline.
void WriteVaRegion(u64 va);

/// Boot-time validation that `ClassifyVa` returns the expected region
/// for known fixed addresses across every bucket. Panics on mismatch.
/// Called from `kernel_main`'s self-test block alongside the other
/// diag self-tests.
void VaRegionSelfTest();

/// Emit a one-shot bracketed mm-map summary to serial:
///   === DUETOS KERNEL MM MAP ===
///     k.text        : 0x... .. 0x...   (N KiB)
///     ...
///   === END KERNEL MM MAP ===
/// Sourced directly from the linker section symbols + `mm/paging.h`
/// + `mm/kstack.h` constants the VA classifier already reads, so a
/// future layout change updates both at once. Intended to run once
/// at boot — every later panic dump's `[region=...]` tags are then
/// trivially decodable against this single anchor.
void WriteMmMapSummary();

} // namespace duetos::core
