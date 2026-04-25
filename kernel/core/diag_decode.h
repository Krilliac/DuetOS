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

} // namespace duetos::core
