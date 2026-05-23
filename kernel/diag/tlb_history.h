#pragma once

#include "util/types.h"

/*
 * kernel/diag/tlb_history.h
 *
 * Circular ring of recent TLB-shootdown IPI broadcasts. Every call
 * to SmpTlbShootdownAddr / SmpTlbShootdownRange records a row:
 *
 *   (source CPU, source RIP, target AddressSpace*, VA start,
 *    VA end, tick at issue)
 *
 * 64 entries, lock-free single-writer-per-CPU (different CPUs
 * write different slots via an atomic counter — collisions can
 * lose entries but never corrupt the ring). Read out at panic
 * time as part of the crash dump.
 *
 * Cost: 8 bytes × 6 fields × 64 = 3 KiB BSS. Per-call overhead
 * is one `xadd` (atomic counter inc) + six quadword stores.
 * Negligible compared to the IPI broadcast itself.
 *
 * Class of bug this catches: TLB-stale / lost-shootdown crashes
 * where the symptom is a #PF at a valid-looking RIP whose page
 * was "supposed to be" remapped recently. Without the ring, the
 * investigator can only see the END STATE (what's mapped now);
 * with the ring, they see WHO did the unmap, WHEN, and FOR
 * WHICH range.
 */

namespace duetos::diag
{

inline constexpr u32 kTlbHistorySlots = 64;

struct TlbHistoryEntry
{
    u64 tick;          // ::duetos::time::TickCount() at issue
    u64 va_start;      // page-aligned
    u64 va_end;        // exclusive, page-aligned
    u64 src_rip;       // who issued the shootdown
    u64 as_ptr;        // mm::AddressSpace* as u64 (avoids header pull-in)
    u32 src_cpu;       // issuing CPU id
    u32 valid;         // 0 = unused slot; 1 = populated
};

/// Record a shootdown. Called from SmpTlbShootdownAddr /
/// SmpTlbShootdownRange. `src_rip` is the address the caller
/// captured via __builtin_return_address(0). Safe at any
/// interrupt level (the per-slot writes are reorder-tolerant —
/// readers only consult `valid` after `tick`).
void TlbHistoryRecord(u64 src_rip, u32 src_cpu, u64 as_ptr, u64 va_start, u64 va_end);

/// Walk the ring and emit each populated entry to the panic-mode
/// serial console. Newest first. Skipped if the ring is empty.
/// Called from DumpDiagnostics in core::Panic.
void TlbHistoryDump();

/// Total shootdowns recorded since boot (may exceed kTlbHistorySlots).
/// The panic dump prefixes the per-entry walk with this so an
/// investigator knows whether they're seeing a complete history
/// (count <= slots) or a windowed tail.
u64 TlbHistoryCount();

} // namespace duetos::diag
