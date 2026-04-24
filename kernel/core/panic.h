#pragma once

#include "types.h"

/*
 * DuetOS — unified kernel panic / assert infrastructure.
 *
 * Before this module every subsystem reimplemented its own local
 * `PanicFoo(msg)` — serial-write a tag, serial-write the message,
 * halt. Nine near-identical copies. This consolidates them behind
 * one call so the format is uniform, the hex-value path doesn't need
 * to be copy-pasted, and the KASSERT macro is available everywhere.
 *
 * Output format:
 *
 *     \n[panic] <subsystem>: <message>
 *       value : 0x<hex>                       (only if PanicWithValue)
 *     [panic] CPU halted — no recovery.
 *
 * All callers must pass a stable subsystem string. Conventionally:
 *   - "mm/frame_allocator"
 *   - "mm/kheap"
 *   - "mm/paging"
 *   - "arch/lapic"
 *   - "arch/ioapic"
 *   - "acpi"
 *   - "sched"
 *   - "sync/spinlock"
 * Match the source-tree path (sans `kernel/`); that way grep-to-panic
 * is trivial during diagnosis.
 *
 * Context: kernel. Safe at any interrupt level — disables interrupts
 * and calls arch::Halt, which never returns.
 */

namespace duetos::core
{

/// Write the panic banner + diagnostic dump + message to COM1, then
/// halt the CPU. NEVER returns. Safe from IRQ context.
///
/// Output includes: current CPU id + LAPIC id (if PerCpu installed),
/// current task name + id (if scheduler online), uptime ticks,
/// control registers (CR0/CR2/CR3/CR4 + EFER + RFLAGS), a 16-frame
/// RBP-chain backtrace from the call site, and a 16-quadword raw
/// stack dump from current RSP.
[[noreturn]] void Panic(const char* subsystem, const char* message);

/// Like Panic but includes a single u64 value rendered as hex. Used
/// for "here's the address that tripped the fault" diagnostics.
[[noreturn]] void PanicWithValue(const char* subsystem, const char* message, u64 value);

/// Emit the diagnostic dump portion (without the halt) using a
/// caller-supplied RIP / RSP / RBP. Used by the trap dispatcher to
/// dump state from the faulting instruction's frame rather than the
/// dispatcher's own frame. Does NOT halt — caller halts.
void DumpDiagnostics(u64 rip, u64 rsp, u64 rbp);

/// Emit `=== DUETOS CRASH DUMP BEGIN ===` + the dump header
/// (schema version, subsystem, message, optional value, symbol-table
/// entry count). Callers then emit their own body and finish with
/// EndCrashDump so host-side tooling can extract the bracketed
/// record into a .dump file. Pass `optional_value = nullptr` to omit
/// the `value` line.
void BeginCrashDump(const char* subsystem, const char* message, const u64* optional_value);

/// Close the dump record started with BeginCrashDump by emitting the
/// `=== DUETOS CRASH DUMP END ===` marker.
void EndCrashDump();

} // namespace duetos::core

// ---------------------------------------------------------------------------
// KASSERT — compile-in-always assert. Not conditionally compiled out in
// release: kernel asserts are defense-in-depth against invariant
// violations, and saving the three bytes of "cmp+je" isn't worth the
// silent-corruption risk.
// ---------------------------------------------------------------------------
#define KASSERT(cond, subsys, msg)                                                                                     \
    do                                                                                                                 \
    {                                                                                                                  \
        if (!(cond))                                                                                                   \
        {                                                                                                              \
            ::duetos::core::Panic((subsys), "KASSERT failed: " msg);                                                 \
        }                                                                                                              \
    } while (0)

/// Same idea, but the failure path also renders a u64 value. Handy for
/// bounds checks: `KASSERT_LT(idx, limit, "mm", "index oob")` would
/// print the offending `idx` if the assertion trips.
#define KASSERT_WITH_VALUE(cond, subsys, msg, value)                                                                   \
    do                                                                                                                 \
    {                                                                                                                  \
        if (!(cond))                                                                                                   \
        {                                                                                                              \
            ::duetos::core::PanicWithValue((subsys), "KASSERT failed: " msg, (value));                               \
        }                                                                                                              \
    } while (0)
