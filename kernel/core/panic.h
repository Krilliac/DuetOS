#pragma once

#include "types.h"

/*
 * CustomOS — unified kernel panic / assert infrastructure.
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

namespace customos::core
{

/// Write the panic banner + message to COM1, then halt the CPU.
/// NEVER returns. Safe from IRQ context.
[[noreturn]] void Panic(const char* subsystem, const char* message);

/// Like Panic but includes a single u64 value rendered as hex. Used
/// for "here's the address that tripped the fault" diagnostics.
[[noreturn]] void PanicWithValue(const char* subsystem, const char* message, u64 value);

} // namespace customos::core

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
            ::customos::core::Panic((subsys), "KASSERT failed: " msg);                                                 \
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
            ::customos::core::PanicWithValue((subsys), "KASSERT failed: " msg, (value));                               \
        }                                                                                                              \
    } while (0)
