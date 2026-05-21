#include "arch/x86_64/msr_safe.h"

#include "arch/x86_64/serial.h"
#include "debug/extable.h"

/*
 * WriteMsrSafe extable wiring.
 *
 * The body of `WriteMsrSafe` lives in msr_safe.S. Three exported
 * labels delimit the wrmsr instruction and its fixup target:
 *
 *   wrmsr_safe_start  — the wrmsr itself (faulting RIP)
 *   wrmsr_safe_end    — one past the wrmsr (success continuation)
 *   wrmsr_safe_fault  — fixup the trap dispatcher jumps RIP to
 *                       when a #GP / #PF hits [start, end).
 *
 * `RegisterMsrSafeExtable` is called from the early boot path
 * after `KernelExtableInit`. The trap dispatcher in `traps.cpp`
 * walks the extable on every kernel-mode #GP / #PF — if the
 * faulting RIP falls in [start, end) it redirects to `fault`.
 */

extern "C"
{
    extern const duetos::u8 wrmsr_safe_start[];
    extern const duetos::u8 wrmsr_safe_end[];
    extern const duetos::u8 wrmsr_safe_fault[];
}

namespace duetos::arch
{

void RegisterMsrSafeExtable()
{
    const duetos::u64 s = reinterpret_cast<duetos::u64>(wrmsr_safe_start);
    const duetos::u64 e = reinterpret_cast<duetos::u64>(wrmsr_safe_end);
    const duetos::u64 f = reinterpret_cast<duetos::u64>(wrmsr_safe_fault);
    const bool ok = ::duetos::debug::KernelExtableRegister(s, e, f, "arch/wrmsr_safe");
    if (!ok)
    {
        SerialWrite("[arch/msr-safe] extable registration failed\n");
    }
}

} // namespace duetos::arch
