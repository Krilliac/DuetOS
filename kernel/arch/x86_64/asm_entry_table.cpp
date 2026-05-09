/*
 * DuetOS — anchor table for hand-written assembly entry points.
 *
 * Several .S files in this slice contribute symbols that, on their
 * own, have no caller yet — they're primitives waiting for a
 * higher-level slice to wire them into a live code path. lld with
 * `--gc-sections` (set in kernel/CMakeLists.txt) garbage-collects
 * sections whose symbols are unreferenced, so without an explicit
 * anchor those primitives would silently disappear from the image.
 *
 * The pointer table here references each one. Marking the table
 * `[[gnu::used]] [[gnu::retain]]` keeps both the table and the
 * symbols it points at in the image. The boot path calls
 * `AsmEntryAnchorReport()` once so the anchor is exercised at
 * runtime — the compiler can't statically prove the table is
 * unused, even ignoring the linker's `--gc-sections` heuristic.
 *
 * The table is single-source-of-truth for "which assembly entry
 * points exist but aren't yet bound to a dispatcher / IDT slot /
 * shadow page." When a higher-level slice wires one in, the entry
 * stays here as a sanity reference; the entry only leaves when the
 * symbol is removed from the codebase entirely.
 */

#include "arch/x86_64/cet.h"
#include "arch/x86_64/fpu.h"
#include "arch/x86_64/serial.h"
#include "arch/x86_64/syscall_msr.h"
#include "arch/x86_64/traps.h"
#include "subsystems/win32/seh_unwind.h"
#include "util/types.h"

extern "C"
{
    /* Symbols defined in .S files this slice introduces. */
    void native_syscall_entry();                           // arch/x86_64/native_syscall_entry.S
    void nt_syscall_entry();                               // subsystems/win32/nt_syscall_entry.S
    void Win32ThreadEntryThunk();                          // subsystems/win32/thread_thunk.S
    void NativeSyscallEntry(duetos::arch::TrapFrame*);     // arch/x86_64/syscall_msr.cpp
    void NtSyscallEntryDispatch(duetos::arch::TrapFrame*); // subsystems/win32/nt_dispatch.cpp
} // extern "C"

namespace duetos::arch
{

namespace
{

struct AsmEntry
{
    const char* name;
    const void* addr;
};

[[gnu::used]] [[gnu::retain]]
const AsmEntry kAsmEntryAnchor[] = {
    {"FpuSaveXState", reinterpret_cast<const void*>(&FpuSaveXState)},
    {"FpuRestoreXState", reinterpret_cast<const void*>(&FpuRestoreXState)},
    {"FpuInitState", reinterpret_cast<const void*>(&FpuInitState)},
    {"native_syscall_entry", reinterpret_cast<const void*>(&native_syscall_entry)},
    {"NativeSyscallEntry", reinterpret_cast<const void*>(&NativeSyscallEntry)},
    {"nt_syscall_entry", reinterpret_cast<const void*>(&nt_syscall_entry)},
    {"NtSyscallEntryDispatch", reinterpret_cast<const void*>(&NtSyscallEntryDispatch)},
    {"RtlCaptureContext", reinterpret_cast<const void*>(&RtlCaptureContext)},
    {"RtlRestoreContext", reinterpret_cast<const void*>(&RtlRestoreContext)},
    {"Win32ThreadEntryThunk", reinterpret_cast<const void*>(&Win32ThreadEntryThunk)},
    {"CetEnableMsrs", reinterpret_cast<const void*>(&CetEnableMsrs)},
    {"CetSetPl0Ssp", reinterpret_cast<const void*>(&CetSetPl0Ssp)},
    {"CetGetSsp", reinterpret_cast<const void*>(&CetGetSsp)},
    {"CetSwitchSsp", reinterpret_cast<const void*>(&CetSwitchSsp)},
    {"SyscallRetargetForAbi", reinterpret_cast<const void*>(&SyscallRetargetForAbi)},
};

} // namespace

void AsmEntryAnchorReport()
{
    /* One-line boot summary so a regression that strips one of
     * these stays observable without a source dive. We iterate
     * the table to keep both it and every entry it references
     * reachable from the live boot path — `--gc-sections` walks
     * forward from real call sites, so a runtime read here pins
     * the symbols against the linker's reachability analysis. */
    constexpr u32 count = sizeof(kAsmEntryAnchor) / sizeof(kAsmEntryAnchor[0]);

    SerialWrite("[asm] entry stubs registered: ");
    SerialWriteHex(count);
    SerialWrite(" symbols\n");

    /* Volatile sink so the loop's loads are not optimised away.
     * Each `entry.addr` load forces the linker to keep the
     * referenced asm symbol live. */
    volatile const void* sink = nullptr;
    for (u32 i = 0; i < count; ++i)
    {
        sink = kAsmEntryAnchor[i].addr;
    }
    (void)sink;
}

} // namespace duetos::arch
