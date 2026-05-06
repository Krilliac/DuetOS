#include "mm/kernel_half_watch.h"

#include "arch/x86_64/serial.h"
#include "core/panic.h"
#include "mm/paging.h"

namespace duetos::mm
{

namespace
{

constexpr u64 kEntriesPerTable = 512;
constexpr u64 kKernelHalfFirst = 256;
constexpr u64 kKernelHalfCount = kEntriesPerTable - kKernelHalfFirst;

// Bits the CPU may set on a present PML4 entry without us touching
// it (Intel SDM Vol 3A §4.7). Mask these out of every comparison so
// a normal page walk under the entry doesn't trip the wire.
//   bit 5 = Accessed  — set whenever any descendant entry is used.
// Dirty (bit 6) is reserved on PML4 entries that point at a lower
// table (which is every kernel-half PML4 entry today — no 512 GiB
// PS pages), so we leave it unmasked: any drift there IS a real
// mutation worth flagging.
constexpr u64 kCpuMaintainedMask = 1ULL << 5;

constinit u64 g_snapshot[kKernelHalfCount] = {};
constinit bool g_armed = false;

inline u64 NormaliseEntry(u64 raw)
{
    return raw & ~kCpuMaintainedMask;
}

} // namespace

void KernelHalfWatchArm()
{
    u64* pml4 = BootPml4Virt();
    if (pml4 == nullptr)
    {
        // PagingInit hasn't run yet — re-arming once paging is up
        // would observe the real entries. Don't pretend to be armed
        // on a null PML4; the resulting Check() would panic on every
        // call against a snapshot of zeros.
        arch::SerialWrite("[mm/kpml4-watch] arm skipped — boot PML4 not yet adopted\n");
        return;
    }
    for (u64 i = 0; i < kKernelHalfCount; ++i)
    {
        g_snapshot[i] = NormaliseEntry(pml4[kKernelHalfFirst + i]);
    }
    g_armed = true;
    arch::SerialWrite("[mm/kpml4-watch] armed (256 PML4 entries snapshotted)\n");
}

bool KernelHalfWatchArmed()
{
    return g_armed;
}

void KernelHalfWatchCheck(const char* callsite_label)
{
    if (!g_armed)
    {
        return;
    }
    u64* pml4 = BootPml4Virt();
    if (pml4 == nullptr)
    {
        // Should not happen post-arm — boot PML4 is set once and
        // never torn down — but guard the deref so a caller during
        // a partial-init state doesn't compound the mystery.
        return;
    }
    for (u64 i = 0; i < kKernelHalfCount; ++i)
    {
        const u64 live = NormaliseEntry(pml4[kKernelHalfFirst + i]);
        if (live != g_snapshot[i])
        {
            // Loud, structured panic — the offending PML4 index, the
            // snapshot value, and the live value all reach the panic
            // banner. The callsite_label tells the next debugger
            // which path observed the drift first; combined with the
            // index it pins which kernel-half region got mutated
            // (bit 47..39 → PML4 index → 512 GiB stride).
            arch::SerialWrite("[mm/kpml4-watch] DRIFT at callsite=");
            arch::SerialWrite(callsite_label != nullptr ? callsite_label : "(null)");
            arch::SerialWrite(" pml4_idx=");
            arch::SerialWriteHex(kKernelHalfFirst + i);
            arch::SerialWrite(" snapshot=");
            arch::SerialWriteHex(g_snapshot[i]);
            arch::SerialWrite(" live=");
            arch::SerialWriteHex(live);
            arch::SerialWrite("\n");
            core::PanicWithValue("mm/kpml4-watch", "kernel-half PML4 entry drifted from snapshot",
                                 kKernelHalfFirst + i);
        }
    }
}

} // namespace duetos::mm
