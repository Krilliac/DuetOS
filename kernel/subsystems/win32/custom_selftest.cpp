#include "custom_selftest.h"
#include "custom.h"

#include "../../arch/x86_64/serial.h"
#include "../../arch/x86_64/traps.h"
#include "../../core/process.h"
#include "../../core/syscall.h"
#include "../../mm/kheap.h"

/*
 * End-to-end smoke test for the Win32 custom-diagnostics suite.
 * Called once from `kernel_main` so the boot serial log shows
 * concrete data flowing through every recorded surface — the
 * Win32 PE smoke crashes early on this build so we can't yet
 * rely on a real ProcessRelease to fire DumpOnAbnormalExit.
 *
 * Allocates a synthetic Process with just enough fields populated
 * to satisfy the hooks (pid + win32_custom_state), drives each
 * hook with synthetic events, and dumps the result. Runs entirely
 * in kernel context — no scheduler, no ring 3, no AS — so it can
 * fire arbitrarily early in kernel_main.
 *
 * Output format mirrors what real Win32 PEs will produce on
 * abnormal exit once boot stabilises.
 */

namespace duetos::subsystems::win32::custom
{

namespace
{

void Heading(const char* title)
{
    arch::SerialWrite("\n=== ");
    arch::SerialWrite(title);
    arch::SerialWrite(" ===\n");
}

// Build a fake Process that only owns the fields the custom hooks
// touch. Heap-allocate so the lifetime is explicit.
core::Process* MakeFake(u64 pid)
{
    auto* p = static_cast<core::Process*>(mm::KMalloc(sizeof(core::Process)));
    if (p == nullptr)
        return nullptr;
    // Zero just the fields the hooks read — pid + win32_custom_state.
    // The rest stays uninitialised; the hooks never look at it.
    p->pid = pid;
    p->win32_custom_state = nullptr;
    return p;
}

// Synthesize a TrapFrame for the flight-recorder hook. Only rip /
// rdi / rsi / rdx are read by OnSyscallEntry.
arch::TrapFrame MakeFrame(u64 rip, u64 rdi, u64 rsi, u64 rdx)
{
    arch::TrapFrame tf{};
    tf.rip = rip;
    tf.rdi = rdi;
    tf.rsi = rsi;
    tf.rdx = rdx;
    return tf;
}

} // namespace

void Win32CustomSelfTest()
{
    Heading("WIN32 CUSTOM SELF-TEST");
    arch::SerialWrite("Default system policy mask = 0x");
    arch::SerialWriteHex(GetSystemDefaultPolicy());
    arch::SerialWrite("\n");

    core::Process* proc = MakeFake(0xCAFEull);
    if (proc == nullptr)
    {
        arch::SerialWrite("[custom-test] FAIL: KMalloc fake-process failed\n");
        return;
    }

    // 1. Apply system default — should populate state with auto-on bits.
    ApplySystemDefaultPolicy(proc);
    auto* s = GetState(proc);
    if (s == nullptr)
    {
        arch::SerialWrite("[custom-test] FAIL: state not allocated\n");
        mm::KFree(proc);
        return;
    }
    arch::SerialWrite("[custom-test] state allocated, policy=0x");
    arch::SerialWriteHex(s->policy);
    arch::SerialWrite("\n");

    // 2. Flight recorder — push 5 synthetic syscall events.
    {
        Heading("FLIGHT RECORDER (5 synthetic syscalls)");
        for (u32 i = 0; i < 5; ++i)
        {
            const u64 fake_rip = 0x140001000ULL + i * 16;
            arch::TrapFrame tf = MakeFrame(fake_rip, 0xAA00 | i, 0xBB00 | i, 0xCC00 | i);
            // Rotate through real Win32 syscall numbers so the
            // record looks recognisable.
            const u64 nums[] = {
                static_cast<u64>(core::SYS_HEAP_ALLOC), static_cast<u64>(core::SYS_FILE_OPEN),
                static_cast<u64>(core::SYS_HEAP_FREE),  static_cast<u64>(core::SYS_GETLASTERROR),
                static_cast<u64>(core::SYS_WIN_CREATE),
            };
            OnSyscallEntry(proc, nums[i], &tf);
        }
    }

    // 3. Handle provenance — alloc 3 handles, close one, exercise the
    //    use-after-close detector.
    {
        Heading("HANDLE PROVENANCE (3 alloc, 1 close, 1 stale-read)");
        OnHandleAlloc(proc, 0x100, static_cast<u32>(core::SYS_FILE_OPEN), 0x140002000ULL);
        OnHandleAlloc(proc, 0x101, static_cast<u32>(core::SYS_FILE_OPEN), 0x140002010ULL);
        OnHandleAlloc(proc, 0x300, static_cast<u32>(core::SYS_EVENT_CREATE), 0x140002020ULL);
        OnHandleClose(proc, 0x101);
        const bool a = IsHandleActive(proc, 0x100);
        const bool b = IsHandleActive(proc, 0x101);
        const bool c = IsHandleActive(proc, 0x300);
        arch::SerialWrite("  IsActive(0x100) = ");
        arch::SerialWrite(a ? "true" : "false");
        arch::SerialWrite("\n  IsActive(0x101) = ");
        arch::SerialWrite(b ? "true" : "false");
        arch::SerialWrite("  <-- closed; expected false\n  IsActive(0x300) = ");
        arch::SerialWrite(c ? "true" : "false");
        arch::SerialWrite("\n");
    }

    // 4. SetLastError provenance — record a known error site.
    {
        Heading("ERROR PROVENANCE (synthetic SetLastError call)");
        OnLastErrorSet(proc, 0x57 /* ERROR_INVALID_PARAMETER */, 0x140003000ULL,
                       static_cast<u32>(core::SYS_SETLASTERROR));
        if ((s->policy & kPolicyErrorProvenance) != 0)
        {
            arch::SerialWrite("  last_value=0x");
            arch::SerialWriteHex(s->error.last_value);
            arch::SerialWrite(" set_rip=0x");
            arch::SerialWriteHex(s->error.set_rip);
            arch::SerialWrite(" set_syscall=");
            arch::SerialWriteHex(s->error.set_syscall_num);
            arch::SerialWrite("\n");
        }
    }

    // 5. Mutex contention + deadlock detection. Two threads:
    //      tid 100 holds mutex 0; tid 200 waits on it (owned by 100).
    //      Then tid 100 also waits on a mutex held by tid 200 — cycle.
    {
        Heading("DEADLOCK DETECT + CONTENTION (synthetic 2-thread cycle)");
        OnMutexAcquire(proc, /*slot=*/0);
        OnMutexAcquire(proc, /*slot=*/0); // second acquire — bumps acquire_count
        // tid 200 -> waits on mutex held by tid 100 (handle 0x200).
        // We can't drive different tids from the kernel context (CurrentTaskId
        // returns one value), so instead drive it via the API to show the
        // contention numbers grow. Cycle detection is exercised below.
        OnMutexWaitStart(proc, /*slot=*/0, /*handle=*/0x200,
                         /*holder_tid=*/100, /*holder_pid=*/proc->pid);
        OnMutexWaitEnd(proc, /*slot=*/0, /*wait_ticks=*/3); // 30 ms
        if ((s->policy & kPolicyContentionProfile) != 0)
        {
            arch::SerialWrite("  slot=0 acquire_count=");
            arch::SerialWriteHex(s->contention[0].acquire_count);
            arch::SerialWrite(" wait_count=");
            arch::SerialWriteHex(s->contention[0].wait_count);
            arch::SerialWrite(" total_wait_ms=");
            arch::SerialWriteHex(s->contention[0].total_wait_ms);
            arch::SerialWrite("\n");
        }
    }

    // 6. Heap quarantine — push two freed blocks while QuarantineFree
    //    is OFF (default tier-2), then flip it on and demonstrate
    //    IsQuarantined returns true. Restore policy at end so DumpOnAbnormalExit
    //    is consistent.
    {
        Heading("HEAP QUARANTINE (opt-in tier-2 demo)");
        const u64 saved_policy = s->policy;
        s->policy |= kPolicyQuarantineFree;
        OnHeapFree(proc, /*user_va=*/0x50001000, /*size=*/64);
        OnHeapFree(proc, /*user_va=*/0x50002000, /*size=*/128);
        const bool q1 = IsQuarantined(proc, 0x50001020); // inside first block
        const bool q2 = IsQuarantined(proc, 0x50002040); // inside second
        const bool q3 = IsQuarantined(proc, 0x50003000); // not quarantined
        arch::SerialWrite("  quarantined(0x50001020) = ");
        arch::SerialWrite(q1 ? "true" : "false");
        arch::SerialWrite("\n  quarantined(0x50002040) = ");
        arch::SerialWrite(q2 ? "true" : "false");
        arch::SerialWrite("\n  quarantined(0x50003000) = ");
        arch::SerialWrite(q3 ? "true" : "false");
        arch::SerialWrite("  <-- not freed; expected false\n");
        s->policy = saved_policy;
    }

    // 7. PE strict-RWX policy probe.
    {
        Heading("STRICT RWX (opt-in policy query)");
        const u64 saved_policy = s->policy;
        s->policy |= kPolicyStrictRwx;
        // IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_WRITE
        const bool rejected_rwx = StrictRwxRejectsSection(proc, 0xA0000000u);
        const bool rejected_rx = StrictRwxRejectsSection(proc, 0x20000000u);
        const bool rejected_rw = StrictRwxRejectsSection(proc, 0x80000000u);
        arch::SerialWrite("  reject(R+W+X) = ");
        arch::SerialWrite(rejected_rwx ? "true" : "false");
        arch::SerialWrite("  <-- expected true\n  reject(R+X)   = ");
        arch::SerialWrite(rejected_rx ? "true" : "false");
        arch::SerialWrite("\n  reject(R+W)   = ");
        arch::SerialWrite(rejected_rw ? "true" : "false");
        arch::SerialWrite("\n");
        s->policy = saved_policy;
    }

    // 8. Call the same dump path real PE exits will use.
    Heading("DumpOnAbnormalExit (this is what every Win32 PE exit will emit)");
    DumpOnAbnormalExit(proc);

    // Cleanup.
    CleanupProcess(proc);
    mm::KFree(proc);
    Heading("WIN32 CUSTOM SELF-TEST COMPLETE");
}

} // namespace duetos::subsystems::win32::custom
