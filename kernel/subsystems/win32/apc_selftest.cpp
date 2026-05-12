/*
 * Boot self-test for the kernel-resident APC queue.
 *
 * Exercises the (queue → drain → empty) round-trip on a stand-in
 * Process so the wiring is verified before any real PE drives
 * QueueUserAPC / NtQueueApcThread. Unit-test-style: walks the
 * `apc_slots[]` table directly without going through the syscall
 * boundary, so the test runs in any boot phase that already has
 * the kheap online.
 */

#include "subsystems/win32/apc_selftest.h"

#include "arch/x86_64/serial.h"
#include "proc/process.h"

namespace duetos::subsystems::win32
{

namespace
{

// Same shape as DoQueueUserApc's enqueue logic — find a free slot
// and stamp it. The self-test bypasses the syscall layer so it
// can run before SchedInit has assigned a real CurrentTask.
bool EnqueueDirect(::duetos::core::Process* p, u64 tid, u64 pfn, u64 data, u64 arg1 = 0, u64 arg2 = 0)
{
    using ::duetos::core::Process;
    for (u32 i = 0; i < Process::kApcSlotCap; ++i)
    {
        if (p->apc_slots[i].in_use == 0)
        {
            p->apc_slots[i].target_tid = tid;
            p->apc_slots[i].pfn = pfn;
            p->apc_slots[i].data = data;
            p->apc_slots[i].arg1 = arg1;
            p->apc_slots[i].arg2 = arg2;
            p->apc_slots[i].in_use = 1;
            return true;
        }
    }
    return false;
}

bool DrainOneDirect(::duetos::core::Process* p, u64 tid, u64& out_pfn, u64& out_data, u64* out_arg1 = nullptr,
                    u64* out_arg2 = nullptr)
{
    using ::duetos::core::Process;
    for (u32 i = 0; i < Process::kApcSlotCap; ++i)
    {
        if (p->apc_slots[i].in_use != 0 && p->apc_slots[i].target_tid == tid)
        {
            out_pfn = p->apc_slots[i].pfn;
            out_data = p->apc_slots[i].data;
            if (out_arg1 != nullptr)
                *out_arg1 = p->apc_slots[i].arg1;
            if (out_arg2 != nullptr)
                *out_arg2 = p->apc_slots[i].arg2;
            p->apc_slots[i].in_use = 0;
            p->apc_slots[i].pfn = 0;
            p->apc_slots[i].data = 0;
            p->apc_slots[i].arg1 = 0;
            p->apc_slots[i].arg2 = 0;
            p->apc_slots[i].target_tid = 0;
            return true;
        }
    }
    return false;
}

} // namespace

void ApcSelfTest()
{
    using ::duetos::core::Process;

    // Stand-in Process — we only touch apc_slots[], so a stack
    // local zeroed Process struct is enough. Process is large;
    // the explicit zero-init keeps every other field at a known
    // safe value.
    static Process p; // file-scope static to avoid blowing the boot stack
    for (u8* b = reinterpret_cast<u8*>(&p); b < reinterpret_cast<u8*>(&p) + sizeof(Process); ++b)
        *b = 0;

    constexpr u64 kTidA = 1234;
    constexpr u64 kTidB = 5678;
    constexpr u64 kPfnA = 0x4000'1000;
    constexpr u64 kDataA = 0xDEADBEEF;
    constexpr u64 kPfnB = 0x4000'2000;
    constexpr u64 kDataB = 0xCAFEBABE;

    // 1. Empty-queue drain returns nothing.
    u64 pfn = 0, data = 0;
    if (DrainOneDirect(&p, kTidA, pfn, data))
    {
        arch::SerialWrite("[selftest:apc] FAIL empty drain returned data\n");
        return;
    }

    // 2. Enqueue + drain round-trip.
    if (!EnqueueDirect(&p, kTidA, kPfnA, kDataA))
    {
        arch::SerialWrite("[selftest:apc] FAIL enqueue\n");
        return;
    }
    if (!DrainOneDirect(&p, kTidA, pfn, data) || pfn != kPfnA || data != kDataA)
    {
        arch::SerialWrite("[selftest:apc] FAIL drain mismatch\n");
        return;
    }
    if (DrainOneDirect(&p, kTidA, pfn, data))
    {
        arch::SerialWrite("[selftest:apc] FAIL post-drain queue not empty\n");
        return;
    }

    // 3. Cross-tid isolation: enqueue for A, drain on B sees nothing.
    if (!EnqueueDirect(&p, kTidA, kPfnA, kDataA))
    {
        arch::SerialWrite("[selftest:apc] FAIL enqueue B-iso\n");
        return;
    }
    if (DrainOneDirect(&p, kTidB, pfn, data))
    {
        arch::SerialWrite("[selftest:apc] FAIL cross-tid drain leaked\n");
        return;
    }
    // Drain on A clears it.
    DrainOneDirect(&p, kTidA, pfn, data);

    // 4. Capacity check — fill the queue, then verify the
    //    (kApcSlotCap + 1)-th enqueue fails.
    for (u32 i = 0; i < Process::kApcSlotCap; ++i)
    {
        if (!EnqueueDirect(&p, kTidA, kPfnA + i, kDataA + i))
        {
            arch::SerialWrite("[selftest:apc] FAIL fill enqueue\n");
            return;
        }
    }
    if (EnqueueDirect(&p, kTidA, kPfnB, kDataB))
    {
        arch::SerialWrite("[selftest:apc] FAIL overcapacity enqueue accepted\n");
        return;
    }

    // Drain everything and verify ordering by registration.
    for (u32 i = 0; i < Process::kApcSlotCap; ++i)
    {
        if (!DrainOneDirect(&p, kTidA, pfn, data) || pfn != kPfnA + i || data != kDataA + i)
        {
            arch::SerialWrite("[selftest:apc] FAIL ordered drain mismatch\n");
            return;
        }
    }

    // 5. Nt-style 3-arg APC: enqueue with NormalContext / SA1 / SA2;
    //    confirm the drain path round-trips all three. This covers
    //    NtQueueApcThread's three-arg shape that QueueUserAPC's
    //    single-ulData wrapper does not.
    constexpr u64 kArg1 = 0x1111'2222'3333'4444ull;
    constexpr u64 kArg2 = 0x5555'6666'7777'8888ull;
    if (!EnqueueDirect(&p, kTidA, kPfnA, kDataA, kArg1, kArg2))
    {
        arch::SerialWrite("[selftest:apc] FAIL enqueue 3-arg\n");
        return;
    }
    u64 got_arg1 = 0;
    u64 got_arg2 = 0;
    if (!DrainOneDirect(&p, kTidA, pfn, data, &got_arg1, &got_arg2) || pfn != kPfnA || data != kDataA ||
        got_arg1 != kArg1 || got_arg2 != kArg2)
    {
        arch::SerialWrite("[selftest:apc] FAIL 3-arg drain mismatch\n");
        return;
    }
    if (DrainOneDirect(&p, kTidA, pfn, data, &got_arg1, &got_arg2))
    {
        arch::SerialWrite("[selftest:apc] FAIL post-3arg-drain queue not empty\n");
        return;
    }

    arch::SerialWrite("[selftest:apc] ok; queue+drain+isolation+capacity+sa1sa2\n");
}

} // namespace duetos::subsystems::win32
