#include "thread_syscall.h"

#include "../../arch/x86_64/gdt.h"
#include "../../arch/x86_64/serial.h"
#include "../../arch/x86_64/traps.h"
#include "../../arch/x86_64/usermode.h"
#include "../../cpu/percpu.h"
#include "../../core/klog.h"
#include "../../core/panic.h"
#include "../../core/process.h"
#include "../../core/syscall.h"
#include "../../mm/address_space.h"
#include "../../mm/frame_allocator.h"
#include "../../mm/kheap.h"
#include "../../mm/page.h"
#include "../../mm/paging.h"
#include "../../sched/sched.h"
#include "stubs.h"

namespace customos::subsystems::win32
{

namespace
{

// Handed from DoThreadCreate to Ring3ThreadEntry via the Task's
// `arg`. Kernel-heap allocated; the entry function reads and
// frees it before iretq. Frees on the same path on any early-
// return too (the Task is then flagged dead).
struct ThreadDesc
{
    u64 start_va;     // ring-3 RIP
    u64 param;        // goes into rcx (Win32 x64 first arg)
    u64 user_rsp;     // ring-3 RSP (stack_top - 8 for shadow alignment)
    u64 user_gs_base; // usually the Process's shared TEB VA (v0 scope)
};

} // namespace

[[noreturn]] void Ring3ThreadEntry(void* arg)
{
    using arch::SerialWrite;
    using arch::SerialWriteHex;

    const u64 kstack_top = sched::SchedCurrentKernelStackTop();
    if (kstack_top == 0)
        ::customos::core::Panic("win32/thread", "SchedCurrentKernelStackTop returned 0");
    arch::TssSetRsp0(kstack_top);
    cpu::CurrentCpu()->kernel_rsp = kstack_top;

    if (arg == nullptr)
        ::customos::core::Panic("win32/thread", "Ring3ThreadEntry called with null desc");

    // Copy onto the stack then free the heap allocation — the
    // iretq below doesn't return, so deferring the free to the
    // task's teardown would leak.
    ThreadDesc d;
    d.start_va = static_cast<ThreadDesc*>(arg)->start_va;
    d.param = static_cast<ThreadDesc*>(arg)->param;
    d.user_rsp = static_cast<ThreadDesc*>(arg)->user_rsp;
    d.user_gs_base = static_cast<ThreadDesc*>(arg)->user_gs_base;
    mm::KFree(arg);

    SerialWrite("[thread] task pid=");
    SerialWriteHex(sched::CurrentTaskId());
    SerialWrite(" entering ring 3 rip=");
    SerialWriteHex(d.start_va);
    SerialWrite(" rsp=");
    SerialWriteHex(d.user_rsp);
    SerialWrite(" param(rcx)=");
    SerialWriteHex(d.param);
    if (d.user_gs_base != 0)
    {
        SerialWrite(" gs_base=");
        SerialWriteHex(d.user_gs_base);
    }
    SerialWrite("\n");

    // Hand off to the 4-arg asm entry that preserves rcx through
    // the iretq (SYS_THREAD_CREATE contract: thread proc sees the
    // caller-supplied param in rcx per Win32 x64 ABI).
    arch::EnterUserModeThread(d.start_va, d.user_rsp, d.user_gs_base, d.param);
}

void DoThreadCreate(arch::TrapFrame* frame)
{
    using arch::SerialWrite;
    using arch::SerialWriteHex;
    using ::customos::core::Process;

    core::Process* proc = core::CurrentProcess();
    if (proc == nullptr || !core::CapSetHas(proc->caps, core::kCapSpawnThread))
    {
        const u64 pid = (proc != nullptr) ? proc->pid : 0;
        core::RecordSandboxDenial(core::kCapSpawnThread);
        if (proc != nullptr && core::ShouldLogDenial(proc->sandbox_denials))
        {
            SerialWrite("[sys] denied syscall=SYS_THREAD_CREATE pid=");
            SerialWriteHex(pid);
            SerialWrite(" cap=");
            SerialWrite(core::CapName(core::kCapSpawnThread));
            SerialWrite("\n");
        }
        frame->rax = static_cast<u64>(-1);
        return;
    }

    const u64 start_va = frame->rdi;
    const u64 param = frame->rsi;

    // Basic input validation. start_va must be non-zero and in
    // the user half of the canonical VA range (we enforce the
    // latter by requiring the high bit unset — the full
    // canonical-form check is the paging layer's problem and
    // would catch any truly wild value on the first #PF).
    if (start_va == 0 || (start_va & (1ULL << 63)) != 0)
    {
        frame->rax = static_cast<u64>(-1);
        return;
    }

    // Find a free thread-table slot.
    u32 slot = Process::kWin32ThreadCap;
    for (u32 i = 0; i < Process::kWin32ThreadCap; ++i)
    {
        if (!proc->win32_threads[i].in_use)
        {
            slot = i;
            break;
        }
    }
    if (slot == Process::kWin32ThreadCap)
    {
        SerialWrite("[thread] create out-of-handles pid=");
        SerialWriteHex(proc->pid);
        SerialWrite("\n");
        frame->rax = static_cast<u64>(-1);
        return;
    }

    // Carve a fresh stack range off the process's thread-stack
    // cursor. N pages, writable + NX + user. Stack grows down,
    // so rsp starts at (base + N*4096 - 8).
    const u64 stack_base_va = proc->thread_stack_cursor;
    const u64 stack_pages = Process::kV0ThreadStackPages;
    mm::PhysAddr top_frame_phys = mm::kNullFrame;
    for (u64 p = 0; p < stack_pages; ++p)
    {
        const mm::PhysAddr frame_phys = mm::AllocateFrame();
        if (frame_phys == mm::kNullFrame)
        {
            SerialWrite("[thread] create FAIL stack frame alloc idx=");
            SerialWriteHex(p);
            SerialWrite("\n");
            frame->rax = static_cast<u64>(-1);
            return;
        }
        const u64 page_va = stack_base_va + p * mm::kPageSize;
        mm::AddressSpaceMapUserPage(proc->as, page_va, frame_phys,
                                    mm::kPagePresent | mm::kPageUser | mm::kPageWritable | mm::kPageNoExecute);
        if (p == stack_pages - 1)
            top_frame_phys = frame_phys;
    }
    proc->thread_stack_cursor += stack_pages * mm::kPageSize;
    const u64 stack_top = stack_base_va + stack_pages * mm::kPageSize;
    // Microsoft x64 ABI: rsp % 16 == 8 on function entry. The
    // iretq into ring-3 doesn't push a return address, so we
    // bias rsp by -8 before entry — same pattern as the main
    // Ring3UserEntry path.
    const u64 user_rsp = stack_top - 8;

    // Plant the thread-exit trampoline VA at [user_rsp]. When the
    // thread proc returns, `ret` pops this value into rip and the
    // trampoline issues SYS_EXIT(retcode). Without this the thread
    // would `ret` into rip=0 and eat a #PF. We write via the
    // direct-map image of the top stack frame — the page isn't
    // mapped into any AS we currently own a CR3 for, but the
    // direct-map gives every frame a kernel-writable alias.
    auto* top_page_kva = static_cast<u8*>(mm::PhysToVirt(top_frame_phys));
    auto* retaddr_slot = reinterpret_cast<u64*>(top_page_kva + mm::kPageSize - 8);
    *retaddr_slot = ::customos::win32::kWin32ThreadExitTrampVa;

    // Build the kernel-heap ThreadDesc that Ring3ThreadEntry
    // will consume. Heap-allocated so the ring-0 stack frame
    // for this syscall can be freed before the new Task runs.
    auto* desc = static_cast<ThreadDesc*>(mm::KMalloc(sizeof(ThreadDesc)));
    if (desc == nullptr)
    {
        SerialWrite("[thread] create FAIL heap alloc for ThreadDesc\n");
        frame->rax = static_cast<u64>(-1);
        return;
    }
    desc->start_va = start_va;
    desc->param = param;
    desc->user_rsp = user_rsp;
    desc->user_gs_base = proc->user_gs_base;

    // Retain the process so the new Task can share it. The
    // scheduler Task will release on death via the reaper — same
    // contract as SchedCreateUser's documented caller discipline.
    core::ProcessRetain(proc);

    // Name: short thread label. Pin to the process's pid + slot
    // for debugging; a real Win32 caller would pass a name via
    // SetThreadDescription, which is a future syscall.
    static char s_name[32] = {};
    // Open-coded "thread-<pid>-<slot>" — avoid dragging a
    // full sprintf in just for this.
    u32 nlen = 0;
    const char* prefix = "thread-";
    for (u32 i = 0; prefix[i] != '\0' && nlen < sizeof(s_name) - 1; ++i, ++nlen)
        s_name[nlen] = prefix[i];
    // lowercase hex digits for pid + slot, 2 hex each — the
    // debugger + logs only need to disambiguate small counts.
    auto hexd = [&](u8 v)
    {
        const char table[] = "0123456789abcdef";
        if (nlen < sizeof(s_name) - 1)
            s_name[nlen++] = table[(v >> 4) & 0xF];
        if (nlen < sizeof(s_name) - 1)
            s_name[nlen++] = table[v & 0xF];
    };
    hexd(static_cast<u8>(proc->pid & 0xFF));
    if (nlen < sizeof(s_name) - 1)
        s_name[nlen++] = '-';
    hexd(static_cast<u8>(slot));
    s_name[nlen] = '\0';

    sched::Task* t = sched::SchedCreateUser(&Ring3ThreadEntry, desc, s_name, proc);
    if (t == nullptr)
    {
        SerialWrite("[thread] create FAIL SchedCreateUser\n");
        mm::KFree(desc);
        // ProcessRetain was consumed by SchedCreateUser's
        // gate-denial branch (ProcessRelease there) on nullptr
        // return. No manual release here — see sched.cpp.
        frame->rax = static_cast<u64>(-1);
        return;
    }

    proc->win32_threads[slot].in_use = true;
    proc->win32_threads[slot].task = t;
    proc->win32_threads[slot].user_stack_va = stack_base_va;

    const u64 handle = Process::kWin32ThreadBase + slot;
    SerialWrite("[thread] create ok pid=");
    SerialWriteHex(proc->pid);
    SerialWrite(" slot=");
    SerialWriteHex(slot);
    SerialWrite(" handle=");
    SerialWriteHex(handle);
    SerialWrite(" start=");
    SerialWriteHex(start_va);
    SerialWrite(" stack_base=");
    SerialWriteHex(stack_base_va);
    SerialWrite("\n");
    frame->rax = handle;
}

} // namespace customos::subsystems::win32
