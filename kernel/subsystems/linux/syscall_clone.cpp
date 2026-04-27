/*
 * Linux clone(2) — v0.
 *
 * Scope: CLONE_THREAD same-AS thread create only. The flag set
 * libc/pthread emits for pthread_create is:
 *
 *   CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND |
 *   CLONE_THREAD | CLONE_SYSVSEM | CLONE_SETTLS |
 *   CLONE_PARENT_SETTID | CLONE_CHILD_CLEARTID
 *
 * We require CLONE_THREAD + CLONE_VM (the two that actually
 * change the kernel-side semantics — same task-group, same AS).
 * Everything else is accepted-but-treated-as-default — the
 * subsystem v0 doesn't yet have the machinery (file-descriptor
 * tables shared by reference, signal-handler arrays shared,
 * SysV-semaphore undo lists, futex wake-on-exit) to honour the
 * remaining flags as anything other than the no-op default that
 * a single-AS / single-fd-table model already implements.
 *
 * Full fork() — separate AS with COW page sharing — and execve()
 * — in-place AS replacement — both stay -ENOSYS in v0 (pending
 * §11.10 follow-ups). Documented as inventory sub-GAPs.
 *
 * Threading model: the new Task shares the calling Process —
 * same caps, same PID (in the Linux task-group sense), same AS,
 * same handles. It gets a fresh kernel stack via SchedCreateUser
 * + a caller-supplied user stack (the `child_stack` arg). On
 * iretq the child sees rax = 0 (matching Linux's "child gets 0
 * from clone"); the parent sees the new task's TID in rax.
 */

#include "subsystems/linux/syscall_internal.h"

#include "arch/x86_64/gdt.h"
#include "arch/x86_64/serial.h"
#include "arch/x86_64/traps.h"
#include "arch/x86_64/usermode.h"
#include "core/panic.h"
#include "cpu/percpu.h"
#include "mm/kheap.h"
#include "mm/paging.h"
#include "proc/process.h"
#include "sched/sched.h"

namespace duetos::subsystems::linux::internal
{

namespace
{

// Hot subset of the Linux clone flag bits we discriminate on.
// CLONE_VM (0x100) + CLONE_THREAD (0x10000) are required;
// CLONE_PARENT_SETTID (0x100000) toggles the *ptid write-back.
constexpr u64 kCloneVm = 0x00000100;
constexpr u64 kCloneThread = 0x00010000;
constexpr u64 kCloneParentSettid = 0x00100000;

// Heap-allocated descriptor handed from DoClone to the kernel-
// side entry function. The entry function reads it, frees it,
// and iretq's into ring 3 — there is no kernel-side return path
// to free it on, so the entry function MUST free before iretq
// (matching Ring3ThreadEntry's contract).
struct LinuxCloneDesc
{
    u64 user_rip; // parent's saved rip (instruction after int 0x80)
    u64 user_rsp; // caller-supplied child_stack
    u64 user_gs_base;
};

[[noreturn]] void LinuxCloneEntry(void* arg)
{
    // Mirror Ring3ThreadEntry's preamble: pin the new task's
    // kernel stack into the TSS (so subsequent syscalls from
    // this ring-3 thread land on the right kernel stack)
    // before iretq.
    const u64 kstack_top = sched::SchedCurrentKernelStackTop();
    if (kstack_top == 0)
        ::duetos::core::Panic("linux/clone", "SchedCurrentKernelStackTop returned 0");
    arch::TssSetRsp0(kstack_top);
    cpu::CurrentCpu()->kernel_rsp = kstack_top;

    if (arg == nullptr)
        ::duetos::core::Panic("linux/clone", "LinuxCloneEntry called with null desc");

    LinuxCloneDesc d = *static_cast<LinuxCloneDesc*>(arg);
    mm::KFree(arg);

    arch::SerialWrite("[linux/clone] task tid=");
    arch::SerialWriteHex(sched::CurrentTaskId());
    arch::SerialWrite(" entering ring 3 rip=");
    arch::SerialWriteHex(d.user_rip);
    arch::SerialWrite(" rsp=");
    arch::SerialWriteHex(d.user_rsp);
    arch::SerialWrite("\n");

    // EnterUserModeThread zeroes every GPR before iretq except
    // rcx (which it loads from the 4th arg). For Linux clone
    // the child must see rax = 0; EnterUserModeThread's
    // xor eax,eax already gives us that. We pass 0 for the
    // rcx arg — Linux syscall ABI doesn't preserve registers
    // across a syscall boundary, so the child sees a clean
    // register file (matches glibc's clone wrapper, which
    // restores any state it needs from the user stack).
    arch::EnterUserModeThread(d.user_rip, d.user_rsp, d.user_gs_base, /*user_rcx=*/0);
}

} // namespace

i64 DoClone(u64 flags, u64 child_stack, u64 ptid_user, u64 ctid_user, u64 tls)
{
    using ::duetos::core::Process;
    (void)ctid_user; // CLONE_CHILD_CLEARTID + futex wake-on-exit not wired in v0
    (void)tls;       // CLONE_SETTLS not wired in v0 (no per-task fs_base ledger)

    Process* proc = core::CurrentProcess();
    if (proc == nullptr)
        return kEPERM;
    if (!core::CapSetHas(proc->caps, core::kCapSpawnThread))
    {
        core::RecordSandboxDenial(core::kCapSpawnThread);
        return kEPERM;
    }

    // Reject anything other than the CLONE_THREAD same-AS path.
    // Full fork (CLONE_THREAD clear) needs AS duplication;
    // that's §11.10 deferred work.
    if ((flags & (kCloneThread | kCloneVm)) != (kCloneThread | kCloneVm))
        return kENOSYS;
    if (child_stack == 0)
        return kEINVAL;
    if ((child_stack & 0xF) != 0)
        return kEINVAL; // x86_64 ABI requires 16-byte stack alignment

    // Parent's saved rip lives on the syscall trap frame.
    // SchedFindUserTrapFrame returns the outermost user→kernel
    // frame for the current task — same helper §11.7 thread-
    // hijack uses to read another task's saved rip / rsp.
    sched::Task* current = sched::CurrentTask();
    arch::TrapFrame* parent_tf = sched::SchedFindUserTrapFrame(current);
    if (parent_tf == nullptr)
        return kEINVAL;

    auto* desc = static_cast<LinuxCloneDesc*>(mm::KMalloc(sizeof(LinuxCloneDesc)));
    if (desc == nullptr)
        return kENOMEM;
    desc->user_rip = parent_tf->rip;
    desc->user_rsp = child_stack;
    desc->user_gs_base = proc->user_gs_base;

    // Retain the process — the new Task shares the AS + caps +
    // handles. The scheduler's reaper drops the refcount when
    // the task hits Dead.
    core::ProcessRetain(proc);

    static char s_name[16] = {'l', 'x', '-', 'c', 'l', 'o', 'n', 'e', 0, 0, 0, 0, 0, 0, 0, 0};
    sched::Task* t = sched::SchedCreateUser(&LinuxCloneEntry, desc, s_name, proc);
    if (t == nullptr)
    {
        mm::KFree(desc);
        // ProcessRetain consumed by SchedCreateUser's denial
        // branch (ProcessRelease there) on nullptr return.
        return kENOMEM;
    }

    const u64 child_tid = sched::TaskId(t);

    // CLONE_PARENT_SETTID — write the new TID through to the
    // caller's *ptid before the parent's syscall returns. If
    // the user pointer is bad we still proceed; the child has
    // been created by the time we'd hit this write, and EFAULT
    // here would leak a thread.
    if ((flags & kCloneParentSettid) != 0 && ptid_user != 0)
    {
        u32 tid_u32 = static_cast<u32>(child_tid);
        (void)mm::CopyToUser(reinterpret_cast<void*>(ptid_user), &tid_u32, sizeof(tid_u32));
    }

    arch::SerialWrite("[linux/clone] parent pid=");
    arch::SerialWriteHex(proc->pid);
    arch::SerialWrite(" -> child tid=");
    arch::SerialWriteHex(child_tid);
    arch::SerialWrite(" stack=");
    arch::SerialWriteHex(child_stack);
    arch::SerialWrite(" flags=");
    arch::SerialWriteHex(flags);
    arch::SerialWrite("\n");

    return static_cast<i64>(child_tid);
}

} // namespace duetos::subsystems::linux::internal
