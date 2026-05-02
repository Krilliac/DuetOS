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
#include "subsystems/linux/fanotify.h"
#include "subsystems/linux/inotify.h"
#include "subsystems/linux/syscall_async_io.h"
#include "subsystems/linux/syscall_pipe.h"
#include "subsystems/linux/syscall_socket.h"

#include "arch/x86_64/gdt.h"
#include "arch/x86_64/serial.h"
#include "arch/x86_64/traps.h"
#include "arch/x86_64/usermode.h"
#include "core/panic.h"
#include "cpu/percpu.h"
#include "mm/kheap.h"
#include "mm/paging.h"
#include "proc/process.h"
#include "util/string.h"
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
    {
        // See win32 Ring3ThreadEntry for the rationale: debug
        // hard-panics; release frees the descriptor and routes
        // this single task to SchedExit, leaving the rest of the
        // kernel running.
        ::duetos::core::DebugPanicOrWarn("linux/clone", "SchedCurrentKernelStackTop returned 0");
        if (arg != nullptr)
        {
            mm::KFree(arg);
        }
        sched::SchedExit();
    }
    arch::TssSetRsp0(kstack_top);
    cpu::CurrentCpu()->kernel_rsp = kstack_top;

    if (arg == nullptr)
    {
        ::duetos::core::DebugPanicOrWarn("linux/clone", "LinuxCloneEntry called with null desc");
        sched::SchedExit();
    }

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

i64 DoFork()
{
    using ::duetos::core::Process;
    Process* parent = core::CurrentProcess();
    if (parent == nullptr)
        return kEPERM;
    if (!core::CapSetHas(parent->caps, core::kCapSpawnThread))
    {
        core::RecordSandboxDenial(core::kCapSpawnThread);
        return kEPERM;
    }
    // RLIMIT_NPROC: refuse if the parent's live-child count
    // would exceed the soft cap. Sentinel 0xFF... means "no cap
    // below kernel ceiling" — skip the check and let the
    // ProcessCreate-side limit (MAX_SCHED_TASKS) apply.
    if (parent->linux_rlimit_nproc_cur != 0xFFFFFFFFFFFFFFFFull)
    {
        const u64 children = sched::SchedCountChildrenOfPid(parent->pid);
        if (children >= parent->linux_rlimit_nproc_cur)
            return kEAGAIN;
    }
    sched::Task* current = sched::CurrentTask();
    arch::TrapFrame* parent_tf = sched::SchedFindUserTrapFrame(current);
    if (parent_tf == nullptr)
        return kEINVAL;

    // Allocate child AS as a deep copy of the parent. Pages are
    // duplicated frame-by-frame with parent PTE flags preserved
    // (W^X stays intact). No COW yet — sub-GAP.
    mm::AddressSpace* child_as = mm::AddressSpaceFork(parent->as);
    if (child_as == nullptr)
        return kENOMEM;

    // Build the child Process. Inherit caps, root, code_va,
    // stack_va, tick_budget. fd table + win32 handle tables
    // start fresh — fd inheritance + CLOEXEC handling deferred.
    Process* child = core::ProcessCreate(parent->name, child_as, parent->caps, parent->root, parent->user_code_va,
                                         parent->user_stack_va, parent->tick_budget);
    if (child == nullptr)
    {
        mm::AddressSpaceRelease(child_as);
        return kENOMEM;
    }
    child->abi_flavor = parent->abi_flavor;
    child->user_gs_base = parent->user_gs_base;
    child->linux_brk_base = parent->linux_brk_base;
    child->linux_brk_current = parent->linux_brk_current;
    child->linux_mmap_cursor = parent->linux_mmap_cursor;
    // Establish the parent-pid linkage so the child's eventual exit
    // path (in ProcessRelease) finds this Process and pushes onto
    // the linux_wait_wq for any in-flight wait4 caller.
    child->linux_parent_pid = parent->pid;

    // fd inheritance — every parent fd survives into the child.
    // Linux semantics: dup() shares the file description; we
    // approximate by copying the slot verbatim and bumping
    // refcounts on pool-backed states (pipe / eventfd / socket)
    // so the kernel object outlives the parent's close().
    // FAT32 file handles share first_cluster + path but track
    // their own per-fd offset — copying the slot achieves that.
    // CLOEXEC is a sub-GAP; every fd survives unconditionally.
    for (u32 i = 0; i < 16; ++i)
    {
        const auto& src = parent->linux_fds[i];
        child->linux_fds[i] = src;
        if (src.state == 3)
            PipeRetainRead(src.first_cluster);
        else if (src.state == 4)
            PipeRetainWrite(src.first_cluster);
        else if (src.state == 5)
            EventfdRetain(src.first_cluster);
        else if (src.state == 6)
            SocketFdRetain(src.first_cluster);
        else if (src.state == 7)
            TimerfdRetain(src.first_cluster);
        else if (src.state == 8)
            SignalfdRetain(src.first_cluster);
        else if (src.state == 9)
            EpollRetain(src.first_cluster);
        else if (src.state == 10)
            InotifyRetain(src.first_cluster);
        else if (src.state == 11)
        {
            // Directory snapshot lives on the PARENT's
            // win32_dirs[] table. The child's table is fresh
            // and empty; sharing the parent's slot index would
            // leave the child's fd dangling. Skip inheritance —
            // the child's dirfd slot is cleared so getdents64
            // sees an honest -EBADF rather than reading the
            // wrong slot. (POSIX permits closing dirfds on
            // fork — same as what some libcs do under
            // FD_CLOEXEC; our v0 just makes it unconditional.)
            child->linux_fds[i].state = 0;
            child->linux_fds[i].first_cluster = 0;
            child->linux_fds[i].size = 0;
            child->linux_fds[i].offset = 0;
        }
        else if (src.state == 12)
        {
            // pidfd: bump the target Process refcount so the
            // child holds an independent reference. The child's
            // close path will release.
            core::Process* tgt = sched::SchedFindProcessByPid(src.first_cluster);
            if (tgt != nullptr)
                core::ProcessRetain(tgt);
        }
        else if (src.state == 13)
            PosixMqRetain(src.first_cluster);
        else if (src.state == 14)
            MemfdRetain(src.first_cluster);
        else if (src.state == 15)
            FanotifyRetain(src.first_cluster);
    }
    // Hand a LinuxCloneDesc to the existing LinuxCloneEntry —
    // it iretq's into ring-3 with rax = 0 (EnterUserModeThread's
    // built-in scrub), exactly the contract Linux fork wants for
    // the child.
    auto* desc = static_cast<LinuxCloneDesc*>(mm::KMalloc(sizeof(LinuxCloneDesc)));
    if (desc == nullptr)
    {
        // Process is mid-flight; release it. ProcessRelease does
        // the AS release transitively.
        core::ProcessRelease(child);
        return kENOMEM;
    }
    // Zero-init: KMalloc returns 0xDE-poisoned bytes; any field
    // not assigned below would carry the poison. Same pattern as
    // ProcessCreate / SchedCreateInternal / AddressSpaceCreate.
    // See .claude/knowledge/kmalloc-zero-init-pattern.md.
    memset(desc, 0, sizeof(LinuxCloneDesc));
    desc->user_rip = parent_tf->rip;
    desc->user_rsp = parent_tf->rsp;
    desc->user_gs_base = parent->user_gs_base;

    static char s_name[16] = {'l', 'x', '-', 'f', 'o', 'r', 'k', 0};
    sched::Task* t = sched::SchedCreateUser(&LinuxCloneEntry, desc, s_name, child);
    if (t == nullptr)
    {
        mm::KFree(desc);
        core::ProcessRelease(child);
        return kENOMEM;
    }

    arch::SerialWrite("[linux/fork] parent pid=");
    arch::SerialWriteHex(parent->pid);
    arch::SerialWrite(" -> child pid=");
    arch::SerialWriteHex(child->pid);
    arch::SerialWrite("\n");
    return static_cast<i64>(child->pid);
}

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
    // Zero-init — see .claude/knowledge/kmalloc-zero-init-pattern.md.
    memset(desc, 0, sizeof(LinuxCloneDesc));
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

// =============================================================
// clone3 — extended clone with the args bundled in a struct
// `clone_args`. Translate the new shape into the classic
// 5-arg clone() and let DoClone do the work.
//
// struct clone_args (Linux 5.3+, first 8 fields = 64 bytes):
//   u64 flags
//   u64 pidfd               (out, ignored in v0)
//   u64 child_tid           (CLONE_CHILD_SETTID)
//   u64 parent_tid          (CLONE_PARENT_SETTID)
//   u64 exit_signal
//   u64 stack
//   u64 stack_size
//   u64 tls
//
// Newer fields (set_tid, set_tid_size, cgroup) are advisory
// extensions ignored here.
// =============================================================

i64 DoClone3(u64 user_args, u64 size)
{
    constexpr u64 kMinSize = 64;
    if (user_args == 0 || size < kMinSize)
        return kEINVAL;

    struct CloneArgs
    {
        u64 flags;
        u64 pidfd;
        u64 child_tid;
        u64 parent_tid;
        u64 exit_signal;
        u64 stack;
        u64 stack_size;
        u64 tls;
    } args = {};

    const u64 to_copy = size < sizeof(args) ? size : sizeof(args);
    if (!mm::CopyFromUser(&args, reinterpret_cast<const void*>(user_args), to_copy))
        return kEFAULT;

    // Classic clone wants child_stack as the TOP of the new
    // stack region. clone3 gives stack base + stack_size; the
    // top is stack + stack_size by Linux convention.
    const u64 child_stack = args.stack + args.stack_size;
    return DoClone(args.flags, child_stack, args.parent_tid, args.child_tid, args.tls);
}

} // namespace duetos::subsystems::linux::internal
