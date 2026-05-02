/*
 * Linux pidfd family + zero-copy fd-to-fd plumbing.
 *
 * pidfd_open / pidfd_send_signal / pidfd_getfd are the modern
 * race-free signaling API. v0 implementation: a pidfd is a
 * LinuxFd (state 12) that pins a target Process via
 * ProcessRetain at open and drops the ref at close. Read /
 * write reject pidfds with EBADF (the only operation Linux
 * supports on a pidfd is poll/epoll for "process exited" and
 * pidfd_send_signal — v0 supports the send_signal path; the
 * exit-poll integration is a sub-GAP).
 *
 * splice / tee / vmsplice route bytes between fds without a
 * userland round-trip. v0 bounces through a 1 KiB on-stack
 * buffer (still kernel-bound, so the userland savings are
 * real: no second SYS_READ + SYS_WRITE pair). True zero-copy
 * page-grant would require a per-pipe page-lending model,
 * which is its own slice — sub-GAP.
 */

#include "subsystems/linux/inotify.h"
#include "subsystems/linux/syscall_async_io.h"
#include "subsystems/linux/syscall_internal.h"
#include "subsystems/linux/syscall_pipe.h"
#include "subsystems/linux/syscall_socket.h"

#include "arch/x86_64/cpu.h"
#include "arch/x86_64/serial.h"
#include "mm/paging.h"
#include "proc/process.h"
#include "sched/sched.h"

namespace duetos::subsystems::linux::internal
{

namespace
{

// Pidfd allocation pool. Per-process instead of a global pool —
// each pidfd needs to live in the caller's linux_fds[] slot table
// and pin ITS view of the target. The first_cluster slot of the
// LinuxFd carries the target PID; ProcessRetain is performed on
// the live Process at open time and Released at close.
//
// Zero-copy claim: NOT pidfds — those don't transfer pages, they
// just hold a process handle. The "zero-copy" comment lives on
// splice/tee/vmsplice below.

i32 FindFreeLinuxFd(core::Process* p)
{
    if (p == nullptr)
        return -1;
    for (u32 i = 3; i < LinuxFdEffectiveMax(p); ++i)
        if (p->linux_fds[i].state == 0)
            return static_cast<i32>(i);
    return -1;
}

} // namespace

// Global pidfd-exit waitqueue (§ syscall_internal.h LinuxPidfdExitWake).
// Lives in this TU because pidfd is the canonical surface that needs
// it; everything else (epoll_wait, DoExitGroup) reaches it through
// the LinuxPidfdExitWake() / LinuxProcessHasPidfd() helpers.
namespace
{
sched::WaitQueue g_pidfd_exit_wq{};
} // namespace

void LinuxPidfdExitWake()
{
    sched::WaitQueueWakeAll(&g_pidfd_exit_wq);
}

bool LinuxProcessHasPidfd(const core::Process* p)
{
    if (p == nullptr)
        return false;
    for (u32 i = 3; i < 16; ++i)
        if (p->linux_fds[i].state == 12)
            return true;
    return false;
}

sched::WaitQueue* LinuxPidfdExitWq()
{
    return &g_pidfd_exit_wq;
}

// =========================================================
// pidfd_open / pidfd_send_signal
// =========================================================

i64 DoPidfdOpen(u64 pid, u64 flags)
{
    (void)flags; // PIDFD_NONBLOCK accepted but ignored
    // pid==0 is invalid in pidfd_open (real Linux returns
    // -EINVAL since "self" is not addressable that way; the
    // documented "no pid" sentinel for pidfd_open is just
    // bad-input).
    if (static_cast<i64>(pid) <= 0)
        return kEINVAL;
    core::Process* caller = core::CurrentProcess();
    if (caller == nullptr)
        return kEPERM;
    core::Process* target = sched::SchedFindProcessByPid(pid);
    if (target == nullptr)
        return kESRCH;
    const i32 fd = FindFreeLinuxFd(caller);
    if (fd < 0)
        return kEMFILE;
    core::ProcessRetain(target);
    caller->linux_fds[fd].state = 12;
    caller->linux_fds[fd].first_cluster = static_cast<u32>(pid);
    caller->linux_fds[fd].size = 0;
    caller->linux_fds[fd].offset = 0;
    caller->linux_fds[fd].path[0] = '\0';
    arch::SerialWrite("[linux/pidfd] open fd=");
    arch::SerialWriteHex(static_cast<u64>(fd));
    arch::SerialWrite(" target_pid=");
    arch::SerialWriteHex(pid);
    arch::SerialWrite("\n");
    return static_cast<i64>(fd);
}

i64 DoPidfdSendSignal(u64 pidfd, u64 sig, u64 user_info, u64 flags)
{
    (void)user_info; // siginfo_t payload not honoured (v0 carries only signum)
    (void)flags;
    core::Process* caller = core::CurrentProcess();
    if (caller == nullptr || pidfd >= 16 || caller->linux_fds[pidfd].state != 12)
        return kEBADF;
    const u64 target_pid = caller->linux_fds[pidfd].first_cluster;
    core::Process* target = sched::SchedFindProcessByPid(target_pid);
    if (target == nullptr)
        return kESRCH; // target may have already exited
    return LinuxSignalDeliver(target, static_cast<u32>(sig));
}

// pidfd_getfd(pidfd, target_fd, flags) — dup an fd from a target
// process into the caller's fd table. v0 implementation supports
// pool-backed states (pipe / eventfd / socket / timerfd / signalfd /
// epoll / inotify / pidfd / mq) by copying the slot verbatim and
// bumping the corresponding refcount. Regular files (state 2) and
// directories (state 11) and memfd (state 14) are not currently
// shareable across processes — sub-GAP. Cap-gated on kCapDebug
// (cross-process fd inspection is the same threat class as
// PROCESS_VM_READ).
i64 DoPidfdGetfd(u64 pidfd, u64 target_fd, u64 flags)
{
    (void)flags;
    using ::duetos::core::CapSetHas;
    using ::duetos::core::kCapDebug;
    core::Process* caller = core::CurrentProcess();
    if (caller == nullptr || pidfd >= 16 || caller->linux_fds[pidfd].state != 12)
        return kEBADF;
    if (!CapSetHas(caller->caps, kCapDebug))
    {
        core::RecordSandboxDenial(kCapDebug);
        return kEPERM;
    }
    const u64 target_pid = caller->linux_fds[pidfd].first_cluster;
    core::Process* target = sched::SchedFindProcessByPid(target_pid);
    if (target == nullptr)
        return kESRCH;
    if (target_fd >= 16 || target->linux_fds[target_fd].state == 0)
        return kEBADF;

    // Find a free slot in caller's table.
    i32 caller_slot = -1;
    for (u32 i = 3; i < LinuxFdEffectiveMax(caller); ++i)
        if (caller->linux_fds[i].state == 0)
        {
            caller_slot = static_cast<i32>(i);
            break;
        }
    if (caller_slot < 0)
        return kEMFILE;

    const auto& src = target->linux_fds[target_fd];
    const u8 state = src.state;
    // Refuse states that aren't safe to share across processes.
    if (state == 2 || state == 11 || state == 14)
        return kEINVAL; // regular file / dirfd / memfd
    // Copy slot verbatim and bump the relevant refcount.
    caller->linux_fds[caller_slot] = src;
    if (state == 3)
        PipeRetainRead(src.first_cluster);
    else if (state == 4)
        PipeRetainWrite(src.first_cluster);
    else if (state == 5)
        EventfdRetain(src.first_cluster);
    else if (state == 6)
        SocketFdRetain(src.first_cluster);
    else if (state == 7)
        TimerfdRetain(src.first_cluster);
    else if (state == 8)
        SignalfdRetain(src.first_cluster);
    else if (state == 9)
        EpollRetain(src.first_cluster);
    else if (state == 10)
        InotifyRetain(src.first_cluster);
    else if (state == 12)
    {
        // pidfd: the pid in first_cluster is independent of the
        // target's reference; bump our own retain.
        core::Process* tgt = sched::SchedFindProcessByPid(src.first_cluster);
        if (tgt != nullptr)
            core::ProcessRetain(tgt);
    }
    else if (state == 13)
        PosixMqRetain(src.first_cluster);
    arch::SerialWrite("[linux/pidfd_getfd] caller=");
    arch::SerialWriteHex(caller->pid);
    arch::SerialWrite(" target=");
    arch::SerialWriteHex(target_pid);
    arch::SerialWrite(" target_fd=");
    arch::SerialWriteHex(target_fd);
    arch::SerialWrite(" caller_fd=");
    arch::SerialWriteHex(static_cast<u64>(caller_slot));
    arch::SerialWrite("\n");
    return static_cast<i64>(caller_slot);
}

// Called from syscall_file.cpp's DoClose state==12 arm.
void PidfdRelease(core::Process* p, u64 target_pid)
{
    if (p == nullptr)
        return;
    core::Process* target = sched::SchedFindProcessByPid(target_pid);
    if (target != nullptr)
        core::ProcessRelease(target);
    // If target is already gone, no ref to drop — exited tasks
    // already released their own refs through the reaper.
}

// =========================================================
// splice / tee / vmsplice — v0 bounce-buffer impls
// =========================================================

// splice / tee / vmsplice — kernel-bypass byte movement.
//
// v0 covers the highest-leverage shape: pipe→pipe transfer
// without leaving the kernel. PipeSpliceFromPipe / PipeTeeFromPipe
// (kernel/subsystems/linux/syscall_pipe.cpp) walk the pool rings
// directly — no CopyToUser/CopyFromUser bounce, no userland
// scratch buffer, no read+write loop the caller has to drive.
// The single-iteration shape matches Linux's contract: one call
// moves at most one transfer's worth of bytes; loops live in the
// caller.
//
// Sub-GAPs (returned as -EINVAL so library fallbacks engage):
//   - file ↔ pipe paths (would need FAT32 read/write integration)
//   - true page-grant zero-copy (vmsplice with SPLICE_F_GIFT)
//   - SPLICE_F_NONBLOCK / SPLICE_F_MOVE / SPLICE_F_MORE flags
//     (accepted but ignored — splice is already non-blocking on
//     dst-full and blocks once on src-empty exactly like
//     PipeRead, which is the practical "blocking" mode anyway).
//   - splice with explicit offsets (for file ends only — fails
//     -EINVAL with pipe ends as Linux does).
i64 DoSplice(u64 fd_in, u64 user_off_in, u64 fd_out, u64 user_off_out, u64 len, u64 flags)
{
    (void)flags;
    core::Process* p = core::CurrentProcess();
    if (p == nullptr || fd_in >= 16 || fd_out >= 16)
        return kEBADF;
    if (p->linux_fds[fd_in].state == 0 || p->linux_fds[fd_out].state == 0)
        return kEBADF;
    if (len == 0)
        return 0;
    // pipe→pipe fast path: source is a pipe-read end (state 3),
    // destination is a pipe-write end (state 4). Linux requires
    // pipes don't take an offset — non-null user_off_* with a pipe
    // is -ESPIPE.
    const u32 in_state = p->linux_fds[fd_in].state;
    const u32 out_state = p->linux_fds[fd_out].state;
    if (in_state == 3 && out_state == 4)
    {
        if (user_off_in != 0 || user_off_out != 0)
            return -29; // -ESPIPE
        const u32 src_idx = p->linux_fds[fd_in].first_cluster;
        const u32 dst_idx = p->linux_fds[fd_out].first_cluster;
        return PipeSpliceFromPipe(dst_idx, src_idx, len);
    }
    // file ↔ pipe paths — sub-GAP. Library fallbacks catch
    // -EINVAL and retry through read+write.
    return kEINVAL;
}

i64 DoTee(u64 fd_in, u64 fd_out, u64 len, u64 flags)
{
    (void)flags;
    core::Process* p = core::CurrentProcess();
    if (p == nullptr || fd_in >= 16 || fd_out >= 16)
        return kEBADF;
    // tee requires both ends to be pipes per Linux. Source is the
    // read end (state 3), destination is the write end (state 4).
    if (p->linux_fds[fd_in].state != 3 || p->linux_fds[fd_out].state != 4)
        return kEINVAL;
    if (len == 0)
        return 0;
    const u32 src_idx = p->linux_fds[fd_in].first_cluster;
    const u32 dst_idx = p->linux_fds[fd_out].first_cluster;
    return PipeTeeFromPipe(dst_idx, src_idx, len);
}

i64 DoVmsplice(u64 fd, u64 user_iov, u64 nr_segs, u64 flags)
{
    (void)flags;
    core::Process* p = core::CurrentProcess();
    if (p == nullptr || fd >= 16)
        return kEBADF;
    // vmsplice writes iovec → pipe. v0 collapses to "iterate the
    // iovec and PipeWrite each segment." iovec layout: u64 base +
    // u64 len repeated nr_segs times.
    if (p->linux_fds[fd].state != 4)
        return kEBADF;
    const u32 pidx = p->linux_fds[fd].first_cluster;
    u64 total = 0;
    for (u64 i = 0; i < nr_segs; ++i)
    {
        u64 iov[2];
        if (!mm::CopyFromUser(iov, reinterpret_cast<const void*>(user_iov + i * 16), sizeof(iov)))
            return kEFAULT;
        const u64 base = iov[0];
        u64 segment_len = iov[1];
        while (segment_len > 0)
        {
            const i64 wrote = PipeWrite(pidx, base + (iov[1] - segment_len), segment_len);
            if (wrote < 0)
                return (total > 0) ? static_cast<i64>(total) : wrote;
            if (wrote == 0)
                return static_cast<i64>(total);
            total += static_cast<u64>(wrote);
            segment_len -= static_cast<u64>(wrote);
        }
    }
    return static_cast<i64>(total);
}

} // namespace duetos::subsystems::linux::internal
