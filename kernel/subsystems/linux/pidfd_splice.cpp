/*
 * Linux pidfd family + zero-copy fd-to-fd plumbing.
 *
 * pidfd_open / pidfd_send_signal / pidfd_getfd are the modern
 * race-free signaling API. A pidfd is a LinuxFd (state 12) whose
 * KFile owns one strong immutable Process identity. Read / write
 * reject pidfds with EBADF (the only operation Linux supports on a
 * pidfd is poll/epoll for "process exited" and pidfd_send_signal.
 * v0 supports both surfaces. The syscall exit path may issue an early
 * advisory wake, while the Process reaper issues the authoritative wake
 * only after release-publishing the inert Exited header.
 *
 * The Process reference belongs to the shared KFile, not to each
 * descriptor slot. HandleTableDuplicate therefore lets dup/fork share the
 * open-file description without multiplying the target reference. Last-task
 * teardown drains Linux fds while the reaper pins the dying Process, so self
 * and cross-process pidfd graphs are broken before the inert header can lose
 * its final reference. No pidfd operation re-resolves a weak numeric PID.
 *
 * splice / tee / vmsplice route bytes between fds without a
 * userland round-trip. v0 bounces through a 1 KiB on-stack
 * buffer (still kernel-bound, so the userland savings are
 * real: no second SYS_READ + SYS_WRITE pair). True zero-copy
 * page-grant would require a per-pipe page-lending model,
 * which is its own slice — sub-GAP.
 */

#include "subsystems/linux/syscall_internal.h"
#include "subsystems/linux/syscall_pipe.h"

#include "arch/x86_64/cpu.h"
#include "arch/x86_64/serial.h"
#include "ipc/handle_table.h"
#include "ipc/kfile.h"
#include "ipc/kobject.h"
#include "mm/paging.h"
#include "proc/process.h"
#include "sched/sched.h"
#include "sync/spinlock.h"
#include "util/nospec.h"

namespace duetos::subsystems::linux::internal
{

void LinuxPollEventWake();
u64 LinuxPollEventSequenceSnapshot();
const u64* LinuxPollEventSequenceAddress();
sched::WaitQueue* LinuxPollEventWq();

namespace
{

constexpr u32 kLinuxFdCap = 16;

// Pidfds need no separate allocation pool. Each descriptor slot owns a
// generation-checked handle to one shared KFile; that KFile owns the sole
// strong Process identity reference for the open-file description.
//
// Zero-copy claim: NOT pidfds — those don't transfer pages, they
// just hold a process handle. The "zero-copy" comment lives on
// splice/tee/vmsplice below.

} // namespace

// Global pidfd-exit waitqueue (§ syscall_internal.h LinuxPidfdExitWake).
// Lives in this TU because pidfd is the canonical surface that needs
// it; everything else (epoll_wait, DoExitGroup) reaches it through
// the LinuxPidfdExitWake() / LinuxPidfdExitWq() helpers.
namespace
{
sched::WaitQueue g_pidfd_exit_wq{};
u64 g_linux_poll_event_sequence = 0;
constinit sync::SpinLock g_linux_poll_event_lock = {
    .next_ticket = 0, .now_serving = 0, .owner_cpu = 0xFFFFFFFFu, .class_id = sync::kLockClassUnclassified};
} // namespace

void LinuxPollEventWake()
{
    const sync::IrqFlags flags = sync::SpinLockAcquire(g_linux_poll_event_lock);
    const u64 previous = __atomic_load_n(&g_linux_poll_event_sequence, __ATOMIC_RELAXED);
    if (previous != ~u64{0})
        __atomic_store_n(&g_linux_poll_event_sequence, previous + 1, __ATOMIC_RELEASE);
    sync::SpinLockRelease(g_linux_poll_event_lock, flags);

    constexpr u64 kRflagsInterruptEnable = 1ULL << 9;
    const bool interrupts_were_enabled = (arch::ReadRflags() & kRflagsInterruptEnable) != 0;
    arch::Cli();
    sched::WaitQueueWakeAll(&g_pidfd_exit_wq);
    if (interrupts_were_enabled)
        arch::Sti();
}

u64 LinuxPollEventSequenceSnapshot()
{
    return __atomic_load_n(&g_linux_poll_event_sequence, __ATOMIC_ACQUIRE);
}

const u64* LinuxPollEventSequenceAddress()
{
    return &g_linux_poll_event_sequence;
}

sched::WaitQueue* LinuxPollEventWq()
{
    return &g_pidfd_exit_wq;
}

void LinuxPidfdExitWake()
{
    // The syscall exit path may call this before SchedExit as an advisory
    // wake. ProcessCompleteExitFromReaper calls it again after release-
    // publishing Exited, closing the SMP re-check/lost-wake window.
    LinuxPollEventWake();
}

core::Process* LinuxPidfdAcquireTarget(const core::LinuxFdAcquired& acquired)
{
    if (acquired.snapshot.state != 12 || acquired.kfile_ref == nullptr)
        return nullptr;
    const auto* file = reinterpret_cast<const ipc::KFile*>(acquired.kfile_ref);
    return ipc::KFileAcquirePidfdTarget(file);
}

sched::WaitQueue* LinuxPidfdExitWq()
{
    return LinuxPollEventWq();
}

// =========================================================
// pidfd_open / pidfd_send_signal
// =========================================================

// pidfd_open(pid, flags) — install a generation-checked KFile whose
// shared open-file description owns a strong Process identity.
i64 DoPidfdOpen(u64 pid, u64 flags)
{
    constexpr u64 kPIDFD_NONBLOCK = 0x800;
    if ((flags & ~kPIDFD_NONBLOCK) != 0)
        return kEINVAL;
    // pid==0 is invalid in pidfd_open (real Linux returns
    // -EINVAL since "self" is not addressable that way; the
    // documented "no pid" sentinel for pidfd_open is just
    // bad-input).
    if (static_cast<i64>(pid) <= 0)
        return kEINVAL;
    core::Process* caller = core::CurrentProcess();
    if (caller == nullptr)
        return kEPERM;

    core::ScopedProcessRef target(sched::SchedFindProcessByPidRetained(pid));
    if (!target)
        return kESRCH;
    core::ScopedProcessRuntimeAccess target_runtime(target.Get());
    const u64 target_pid = target->pid;
    if (!target_runtime || !sched::SchedProcessAlive(target_pid))
        return kESRCH;

    auto file_result = ipc::KFileCreatePidfd(target.Get());
    if (!file_result.has_value())
        return kENOMEM;
    ipc::KFile* file = file_result.value();

    core::Process::LinuxFd payload{};
    payload.state = 12;
    payload.kf_handle = ipc::kHandleInvalid;
    core::LinuxFdPrepared prepared{};
    if (!core::LinuxFdPrepare(&prepared, payload, &file->base, static_cast<u32>(flags & kPIDFD_NONBLOCK)))
    {
        ipc::KObjectRelease(&file->base);
        return kENOMEM;
    }
    const i32 fd = core::LinuxFdBindLowest(caller, 3, &prepared, true);
    if (fd < 0)
    {
        core::LinuxFdPreparedRelease(&prepared);
        return kEMFILE;
    }
    arch::SerialWrite("[linux/pidfd] open fd=");
    arch::SerialWriteHex(static_cast<u64>(fd));
    arch::SerialWrite(" target_pid=");
    arch::SerialWriteHex(target_pid);
    arch::SerialWrite("\n");
    return static_cast<i64>(fd);
}

i64 DoPidfdSendSignal(u64 pidfd, u64 sig, u64 user_info, u64 flags)
{
    (void)user_info; // siginfo_t payload not honoured (v0 carries only signum)
    (void)flags;
    core::Process* caller = core::CurrentProcess();
    if (caller == nullptr || pidfd >= kLinuxFdCap)
        return kEBADF;
    // Spectre v1 nospec — see syscall_io.cpp DoWrite for rationale.
    // Mask BEFORE the linux_fds[] dereference: a misprediction of the
    // `pidfd >= 16` bounds check would otherwise speculate the load at
    // an OOB index and leak via cache side-channel.
    pidfd = util::MaskedIndex(pidfd, kLinuxFdCap);
    core::LinuxFdAcquired acquired{};
    if (!core::LinuxFdAcquire(caller, static_cast<u32>(pidfd), 12, &acquired))
        return kEBADF;
    core::ScopedProcessRef target(LinuxPidfdAcquireTarget(acquired));
    core::LinuxFdAcquiredRelease(&acquired);
    if (!target)
        return kEBADF;
    core::ScopedProcessRuntimeAccess target_runtime(target.Get());
    const u64 target_pid = target->pid;
    if (!target_runtime || !sched::SchedProcessAlive(target_pid))
        return kESRCH; // target may have already exited
    // The KFile-derived retained identity keeps the target alive across
    // delivery; no numeric PID lookup can redirect this operation.
    return LinuxSignalDeliver(target.Get(), static_cast<u32>(sig));
}

// pidfd_getfd(pidfd, target_fd, flags) duplicates one exact retained fd
// generation from the target into the caller. Export/import never holds two
// process fd locks together. Regular files (state 2), directories (state 11),
// and memfd (state 14) are not currently shareable across processes; that
// remains a bounded sub-GAP (see
// wiki/reference/Design-Decisions.md). Cap-gated on kCapDebug
// (cross-process fd inspection is the same threat class as
// PROCESS_VM_READ).
i64 DoPidfdGetfd(u64 pidfd, u64 target_fd, u64 flags)
{
    using ::duetos::core::kCapDebug;
    // pidfd_getfd(2): "flags is reserved for future use; currently
    // it must be zero." The returned descriptor is close-on-exec.
    if (flags != 0)
        return kEINVAL;
    core::Process* caller = core::CurrentProcess();
    if (caller == nullptr || pidfd >= kLinuxFdCap)
        return kEBADF;
    if (!core::ProcessHasCap(caller, kCapDebug))
    {
        core::RecordSandboxDenial(kCapDebug);
        return kEPERM;
    }
    // Spectre v1 nospec — see syscall_io.cpp DoWrite for rationale.
    // Mask BEFORE the linux_fds[] dereference (the bounds-check branch
    // can mispredict and leak an OOB load via cache side-channel).
    pidfd = util::MaskedIndex(pidfd, kLinuxFdCap);
    if (target_fd >= kLinuxFdCap)
        return kEBADF;

    core::LinuxFdAcquired pidfd_acquired{};
    if (!core::LinuxFdAcquire(caller, static_cast<u32>(pidfd), 12, &pidfd_acquired))
        return kEBADF;
    core::ScopedProcessRef target(LinuxPidfdAcquireTarget(pidfd_acquired));
    core::LinuxFdAcquiredRelease(&pidfd_acquired);
    if (!target)
        return kEBADF;
    core::ScopedProcessRuntimeAccess target_runtime(target.Get());
    const u64 target_pid = target->pid;
    if (!target_runtime || !sched::SchedProcessAlive(target_pid))
        return kESRCH;
    target_fd = util::MaskedIndex(target_fd, kLinuxFdCap);
    core::LinuxFdTransfer transfer{};
    if (!core::LinuxFdExport(target.Get(), static_cast<u32>(target_fd), &transfer))
        return kEBADF;

    // Refuse states that aren't safe to share across processes.
    const u8 state = transfer.snapshot.state;
    if (state == 2 || state == 11 || state == 14)
    {
        core::LinuxFdTransferRelease(&transfer);
        return kEINVAL; // regular file / dirfd / memfd
    }

    // Import consumes the retained transfer only on success. Explicit release
    // is therefore safe on both paths and never runs while an fd lock is held.
    const i32 caller_slot = core::LinuxFdImportLowest(caller, 3, &transfer, true);
    core::LinuxFdTransferRelease(&transfer);
    if (caller_slot < 0)
        return kEMFILE;

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
    // Spectre v1 nospec — see syscall_io.cpp DoWrite for rationale.
    fd_in = util::MaskedIndex(fd_in, 16);
    fd_out = util::MaskedIndex(fd_out, 16);
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
    // Spectre v1 nospec — see syscall_io.cpp DoWrite for rationale.
    fd_in = util::MaskedIndex(fd_in, 16);
    fd_out = util::MaskedIndex(fd_out, 16);
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
    // Spectre v1 nospec — see syscall_io.cpp DoWrite for rationale.
    fd = util::MaskedIndex(fd, 16);
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
