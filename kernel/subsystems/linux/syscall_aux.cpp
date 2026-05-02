/*
 * DuetOS — Linux ABI: syscalls we deliberately do NOT implement.
 *
 * This TU is the exception list, not a TODO list. Every handler
 * here returns the spec-correct errno for "this Linux feature is
 * recognised by the kernel but the underlying mechanism doesn't
 * exist in DuetOS". Real userspace code (glibc/musl tools, busybox
 * static binaries, Linux build scripts) is documented to fall back
 * gracefully on these errnos — that fallback is the point.
 *
 * If a syscall lands here, one of these is true:
 *
 *   1. The Linux feature is deprecated / never-released (uselib,
 *      ustat, sysfs, sysctl, lookup_dcookie, modify_ldt,
 *      remap_file_pages, epoll_ctl_old/wait_old). Mainline Linux
 *      itself returns -ENOSYS for these.
 *
 *   2. The feature requires a v0-missing subsystem (namespaces:
 *      unshare/setns; LSM: lsm_*; AIO: io_pgetevents; quotas:
 *      quotactl_fd; NUMA: set_mempolicy_home_node; mount-table:
 *      statmount/listmount; secret memory: memfd_secret; shadow
 *      stacks: map_shadow_stack; page-cache stats: cachestat).
 *
 *   3. The feature is a 5.16+ extended-ABI alternative whose
 *      callers fall back to the classic syscall we DO implement
 *      (futex_waitv/wake/wait/requeue → futex(2); rseq → no
 *      fast-path).
 *
 *   4. The feature requires cap-gating that we haven't modelled
 *      (process_vm_readv/writev, kcmp, seccomp).
 *
 *   5. The feature is internal-ABI never callable from userspace
 *      directly (restart_syscall).
 *
 * Adding new entries here is an explicit decision to NOT
 * implement: the comment above each handler must say which
 * category and why a real implementation isn't available. If a
 * follow-up slice DOES build the missing infrastructure, the
 * handler moves OUT of this file into the appropriate
 * syscall_<family>.cpp peer.
 */

#include "subsystems/linux/syscall_internal.h"

#include "mm/paging.h"
#include "proc/process.h"

namespace duetos::subsystems::linux::internal
{

// =============================================================
// Category 1 — deprecated / never-released. Mainline Linux
// itself returns -ENOSYS. ABI-completeness only.
// =============================================================

// uselib(library) — historical pre-libdl dynamic load. Removed
// from glibc decades ago; Linux still has the entry for ABI
// compat but always returns -ENOSYS.
i64 DoUselib(u64 library)
{
    (void)library;
    return kENOSYS;
}

// remap_file_pages(addr, size, prot, pgoff, flags) — replaced
// by mmap(MAP_FIXED) loops; deprecated in 4.x.
i64 DoRemapFilePages(u64 addr, u64 size, u64 prot, u64 pgoff, u64 flags)
{
    (void)addr;
    (void)size;
    (void)prot;
    (void)pgoff;
    (void)flags;
    return kENOSYS;
}

// epoll_ctl_old / epoll_wait_old — never-released x86_64-only
// aliases. Stayed -ENOSYS in mainline forever.
i64 DoEpollCtlOld(u64 a1, u64 a2, u64 a3, u64 a4)
{
    (void)a1;
    (void)a2;
    (void)a3;
    (void)a4;
    return kENOSYS;
}
i64 DoEpollWaitOld(u64 a1, u64 a2, u64 a3, u64 a4)
{
    (void)a1;
    (void)a2;
    (void)a3;
    (void)a4;
    return kENOSYS;
}

// modify_ldt(func, ptr, bytecount) — read/write the LDT for
// 32-bit segment registers. v0 is 64-bit-only; func==0
// (read) returns 0 bytes (empty LDT); other funcs -ENOSYS.
i64 DoModifyLdt(u64 func, u64 ptr, u64 bytecount)
{
    (void)ptr;
    (void)bytecount;
    if (func == 0)
        return 0;
    return kENOSYS;
}

// =============================================================
// Category 2 — v0-missing subsystem. Real implementation
// requires building the underlying infrastructure first
// (namespaces, LSM, AIO, NUMA, mount-table, secret memory,
// shadow stacks, page-cache statistics).
// =============================================================

// unshare(flags) — detach pieces of the calling process's
// execution context. v0 has no namespaces, so flags=0 is a
// no-op (zero unshares = nothing to do; succeeds), and any
// non-zero flags request something we can't deliver.
i64 DoUnshare(u64 flags)
{
    if (flags == 0)
        return 0;
    return kEINVAL;
}

// setns(fd, nstype) — switch a namespace.
i64 DoSetns(u64 fd, u64 nstype)
{
    (void)fd;
    (void)nstype;
    return kEINVAL;
}

// quotactl_fd(fd, cmd, id, addr) — fd-based quota control.
i64 DoQuotactlFd(u64 fd, u64 cmd, u64 id, u64 addr)
{
    (void)fd;
    (void)cmd;
    (void)id;
    (void)addr;
    return kENOSYS;
}

// io_pgetevents(ctx, min_nr, nr, events, timeout, sig) — AIO
// completion query with signal mask.
i64 DoIoPgetevents(u64 ctx, u64 min_nr, u64 nr, u64 events, u64 timeout, u64 sig)
{
    (void)ctx;
    (void)min_nr;
    (void)nr;
    (void)events;
    (void)timeout;
    (void)sig;
    return kENOSYS;
}

// set_mempolicy_home_node(start, len, home_node, flags) —
// preferred NUMA node. Single-NUMA-node v0; node==0 accept,
// else -EINVAL.
i64 DoSetMempolicyHomeNode(u64 start, u64 len, u64 home_node, u64 flags)
{
    (void)start;
    (void)len;
    (void)flags;
    if (home_node == 0)
        return 0;
    return kEINVAL;
}

// cachestat(fd, range, cstat, flags) — per-fd page-cache
// residency. We don't track a page cache; report "everything
// resident, nothing dirty" via a zeroed cstat buffer (safe v0
// lie since FAT32 reads land in buffer cache and writes flush
// synchronously).
i64 DoCachestat(u64 fd, u64 user_range, u64 user_cstat, u64 flags)
{
    (void)fd;
    (void)flags;
    if (user_range == 0 || user_cstat == 0)
        return kEINVAL;
    u8 zeros[48] = {0};
    if (!mm::CopyToUser(reinterpret_cast<void*>(user_cstat), zeros, sizeof(zeros)))
        return kEFAULT;
    return 0;
}

// memfd_secret(flags) — secret-memory fd.
i64 DoMemfdSecret(u64 flags)
{
    (void)flags;
    return kENOSYS;
}

// map_shadow_stack(addr, size, flags) — CET shadow-stack region.
i64 DoMapShadowStack(u64 addr, u64 size, u64 flags)
{
    (void)addr;
    (void)size;
    (void)flags;
    return kENOSYS;
}

// statmount / listmount — mount-table introspection.
i64 DoStatmount(u64 req, u64 buf, u64 bufsize, u64 flags)
{
    (void)req;
    (void)buf;
    (void)bufsize;
    (void)flags;
    return kENOSYS;
}
i64 DoListmount(u64 req, u64 buf, u64 bufsize, u64 flags)
{
    (void)req;
    (void)buf;
    (void)bufsize;
    (void)flags;
    return kENOSYS;
}

// LSM (Linux Security Module) self-attribute access.
i64 DoLsmGetSelfAttr(u64 attr, u64 ctx, u64 size, u64 flags)
{
    (void)attr;
    (void)ctx;
    (void)size;
    (void)flags;
    return kENOSYS;
}
i64 DoLsmSetSelfAttr(u64 attr, u64 ctx, u64 size, u64 flags)
{
    (void)attr;
    (void)ctx;
    (void)size;
    (void)flags;
    return kENOSYS;
}
i64 DoLsmListModules(u64 ids, u64 size, u64 flags)
{
    (void)ids;
    (void)size;
    (void)flags;
    return kENOSYS;
}

// =============================================================
// Category 3 — extended-ABI alternative. Callers fall back to
// the classic syscall we DO implement (futex(2)).
// =============================================================

// 5.16+ extended futex ops. glibc/musl probe via /proc/sys/
// kernel/futex_* (which we don't expose) and fall back to
// classic futex(2). -ENOSYS keeps that fallback alive.
i64 DoFutexWaitv(u64 waiters, u64 nr_futexes, u64 flags, u64 timeout, u64 clockid)
{
    (void)waiters;
    (void)nr_futexes;
    (void)flags;
    (void)timeout;
    (void)clockid;
    return kENOSYS;
}
i64 DoFutexWake(u64 uaddr, u64 mask, u64 nr, u64 flags)
{
    (void)uaddr;
    (void)mask;
    (void)nr;
    (void)flags;
    return kENOSYS;
}
i64 DoFutexWait(u64 uaddr, u64 val, u64 mask, u64 flags, u64 timeout, u64 clockid)
{
    (void)uaddr;
    (void)val;
    (void)mask;
    (void)flags;
    (void)timeout;
    (void)clockid;
    return kENOSYS;
}
i64 DoFutexRequeue(u64 waiters, u64 flags, u64 nr_wake, u64 nr_requeue)
{
    (void)waiters;
    (void)flags;
    (void)nr_wake;
    (void)nr_requeue;
    return kENOSYS;
}

// rseq(rseq, rseq_len, flags, sig) — restartable sequences.
// glibc/musl tolerate -ENOSYS by skipping the rseq fast-path.
i64 DoRseq(u64 rseq, u64 rseq_len, u64 flags, u64 sig)
{
    (void)rseq;
    (void)rseq_len;
    (void)flags;
    (void)sig;
    return kENOSYS;
}

// =============================================================
// Category 4 — cap-gating not modelled. Real implementation
// would need a cross-process inspection privilege model that
// v0 doesn't have.
// =============================================================

// process_vm_readv / process_vm_writev — peer into another
// process's VM. v0 -> -ESRCH (target pid never readable).
i64 DoProcessVmReadv(u64 pid, u64 lvec, u64 lcnt, u64 rvec, u64 rcnt, u64 flags)
{
    (void)pid;
    (void)lvec;
    (void)lcnt;
    (void)rvec;
    (void)rcnt;
    (void)flags;
    return kESRCH;
}
i64 DoProcessVmWritev(u64 pid, u64 lvec, u64 lcnt, u64 rvec, u64 rcnt, u64 flags)
{
    return DoProcessVmReadv(pid, lvec, lcnt, rvec, rcnt, flags);
}

// kcmp(pid1, pid2, type, idx1, idx2) — compare resources.
// -EPERM matches Linux's "ptrace_scope locked out" path.
i64 DoKcmp(u64 pid1, u64 pid2, u64 type, u64 idx1, u64 idx2)
{
    (void)pid1;
    (void)pid2;
    (void)type;
    (void)idx1;
    (void)idx2;
    return kEPERM;
}

// seccomp(operation, flags, args) — syscall filtering. v0
// supports only the introspection commands that don't change
// state: SECCOMP_GET_ACTION_AVAIL (cmd 2) returns 0; others
// -EINVAL.
i64 DoSeccomp(u64 op, u64 flags, u64 args)
{
    (void)flags;
    (void)args;
    if (op == 2)
        return 0;
    return kEINVAL;
}

// =============================================================
// Category 5 — internal Linux ABI never user-callable.
// =============================================================

// restart_syscall — kernel-internal hook to resume an
// EINTR'd syscall. Userspace direct-call observes -EINTR
// (we don't have the saved state to restart).
i64 DoRestartSyscall()
{
    return kEINTR;
}

} // namespace duetos::subsystems::linux::internal
