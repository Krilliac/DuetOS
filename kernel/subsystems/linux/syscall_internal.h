#pragma once

// Private cross-TU surface for the Linux ABI subsystem. Splits
// the implementation across multiple translation units that share
// the constants + handler declarations below:
//
//   syscall.cpp      — dispatcher, public wrappers, handlers not
//                      yet extracted into per-domain TUs.
//   syscall_cred.cpp — uid/gid/groups/capabilities handlers.
//
// Anything in `namespace duetos::subsystems::linux::internal` is
// intended for the subsystem's own TUs only — never include this
// header from outside kernel/subsystems/linux/. The public API
// lives in syscall.h.

#include "arch/x86_64/traps.h"
#include "proc/process.h"
#include "sched/sched.h"
#include "util/types.h"

namespace duetos::subsystems::linux::internal
{

// Canonical Linux errno values used by handlers we implement.
// Linux returns errno via a negative rax — these constants are
// the negated values so handlers can `return kEXXX` directly.
inline constexpr i64 kEPERM = -1;
inline constexpr i64 kENOENT = -2;
inline constexpr i64 kESRCH = -3;
inline constexpr i64 kEINTR = -4;
inline constexpr i64 kEIO = -5;
inline constexpr i64 kEBADF = -9;
inline constexpr i64 kECHILD = -10;
inline constexpr i64 kENOMEM = -12;
inline constexpr i64 kEACCES = -13;
inline constexpr i64 kEFAULT = -14;
inline constexpr i64 kENOTDIR = -20;
inline constexpr i64 kEISDIR = -21;
inline constexpr i64 kEINVAL = -22;
inline constexpr i64 kENFILE = -23;
inline constexpr i64 kEMFILE = -24;
inline constexpr i64 kEAGAIN = -11;
inline constexpr i64 kEOVERFLOW = -75;
inline constexpr i64 kEOPNOTSUPP = -95;
inline constexpr i64 kESTALE = -116;
inline constexpr i64 kENOTTY = -25;
inline constexpr i64 kESPIPE = -29;
inline constexpr i64 kERANGE = -34;
inline constexpr i64 kENAMETOOLONG = -36;
inline constexpr i64 kENOSYS = -38;

// Resource limit handlers (syscall_rlimit.cpp). v0 reports the
// real ceilings where it has them (NOFILE 16, NPROC 64, STACK
// 64 KiB, NICE 20) and RLIM_INFINITY for everything else.
i64 DoGetrlimit(u64 resource, u64 user_old);
i64 DoSetrlimit(u64 resource, u64 user_new);
i64 DoPrlimit64(u64 pid, u64 resource, u64 user_new, u64 user_old);

// Stub handlers (syscall_stub.cpp). Calls for subsystems v0 has
// no machinery for: pipes, fork/wait, eventfd / timerfd /
// signalfd, epoll, inotify, plus the page-cache hint pair
// (fadvise64 / readahead). Plus the "tracing / mount / link /
// rename" compat group: ptrace / syslog / vhangup / acct /
// mount / umount2 / sync / syncfs / rename / link / symlink /
// set_thread_area / get_thread_area / ioprio_get / ioprio_set.
// Each returns the canonical Linux errno (-ENFILE / -ECHILD /
// -ENOSYS / -EPERM) for "we don't have that subsystem" so
// callers fall through to a polyfill instead of the
// unhandled-syscall panic line.
i64 DoPtrace(u64 request, u64 pid, u64 addr, u64 data);
i64 DoSyslog(u64 type, u64 bufp, u64 len);
i64 DoVhangup();
i64 DoAcct(u64 filename);
i64 DoMount(u64 source, u64 target, u64 fstype, u64 flags, u64 data);
i64 DoUmount2(u64 target, u64 flags);
i64 DoSync();
i64 DoSyncfs(u64 fd);
i64 DoRename(u64 old_path, u64 new_path);
i64 DoLink(u64 old_path, u64 new_path);
i64 DoSymlink(u64 target, u64 linkpath);
i64 DoSetThreadArea(u64 u_info);
i64 DoGetThreadArea(u64 u_info);
i64 DoIoprioGet(u64 which, u64 who);
i64 DoIoprioSet(u64 which, u64 who, u64 ioprio);
// Linux pipe(2) / pipe2(2) — defined in syscall_pipe.cpp. v0
// blocking-only (O_NONBLOCK accepted but ignored). Each call
// allocates two LinuxFd slots (read + write ends, state 3/4)
// pointing at a shared kernel pipe pool entry.
i64 DoPipe(u64 user_fds);
i64 DoPipe2(u64 user_fds, u64 flags);

// Linux eventfd(2) / eventfd2(2) — defined in syscall_pipe.cpp.
// Allocates one LinuxFd slot (state 5) pointing at an eventfd
// pool entry holding a u64 counter.
i64 DoEventfd(u64 initval);
i64 DoEventfd2(u64 initval, u64 flags);
i64 DoWait4(u64 pid, u64 user_status, u64 options, u64 user_rusage);
i64 DoWaitid(u64 idtype, u64 id, u64 user_info, u64 options, u64 user_rusage);
i64 DoTimerfdCreate(u64 clockid, u64 flags);
i64 DoTimerfdSettime(u64 fd, u64 flags, u64 user_new, u64 user_old);
i64 DoTimerfdGettime(u64 fd, u64 user_curr);
i64 DoSignalfd(u64 fd, u64 user_mask, u64 sigsetsize, u64 flags);
i64 DoFadvise64(u64 fd, u64 offset, u64 len, u64 advice);
i64 DoReadahead(u64 fd, u64 offset, u64 count);
i64 DoEpollCreate(u64 size);
i64 DoEpollCreate1(u64 flags);
i64 DoEpollCtl(u64 epfd, u64 op, u64 fd, u64 event);
i64 DoEpollWait(u64 epfd, u64 events, u64 maxevents, u64 timeout_ms);
i64 DoEpollPwait(u64 epfd, u64 events, u64 maxevents, u64 timeout_ms, u64 sigmask, u64 sigsetsize);
// Inotify family (inotify.cpp). Real ring + watch table; FS
// mutations publish events via InotifyPublish() called from
// fs::routing.
i64 InotifyInit();
i64 InotifyInit1(u64 flags);
i64 DoInotifyAddWatch(u64 fd, u64 user_path, u64 mask);
i64 DoInotifyRmWatch(u64 fd, u64 wd);

// Memory-management handlers (syscall_mm.cpp). brk grows the
// per-process Linux heap; mmap supports MAP_PRIVATE +
// MAP_ANONYMOUS or MAP_PRIVATE + file-backed (no page-cache, so
// MAP_SHARED is rejected). mprotect / madvise / mremap / msync /
// mincore validate inputs the way Linux does but mostly accept
// as no-op since v0 has no swap and no page reclaim.
i64 DoBrk(u64 new_brk);
i64 DoMmap(u64 addr, u64 len, u64 prot, u64 flags, u64 fd, u64 off);
i64 DoMunmap(u64 addr, u64 len);
i64 DoMprotect(u64 addr, u64 len, u64 prot);
i64 DoMadvise(u64 addr, u64 len, u64 advice);
i64 DoMremap(u64 old_addr, u64 old_len, u64 new_len, u64 flags, u64 new_addr);
i64 DoMsync(u64 addr, u64 len, u64 flags);
i64 DoMincore(u64 addr, u64 len, u64 user_vec);
i64 DoMlock(u64 addr, u64 len);
i64 DoMunlock(u64 addr, u64 len);
i64 DoMlockall(u64 flags);
i64 DoMunlockall();

// Process-control handlers (syscall_proc.cpp). exit / exit_group
// teardown the calling task via sched::SchedExit; getpid / gettid
// both return the current task id (one task per process in v0);
// kill / tgkill targeting self exits, anything else returns
// -ESRCH because we don't deliver signals yet. setpgid / getpgrp
// / getpgid / getsid / setsid are accepted as no-ops returning
// 0 / 1 (init-like ppid).
i64 DoExit(u64 status);
i64 DoExitGroup(u64 status);
i64 DoGetPid();
i64 DoGetTid();

// Linux clone(flags, stack, ptid, ctid, tls). v0 implements the
// CLONE_THREAD subset only — same-AS thread create, equivalent
// to pthread_create's flag bundle. flags missing CLONE_THREAD
// or CLONE_VM return -ENOSYS so libc falls back without
// pretending the call succeeded. Defined in syscall_clone.cpp.
//
// The full Linux signature carries ptid / ctid / tls — v0 honours
// CLONE_PARENT_SETTID by writing the new TID through `ptid_user`
// and CLONE_SETTLS by stamping `tls` into the new task's
// fs_base. CLONE_CHILD_CLEARTID + futex-wake-on-exit are not
// wired (no futex engine in v0); the call is accepted-but-ignored
// for that flag.
i64 DoClone(u64 flags, u64 child_stack, u64 ptid_user, u64 ctid_user, u64 tls);

// Linux fork(2) — full process duplication (separate AS, deep
// copy of every user page). vfork() forwards here too. Defined
// in syscall_clone.cpp. CapsSpawnThread-gated. Sub-GAPs:
// no COW (frame-by-frame deep copy), no fd inheritance, no
// signal-handler inheritance.
i64 DoFork();

i64 DoGetpgrp();
i64 DoGetPpid();
i64 DoGetPgid(u64 pid);
i64 DoGetSid(u64 pid);
i64 DoSetPgid(u64 pid, u64 pgid);
i64 DoSetsid();
i64 DoSchedYield();
i64 DoTgkill(u64 tgid, u64 tid, u64 sig);
i64 DoKill(u64 pid, u64 sig);

// POSIX *at-family: AT_FDCWD = -100 means "resolve the path
// relative to the caller's CWD". v0 has no per-process CWD
// pointer threaded into the FAT32 lookup path yet, so AT_FDCWD
// always resolves against the sandbox root; any other dirfd is
// -EBADF until per-fd CWDs land. AT_REMOVEDIR is the unlinkat
// flag bit that turns the call into rmdir.
inline constexpr i64 kAtFdCwd = -100;
inline constexpr u64 kAtRemoveDir = 0x200;

// Path-strip helpers shared across the file / fs_mut / utime /
// utimensat handlers. Definitions live in syscall.cpp for now;
// a future slice may move them to a dedicated syscall_pathutil.cpp.
//
// StripFatPrefix: skip a leading "/fat/" mount prefix (or any run
//   of '/'). The FAT32 driver wants volume-relative paths.
// CopyAndStripFatPath: copy a u64 user pointer into a 64-byte
//   kernel buffer, NUL-terminate, then point `out_leaf` at the
//   stripped suffix. Returns false on copy failure or unterminated
//   string.
// AtFdCwdOnly: the *at-family guard — returns 0 for AT_FDCWD,
//   -EBADF (with a serial log line) otherwise.
const char* StripFatPrefix(const char* p);
bool CopyAndStripFatPath(u64 user_path, char (&kbuf)[64], const char*& out_leaf);
i64 AtFdCwdOnly(i64 dirfd);

// FS-mutating handlers (syscall_fs_mut.cpp). truncate / ftruncate
// / unlink / mkdir / rmdir route through the FAT32 *AtPath
// primitives. chmod / fchmod / chown / fchown / lchown / utime
// are no-ops in v0 (no permission / time model) but verify the
// target exists. mknod returns -EPERM. The *at-family delegates
// to the non-*at handler when dirfd == AT_FDCWD.
i64 DoChmod(u64 user_path, u64 mode);
i64 DoFchmod(u64 fd, u64 mode);
i64 DoChown(u64 user_path, u64 uid, u64 gid);
i64 DoFchown(u64 fd, u64 uid, u64 gid);
i64 DoLchown(u64 user_path, u64 uid, u64 gid);
i64 DoUtime(u64 user_path, u64 user_buf);
i64 DoMknod(u64 user_path, u64 mode, u64 dev);
i64 DoTruncate(u64 user_path, u64 length);
i64 DoFtruncate(u64 fd, u64 length);
i64 DoUnlink(u64 user_path);
i64 DoMkdir(u64 user_path, u64 mode);
i64 DoRmdir(u64 user_path);
i64 DoMkdirat(i64 dirfd, u64 user_path, u64 mode);
i64 DoUnlinkat(i64 dirfd, u64 user_path, u64 flags);
i64 DoLinkat(i64 olddirfd, u64 oldpath, i64 newdirfd, u64 newpath, u64 flags);
i64 DoSymlinkat(u64 target, i64 newdirfd, u64 linkpath);
i64 DoRenameat(i64 olddirfd, u64 oldpath, i64 newdirfd, u64 newpath);
i64 DoRenameat2(i64 olddirfd, u64 oldpath, i64 newdirfd, u64 newpath, u64 flags);
i64 DoFchownat(i64 dirfd, u64 user_path, u64 uid, u64 gid, u64 flags);
i64 DoFutimesat(i64 dirfd, u64 user_path, u64 user_times);
i64 DoFchmodat(i64 dirfd, u64 user_path, u64 mode, u64 flags);
i64 DoFaccessat(i64 dirfd, u64 user_path, u64 mode, u64 flags);
i64 DoFaccessat2(i64 dirfd, u64 user_path, u64 mode, u64 flags);
i64 DoUtimensat(i64 dirfd, u64 user_path, u64 user_times, u64 flags);

// Miscellaneous handlers (syscall_misc.cpp). The handlers that
// don't fit any of the other domain slices: arch_prctl, uname,
// set_tid_address, sysinfo, getrandom, futex, personality,
// pause, flock, get/setpriority, getcpu, prctl, getrusage,
// poll/ppoll/select/pselect6, getdents64, set/get_robust_list,
// readlink (with the /proc/self/exe special case).
i64 DoSetTidAddress(u64 user_tid_ptr);
i64 DoReadlink(u64 user_path, u64 user_buf, u64 bufsiz);
i64 DoFutex(u64 uaddr, u64 op, u64 val, u64 timeout, u64 uaddr2, u64 val3);
i64 DoGetRandom(u64 user_buf, u64 count, u64 flags);
i64 DoSysinfo(u64 user_info);
i64 DoGetrusage(u64 who, u64 user_buf);
i64 DoPoll(u64 user_fds, u64 nfds, i64 timeout_ms);
i64 DoSelect(u64 nfds, u64 rfds, u64 wfds, u64 efds, u64 timeout);
i64 DoGetdents64(u64 fd, u64 user_buf, u64 count);
i64 DoSetRobustList(u64 head, u64 len);
i64 DoGetRobustList(u64 pid, u64 user_head_ptr, u64 user_len_ptr);
i64 DoArchPrctl(u64 code, u64 addr);
i64 DoUname(u64 user_buf);
i64 DoPause();
i64 DoFlock(u64 fd, u64 op);
i64 DoPersonality(u64 persona);
i64 DoGetpriority(u64 which, u64 who);
i64 DoSetpriority(u64 which, u64 who, u64 prio);
i64 DoGetcpu(u64 user_cpu, u64 user_node, u64 user_tcache);
i64 DoPpoll(u64 user_fds, u64 nfds, u64 user_ts, u64 user_sigmask, u64 sigsetsize);
i64 DoPselect6(u64 nfds, u64 r, u64 w, u64 e, u64 user_ts, u64 user_sigmask);
i64 DoPrctl(u64 option, u64 arg2, u64 arg3, u64 arg4, u64 arg5);

// I/O handlers (syscall_io.cpp). read / write route through the
// FAT32 driver (or COM1 for stdin/stdout/stderr fds). lseek
// adjusts the per-fd cursor; ioctl handles the three TTY ioctls
// musl's stdio actually probes (TCGETS / TCSETS / TIOCGWINSZ).
// pread64 / pwrite64 save+restore the cursor around DoRead /
// DoWrite. fsync / fdatasync are no-ops (writes are synchronous).
// readv / writev iterate the iovec calling DoRead / DoWrite.
i64 DoRead(u64 fd, u64 user_buf, u64 len);
i64 DoWrite(u64 fd, u64 user_buf, u64 len);
i64 DoReadv(u64 fd, u64 user_iov, u64 iovcnt);
i64 DoWritev(u64 fd, u64 user_iov, u64 iovcnt);
i64 DoLseek(u64 fd, i64 offset, u64 whence);
i64 DoIoctl(u64 fd, u64 cmd, u64 arg);
i64 DoFsync(u64 fd);
i64 DoFdatasync(u64 fd);
i64 DoPread64(u64 fd, u64 user_buf, u64 len, i64 offset);
i64 DoPwrite64(u64 fd, u64 user_buf, u64 len, i64 offset);

// File handlers (syscall_file.cpp). open / close / stat / fstat
// / lstat / access / openat / newfstatat. open snapshots the
// FAT32 entry into the per-process linux_fds[16] table; stat
// fills a 144-byte Linux struct stat from the entry; lstat is
// identical (no symlinks); openat / newfstatat enforce the
// AT_FDCWD-only constraint via AtFdCwdOnly.
// Effective per-Process fd ceiling: min(16, p->linux_rlimit_nofile_cur).
// Used by primary fd-alloc paths (DoOpen, DoDup) so a setrlimit
// that lowers RLIMIT_NOFILE actually limits subsequent open()s.
// Auxiliary allocators (signalfd / timerfd / eventfd / inotify /
// fanotify / pidfd / pipe / msgq / memfd) currently still allow
// up to 16 — sub-GAP, separate slice. Any caller that uses the
// 0xFFFFFFFFFFFFFFFF sentinel falls through to 16.
inline u32 LinuxFdEffectiveMax(const core::Process* p)
{
    if (p == nullptr)
        return 16;
    const u64 cap = p->linux_rlimit_nofile_cur;
    if (cap == 0xFFFFFFFFFFFFFFFFull || cap > 16)
        return 16;
    return static_cast<u32>(cap);
}

i64 DoOpen(u64 user_path, u64 flags, u64 mode);
i64 DoClose(u64 fd);
i64 DoStat(u64 user_path, u64 user_buf);
i64 DoFstat(u64 fd, u64 user_buf);
i64 DoLstat(u64 user_path, u64 user_buf);
i64 DoAccess(u64 user_path, u64 mode);
i64 DoOpenat(i64 dirfd, u64 user_path, u64 flags, u64 mode);
i64 DoNewFstatat(i64 dirfd, u64 user_path, u64 user_buf, u64 flags);

// CWD / path handlers (syscall_path.cpp). v0 records per-process
// CWD in core::Process::linux_cwd; chdir / fchdir update it,
// getcwd reads it back. The string is volume-relative — every
// FAT32 / ramfs lookup site already strips the mount prefix at
// the use point.
i64 DoChdir(u64 user_path);
i64 DoFchdir(u64 fd);
i64 DoGetcwd(u64 user_buf, u64 size);

// File-descriptor handlers (syscall_fd.cpp). v0 stores per-fd
// state in core::Process::linux_fds[16]; dup / dup2 / dup3 / fcntl
// manipulate the slot table without sharing file descriptions
// (real Linux dup() shares; we don't yet).
i64 DoDup(u64 fd);
i64 DoDup2(u64 oldfd, u64 newfd);
i64 DoDup3(u64 oldfd, u64 newfd, u64 flags);
i64 DoFcntl(u64 fd, u64 cmd, u64 arg);

// Signal handlers (syscall_sig.cpp). v0 has no actual signal
// delivery — every entry persists state where the caller probes
// it (sigaction slots, signal mask) or returns 0 / -EINTR so
// libc paths make forward progress instead of -ENOSYS-crashing.
// SysV IPC (sysv_ipc.cpp).
//   shmget / shmat / shmdt / shmctl — named shared memory backed
//     by an 8-segment global pool of physical frames; attach
//     installs borrowed PTEs into the caller's AS.
//   semget / semop / semctl / semtimedop — 8-set / 16-sem-per-set
//     pool with WaitQueue-blocking decrement-with-wait + wait-on-
//     zero. semtimedop ignores the timeout (sub-GAP).
i64 DoShmget(u64 key, u64 size, u64 shmflg);
i64 DoShmat(u64 shmid, u64 shmaddr, u64 shmflg);
i64 DoShmdt(u64 shmaddr);
i64 DoShmctl(u64 shmid, u64 cmd, u64 user_buf);
i64 DoSemget(u64 key, u64 nsems, u64 semflg);
i64 DoSemop(u64 semid, u64 user_ops, u64 nops);
i64 DoSemtimedop(u64 semid, u64 user_ops, u64 nops, u64 user_timeout);
i64 DoSemctl(u64 semid, u64 semnum, u64 cmd, u64 arg);

// SysV msg queues (msg_queues.cpp). Same shape as SysV sem: 8-queue
// global pool keyed by IPC key. Each msg has an mtype prefix; recv
// can filter by mtype (== / <= |mtype|). Blocking via per-queue
// read_wq / write_wq.
i64 DoMsgget(u64 key, u64 msgflg);
i64 DoMsgsnd(u64 msqid, u64 user_msg, u64 msgsz, u64 msgflg);
i64 DoMsgrcv(u64 msqid, u64 user_msg, u64 msgsz, u64 mtype_filter, u64 msgflg);
i64 DoMsgctl(u64 msqid, u64 cmd, u64 user_buf);

// POSIX msg queues (msg_queues.cpp). 8-queue pool keyed by string
// name ("/foo"). LinuxFd state 13 = mqdes. Receivers see the
// highest-priority pending message. Refcounted: mq_unlink + close
// of last fd frees the ring.
i64 DoMqOpen(u64 user_name, u64 oflag, u64 mode, u64 user_attr);
i64 DoMqUnlink(u64 user_name);
i64 DoMqTimedsend(u64 mqdes, u64 user_msg, u64 msg_len, u64 prio, u64 user_timeout);
i64 DoMqTimedreceive(u64 mqdes, u64 user_msg, u64 msg_cap, u64 user_prio, u64 user_timeout);
i64 DoMqNotify(u64 mqdes, u64 user_notification);
i64 DoMqGetsetattr(u64 mqdes, u64 user_new, u64 user_old);
void PosixMqRetain(u32 idx);
void PosixMqRelease(u32 idx);

// Extra modern fs / mm / fd / numa / namespacing surface
// (extra_syscalls.cpp). Real implementations: statx,
// copy_file_range, memfd_create, close_range, statfs / fstatfs.
// No-op success: NUMA family (set/get_mempolicy / mbind /
// migrate_pages / move_pages), mseal, process_madvise,
// process_mrelease. Honest -ENOSYS / -EINVAL: userfaultfd,
// io_uring_*, pkey_*, name_to_handle_at / open_by_handle_at,
// fsopen / fsconfig / fsmount / fspick / open_tree /
// move_mount / mount_setattr, landlock_*.
i64 DoStatx(u64 dirfd, u64 user_path, u64 flags, u64 mask, u64 user_buf);
i64 DoCopyFileRange(u64 fd_in, u64 user_off_in, u64 fd_out, u64 user_off_out, u64 len, u64 flags);
i64 DoMemfdCreate(u64 user_name, u64 flags);
void MemfdRetain(u32 idx);
void MemfdRelease(u32 idx);
i64 DoCloseRange(u64 first, u64 last, u64 flags);
i64 DoStatfs(u64 user_path, u64 user_buf);
i64 DoFstatfs(u64 fd, u64 user_buf);
i64 DoSetMempolicy(u64 mode, u64 user_nodemask, u64 maxnode);
i64 DoGetMempolicy(u64 user_mode, u64 user_nodemask, u64 maxnode, u64 addr, u64 flags);
i64 DoMbind(u64 addr, u64 len, u64 mode, u64 user_nodemask, u64 maxnode, u64 flags);
i64 DoMigratePages(u64 pid, u64 maxnode, u64 user_old, u64 user_new);
i64 DoMovePages(u64 pid, u64 nr_pages, u64 user_pages, u64 user_nodes, u64 user_status, u64 flags);
i64 DoMseal(u64 start, u64 len, u64 flags);
i64 DoProcessMadvise(u64 pidfd, u64 user_iovec, u64 vlen, u64 advice, u64 flags);
i64 DoProcessMrelease(u64 pidfd, u64 flags);
i64 DoUserfaultfd(u64 flags);
i64 DoIoUringSetup(u64 entries, u64 user_params);
i64 DoIoUringEnter(u64 fd, u64 to_submit, u64 min_complete, u64 flags, u64 user_sig, u64 sigsz);
i64 DoIoUringRegister(u64 fd, u64 op, u64 user_arg, u64 nr_args);
i64 DoPkeyAlloc(u64 flags, u64 init_val);
i64 DoPkeyFree(u64 pkey);
i64 DoPkeyMprotect(u64 addr, u64 len, u64 prot, u64 pkey);
i64 DoNameToHandleAt(u64 dirfd, u64 user_path, u64 user_handle, u64 user_mount_id, u64 flags);
i64 DoOpenByHandleAt(u64 mount_fd, u64 user_handle, u64 flags);
i64 DoFsopen(u64 user_fsname, u64 flags);
i64 DoFsconfig(u64 fd, u64 cmd, u64 user_key, u64 user_value, u64 aux);
i64 DoFsmount(u64 fs_fd, u64 flags, u64 attr_flags);
i64 DoFspick(u64 dirfd, u64 user_path, u64 flags);
i64 DoOpenTree(u64 dirfd, u64 user_path, u64 flags);
i64 DoMoveMount(u64 from_dfd, u64 user_from, u64 to_dfd, u64 user_to, u64 flags);
i64 DoMountSetattr(u64 dirfd, u64 user_path, u64 flags, u64 user_uattr, u64 size);
i64 DoLandlockCreateRuleset(u64 user_attr, u64 size, u64 flags);
i64 DoLandlockAddRule(u64 ruleset_fd, u64 rule_type, u64 user_rule_attr, u64 flags);
i64 DoLandlockRestrictSelf(u64 ruleset_fd, u64 flags);

// Keyrings (keyrings.cpp). Per-process 16-slot keyring. add_key /
// request_key + multiplexed keyctl ops (READ / DESCRIBE / UPDATE /
// SETPERM / SEARCH / INVALIDATE / CLEAR / etc.). "user" + "logon"
// types only; "asymmetric" / "encrypted" return -EOPNOTSUPP.
i64 DoAddKey(u64 user_type, u64 user_desc, u64 user_payload, u64 plen, u64 keyring);
i64 DoRequestKey(u64 user_type, u64 user_desc, u64 user_callout, u64 dest_keyring);
i64 DoKeyctl(u64 op, u64 a2, u64 a3, u64 a4, u64 a5);

// Modern pidfd signaling. pidfd_open allocates a LinuxFd
// (state 12, first_cluster = pid) that pins the target Process
// via ProcessRetain; close drops the ref. pidfd_send_signal
// resolves the pidfd back to the target Process and forwards
// to the real LinuxSignalDeliver path.
i64 DoPidfdOpen(u64 pid, u64 flags);
i64 DoPidfdSendSignal(u64 pidfd, u64 sig, u64 user_info, u64 flags);
i64 DoPidfdGetfd(u64 pidfd, u64 target_fd, u64 flags);

// Global pidfd-exit waitqueue. Wakes every poller blocked
// on a pidfd whenever ANY Linux process exits. Sub-GAP: a
// per-pid waitqueue would scope the wake — the global form
// causes spurious wakes when an unrelated process exits, but
// the predicate (`SchedIsPidZombie` etc.) is re-evaluated on
// wake so correctness holds. Used by:
//   - DoExitGroup     — calls LinuxPidfdExitWake() on the way out.
//   - DoEpollWait     — when at least one watched fd is a
//                       state-12 pidfd, sleeps on the queue
//                       instead of via SchedSleepTicks, so
//                       wake-on-exit latency is bounded by
//                       process-exit ordering instead of the
//                       100 ms timer cadence.
void LinuxPidfdExitWake();
sched::WaitQueue* LinuxPidfdExitWq();

// True iff `p` has at least one pidfd (state == 12) in its
// linux_fds[] table. Cheap (16-slot scan); used by DoEpollWait
// to decide whether to sleep on the pidfd-exit waitqueue.
bool LinuxProcessHasPidfd(const core::Process* p);

// Kernel-level zero-copy fd-to-fd I/O. v0 implementations bounce
// through a 1 KiB on-stack buffer (no actual zero-copy yet, but
// the syscall surface works so callers don't need to roll their
// own pipe-pumping loops). splice/tee share a 1 KiB chunk; vmsplice
// handles only the iovec→pipe direction.
i64 DoSplice(u64 fd_in, u64 user_off_in, u64 fd_out, u64 user_off_out, u64 len, u64 flags);
i64 DoTee(u64 fd_in, u64 fd_out, u64 len, u64 flags);
i64 DoVmsplice(u64 fd, u64 user_iov, u64 nr_segs, u64 flags);

i64 DoRtSigaction(u64 signum, u64 new_act, u64 old_act, u64 sigsetsize);

// Deliver a Linux signal to `target`. Looks up the target's
// sigaction[sig]; for SIG_DFL with a fatal default action, kills
// every task in target via SchedKillByProcess and stamps
// linux_was_signaled / linux_exit_signal on the process so the
// parent's wait4 surfaces the right wstatus. SIG_IGN drops the
// signal. User handlers are pushed onto linux_pending_signals so
// signalfd / rt_sigpending can observe them, but no in-process
// trampoline runs (sub-GAP: real handler delivery requires a
// signal-frame builder + sigreturn). Returns 0 on success;
// signum out of range returns -EINVAL.
//
// Safe to call from any kernel context — IRQ-off bracketed
// internally for the bitmap mutation.
i64 LinuxSignalDeliver(core::Process* target, u32 signum);

// True iff signum has a fatal default action (SIGTERM / SIGKILL /
// SIGINT / SIGABRT / SIGSEGV / SIGFPE / SIGBUS / SIGHUP / SIGQUIT /
// SIGPIPE / SIGUSR1 / SIGUSR2). Non-fatal signals (SIGCHLD /
// SIGCONT / SIGURG / SIGWINCH / SIGSTOP) just sit in the pending
// bitmap. SIGSTOP / SIGCONT have stop/continue semantics in
// real Linux; v0 treats them as non-fatal queues only.
bool LinuxSignalIsFatalDefault(u32 signum);
i64 DoRtSigprocmask(u64 how, u64 user_set, u64 user_oldset, u64 sigsetsize);
i64 DoSigaltstack(u64 ss, u64 old_ss);
i64 DoRtSigreturn(arch::TrapFrame* frame);
i64 DoRtSigpending(u64 user_set, u64 sigsetsize);
i64 DoRtSigsuspend(u64 user_mask, u64 sigsetsize);
i64 DoRtSigtimedwait(u64 user_mask, u64 user_info, u64 user_ts, u64 sigsetsize);

// Time / clock handlers (syscall_time.cpp). NowNs is the
// HPET-derived "nanoseconds since boot" reading every Linux
// clock currently bottoms out in (CLOCK_REALTIME ≈ boot in v0).
// LinuxNowNs in the public wrapper layer forwards to it.
u64 NowNs();
i64 DoClockGetTime(u64 clk_id, u64 user_ts);
i64 DoGettimeofday(u64 user_tv, u64 user_tz);
i64 DoTime(u64 user_tloc);
i64 DoNanosleep(u64 user_req, u64 user_rem);
i64 DoTimes(u64 user_buf);
i64 DoClockGetres(u64 clk_id, u64 user_res);
i64 DoClockNanosleep(u64 clk_id, u64 flags, u64 user_req, u64 user_rem);

// Real clock-mutator handlers. v0 maintains a single signed
// `g_realtime_offset_ns` added to NowNs() on CLOCK_REALTIME reads;
// CLOCK_MONOTONIC / boot-relative clocks ignore the offset.
// Cap-gated by kCapDebug — Linux's CAP_SYS_TIME analog in v0 (no
// dedicated time-set cap yet). Untrusted callers keep their pre-
// slice behaviour (-EPERM) so existing sandbox profiles are
// unchanged. clock_adjtime / adjtimex stay STUB until a struct-timex
// definition lands; the dispatch arms for them route through the
// helpers here so the cap probe is consistent.
i64 DoClockSettime(u64 clk_id, u64 user_ts);
i64 DoSettimeofday(u64 user_tv, u64 user_tz);
i64 DoClockAdjtime(u64 clk_id, u64 user_buf);
i64 DoAdjtimex(u64 user_buf);

// Read the live realtime offset (signed ns). Exposed for any other
// TU that needs to format a wall-clock time (e.g. uname-style date
// printing, log timestamping). Monotonic readers should keep using
// NowNs() directly.
i64 LinuxRealtimeOffsetNs();

// Scheduler-policy handlers (syscall_sched.cpp). v0 has one real
// scheduler (round-robin kernel threads) and BSP-only SMP, so
// every handler reports SCHED_OTHER on CPU 0 and rejects
// real-time class transitions with -EPERM.
i64 DoSchedSetaffinity(u64 pid, u64 cpusetsize, u64 user_mask);
i64 DoSchedGetaffinity(u64 pid, u64 cpusetsize, u64 user_mask);
i64 DoSchedGetscheduler(u64 pid);
i64 DoSchedSetscheduler(u64 pid, u64 policy, u64 user_param);
i64 DoSchedGetparam(u64 pid, u64 user_param);
i64 DoSchedSetparam(u64 pid, u64 user_param);
i64 DoSchedGetPriorityMax(u64 policy);
i64 DoSchedGetPriorityMin(u64 policy);
i64 DoSchedRrGetInterval(u64 pid, u64 user_ts);

// Credential handlers (syscall_cred.cpp). All are uid-0/gid-0
// no-ops in v0 — DuetOS has no Linux-style user account model.
i64 DoGetUid();
i64 DoGetGid();
i64 DoGetEuid();
i64 DoGetEgid();
i64 DoSetuid(u64 uid);
i64 DoSetgid(u64 gid);
i64 DoSetreuid(u64 ruid, u64 euid);
i64 DoSetregid(u64 rgid, u64 egid);
i64 DoSetresuid(u64 ruid, u64 euid, u64 suid);
i64 DoSetresgid(u64 rgid, u64 egid, u64 sgid);
i64 DoGetresuid(u64 user_r, u64 user_e, u64 user_s);
i64 DoGetresgid(u64 user_r, u64 user_e, u64 user_s);
i64 DoSetfsuid(u64 uid);
i64 DoSetfsgid(u64 gid);
i64 DoGetgroups(u64 size, u64 user_list);
i64 DoSetgroups(u64 size, u64 user_list);
i64 DoCapget(u64 user_hdr, u64 user_data);
i64 DoCapset(u64 user_hdr, u64 user_data);

} // namespace duetos::subsystems::linux::internal
