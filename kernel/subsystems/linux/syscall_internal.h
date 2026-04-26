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

#include "../../core/types.h"

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
inline constexpr i64 kEFAULT = -14;
inline constexpr i64 kEISDIR = -21;
inline constexpr i64 kEINVAL = -22;
inline constexpr i64 kENFILE = -23;
inline constexpr i64 kEMFILE = -24;
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
i64 DoPipe(u64 user_fds);
i64 DoPipe2(u64 user_fds, u64 flags);
i64 DoWait4(u64 pid, u64 user_status, u64 options, u64 user_rusage);
i64 DoWaitid(u64 idtype, u64 id, u64 user_info, u64 options, u64 user_rusage);
i64 DoEventfd(u64 initval, u64 flags);
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
i64 DoInotifyInit();
i64 DoInotifyInit1(u64 flags);

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

// File handlers (syscall_file.cpp). open / close / stat / fstat
// / lstat / access / openat / newfstatat. open snapshots the
// FAT32 entry into the per-process linux_fds[16] table; stat
// fills a 144-byte Linux struct stat from the entry; lstat is
// identical (no symlinks); openat / newfstatat enforce the
// AT_FDCWD-only constraint via AtFdCwdOnly.
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
i64 DoRtSigaction(u64 signum, u64 new_act, u64 old_act, u64 sigsetsize);
i64 DoRtSigprocmask(u64 how, u64 user_set, u64 user_oldset, u64 sigsetsize);
i64 DoSigaltstack(u64 ss, u64 old_ss);
i64 DoRtSigreturn();
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
