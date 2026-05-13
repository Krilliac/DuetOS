# Syscall ABI Coverage Matrix

> **Audience:** ABI consumers, PE/Linux thunk authors, kernel hackers
>
> **Execution context:** N/A (specification)
>
> **Maturity:** ABI commitment — once a syscall number is published it is forever

## Overview

This page is the cross-ABI coverage matrix for every syscall surface
DuetOS exposes (native `int 0x80`, Win32 NT, Linux). The numeric IDs,
status, and owner-file columns are auto-generated.

For the live native handler list (numbered against
`kernel/syscall/syscall_names.def`), see the auto-block at the bottom
of this page; it is refreshed by `docs/sync-wiki.sh sync`. The same
data is also exported as machine-readable
[`docs/syscall-abi-matrix.csv`](../../docs/syscall-abi-matrix.csv) and
[`docs/syscall-abi-matrix.json`](../../docs/syscall-abi-matrix.json).

For the calling-convention rules and the relationship between syscalls
and capabilities, see [Syscalls](../kernel/Syscalls.md) and
[Capabilities](../security/Capabilities.md).

## Coverage Matrix

_Auto-generated coverage matrix; do not edit by hand._

| ABI | number | name | status | owner file/function | fallback behavior |
| --- | ---: | --- | --- | --- | --- |
| linux | 0 | `read` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 1 | `write` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 2 | `open` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 3 | `close` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 4 | `stat` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 5 | `fstat` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 6 | `lstat` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 7 | `poll` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 8 | `lseek` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 9 | `mmap` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 10 | `mprotect` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 11 | `munmap` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 12 | `brk` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 13 | `rt_sigaction` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 14 | `rt_sigprocmask` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 15 | `rt_sigreturn` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 16 | `ioctl` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 17 | `pread64` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 18 | `pwrite64` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 19 | `readv` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 20 | `writev` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 21 | `access` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 22 | `pipe` | translated | `kernel/subsystems/translation/translate.cpp::TranslateDeliberateEnosys` | synthetic:enosys-no-ipc |
| linux | 23 | `select` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 24 | `sched_yield` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 25 | `mremap` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 26 | `msync` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 27 | `mincore` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 28 | `madvise` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 29 | `shmget` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 30 | `shmat` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 31 | `shmctl` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 32 | `dup` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 33 | `dup2` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 34 | `pause` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 35 | `nanosleep` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 36 | `getitimer` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 37 | `alarm` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 38 | `setitimer` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 39 | `getpid` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 40 | `sendfile` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 41 | `socket` | translated | `kernel/subsystems/translation/translate.cpp::TranslateDeliberateEnosys` | synthetic:enosys-no-ipc |
| linux | 42 | `connect` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 43 | `accept` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 44 | `sendto` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 45 | `recvfrom` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 46 | `sendmsg` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 47 | `recvmsg` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 48 | `shutdown` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 49 | `bind` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 50 | `listen` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 51 | `getsockname` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 52 | `getpeername` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 53 | `socketpair` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 54 | `setsockopt` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 55 | `getsockopt` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 56 | `clone` | translated | `kernel/subsystems/translation/translate.cpp::TranslateDeliberateEnosys` | synthetic:enosys-no-process-create |
| linux | 57 | `fork` | translated | `kernel/subsystems/translation/translate.cpp::TranslateDeliberateEnosys` | synthetic:enosys-no-process-create |
| linux | 58 | `vfork` | translated | `kernel/subsystems/translation/translate.cpp::TranslateDeliberateEnosys` | synthetic:enosys-no-process-create |
| linux | 59 | `execve` | translated | `kernel/subsystems/translation/translate.cpp::TranslateDeliberateEnosys` | synthetic:enosys-no-process-create |
| linux | 60 | `exit` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 61 | `wait4` | translated | `kernel/subsystems/translation/translate.cpp::TranslateDeliberateEnosys` | synthetic:enosys-no-process-create |
| linux | 62 | `kill` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 63 | `uname` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 64 | `semget` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 65 | `semop` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 66 | `semctl` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 67 | `shmdt` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 68 | `msgget` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 69 | `msgsnd` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 70 | `msgrcv` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 71 | `msgctl` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 72 | `fcntl` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 73 | `flock` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 74 | `fsync` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 75 | `fdatasync` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 76 | `truncate` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 77 | `ftruncate` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 78 | `getdents` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 79 | `getcwd` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 80 | `chdir` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 81 | `fchdir` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 82 | `rename` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 83 | `mkdir` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 84 | `rmdir` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 85 | `creat` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 86 | `link` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 87 | `unlink` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 88 | `symlink` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 89 | `readlink` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 90 | `chmod` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 91 | `fchmod` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 92 | `chown` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 93 | `fchown` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 94 | `lchown` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 95 | `umask` | translated | `kernel/subsystems/translation/translate.cpp::TranslateUmask` | synthetic:022-default |
| linux | 96 | `gettimeofday` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 97 | `getrlimit` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 98 | `getrusage` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 99 | `sysinfo` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 100 | `times` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 101 | `ptrace` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 102 | `getuid` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 103 | `syslog` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 104 | `getgid` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 105 | `setuid` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 106 | `setgid` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 107 | `geteuid` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 108 | `getegid` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 109 | `setpgid` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 110 | `getppid` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 111 | `getpgrp` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 112 | `setsid` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 113 | `setreuid` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 114 | `setregid` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 115 | `getgroups` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 116 | `setgroups` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 117 | `setresuid` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 118 | `getresuid` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 119 | `setresgid` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 120 | `getresgid` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 121 | `getpgid` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 122 | `setfsuid` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 123 | `setfsgid` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 124 | `getsid` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 125 | `capget` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 126 | `capset` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 127 | `rt_sigpending` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 128 | `rt_sigtimedwait` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 129 | `rt_sigqueueinfo` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 130 | `rt_sigsuspend` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 131 | `sigaltstack` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 132 | `utime` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 133 | `mknod` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 134 | `uselib` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 135 | `personality` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 136 | `ustat` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 137 | `statfs` | translated | `kernel/subsystems/translation/translate.cpp::TranslateStatfs` | synthetic:fat32-style-statfs |
| linux | 138 | `fstatfs` | translated | `kernel/subsystems/translation/translate.cpp::TranslateStatfs` | synthetic:fat32-style-statfs |
| linux | 139 | `sysfs` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 140 | `getpriority` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 141 | `setpriority` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 142 | `sched_setparam` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 143 | `sched_getparam` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 144 | `sched_setscheduler` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 145 | `sched_getscheduler` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 146 | `sched_get_priority_max` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 147 | `sched_get_priority_min` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 148 | `sched_rr_get_interval` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 149 | `mlock` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 150 | `munlock` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 151 | `mlockall` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 152 | `munlockall` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 153 | `vhangup` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 154 | `modify_ldt` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 155 | `pivot_root` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 156 | `_sysctl` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 157 | `prctl` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 158 | `arch_prctl` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 159 | `adjtimex` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 160 | `setrlimit` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 161 | `chroot` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 162 | `sync` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 163 | `acct` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 164 | `settimeofday` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 165 | `mount` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 166 | `umount2` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 167 | `swapon` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 168 | `swapoff` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 169 | `reboot` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 170 | `sethostname` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 171 | `setdomainname` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 172 | `iopl` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 173 | `ioperm` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 174 | `create_module` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 175 | `init_module` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 176 | `delete_module` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 177 | `get_kernel_syms` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 178 | `query_module` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 179 | `quotactl` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 180 | `nfsservctl` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 181 | `getpmsg` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 182 | `putpmsg` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 183 | `afs_syscall` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 184 | `tuxcall` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 185 | `security` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 186 | `gettid` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 187 | `readahead` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 188 | `setxattr` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 189 | `lsetxattr` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 190 | `fsetxattr` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 191 | `getxattr` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 192 | `lgetxattr` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 193 | `fgetxattr` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 194 | `listxattr` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 195 | `llistxattr` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 196 | `flistxattr` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 197 | `removexattr` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 198 | `lremovexattr` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 199 | `fremovexattr` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 200 | `tkill` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 201 | `time` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 202 | `futex` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 203 | `sched_setaffinity` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 204 | `sched_getaffinity` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 205 | `set_thread_area` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 206 | `io_setup` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 207 | `io_destroy` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 208 | `io_getevents` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 209 | `io_submit` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 210 | `io_cancel` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 211 | `get_thread_area` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 212 | `lookup_dcookie` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 213 | `epoll_create` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 214 | `epoll_ctl_old` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 215 | `epoll_wait_old` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 216 | `remap_file_pages` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 217 | `getdents64` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 218 | `set_tid_address` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 219 | `restart_syscall` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 220 | `semtimedop` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 221 | `fadvise64` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 222 | `timer_create` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 223 | `timer_settime` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 224 | `timer_gettime` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 225 | `timer_getoverrun` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 226 | `timer_delete` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 227 | `clock_settime` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 228 | `clock_gettime` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 229 | `clock_getres` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 230 | `clock_nanosleep` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 231 | `exit_group` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 232 | `epoll_wait` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 233 | `epoll_ctl` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 234 | `tgkill` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 235 | `utimes` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 236 | `vserver` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 237 | `mbind` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 238 | `set_mempolicy` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 239 | `get_mempolicy` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 240 | `mq_open` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 241 | `mq_unlink` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 242 | `mq_timedsend` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 243 | `mq_timedreceive` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 244 | `mq_notify` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 245 | `mq_getsetattr` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 246 | `kexec_load` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 247 | `waitid` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 248 | `add_key` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 249 | `request_key` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 250 | `keyctl` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 251 | `ioprio_set` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 252 | `ioprio_get` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 253 | `inotify_init` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 254 | `inotify_add_watch` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 255 | `inotify_rm_watch` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 256 | `migrate_pages` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 257 | `openat` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 258 | `mkdirat` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 259 | `mknodat` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 260 | `fchownat` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 261 | `futimesat` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 262 | `newfstatat` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 263 | `unlinkat` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 264 | `renameat` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 265 | `linkat` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 266 | `symlinkat` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 267 | `readlinkat` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 268 | `fchmodat` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 269 | `faccessat` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 270 | `pselect6` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 271 | `ppoll` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 272 | `unshare` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 273 | `set_robust_list` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 274 | `get_robust_list` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 275 | `splice` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 276 | `tee` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 277 | `sync_file_range` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 278 | `vmsplice` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 279 | `move_pages` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 280 | `utimensat` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 281 | `epoll_pwait` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 282 | `signalfd` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 283 | `timerfd_create` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 284 | `eventfd` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 285 | `fallocate` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 286 | `timerfd_settime` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 287 | `timerfd_gettime` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 288 | `accept4` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 289 | `signalfd4` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 290 | `eventfd2` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 291 | `epoll_create1` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 292 | `dup3` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 293 | `pipe2` | translated | `kernel/subsystems/translation/translate.cpp::TranslateDeliberateEnosys` | synthetic:enosys-no-ipc |
| linux | 294 | `inotify_init1` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 295 | `preadv` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 296 | `pwritev` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 297 | `rt_tgsigqueueinfo` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 298 | `perf_event_open` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 299 | `recvmmsg` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 300 | `fanotify_init` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 301 | `fanotify_mark` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 302 | `prlimit64` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 303 | `name_to_handle_at` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 304 | `open_by_handle_at` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 305 | `clock_adjtime` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 306 | `syncfs` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 307 | `sendmmsg` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 308 | `setns` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 309 | `getcpu` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 310 | `process_vm_readv` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 311 | `process_vm_writev` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 312 | `kcmp` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 313 | `finit_module` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 314 | `sched_setattr` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 315 | `sched_getattr` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 316 | `renameat2` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 317 | `seccomp` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 318 | `getrandom` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 319 | `memfd_create` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 320 | `kexec_file_load` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 321 | `bpf` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 322 | `execveat` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 323 | `userfaultfd` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 324 | `membarrier` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 325 | `mlock2` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 326 | `copy_file_range` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 327 | `preadv2` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 328 | `pwritev2` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 329 | `pkey_mprotect` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 330 | `pkey_alloc` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 331 | `pkey_free` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 332 | `statx` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 333 | `io_pgetevents` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 334 | `rseq` | translated | `kernel/subsystems/translation/translate.cpp::TranslateRseq` | synthetic:enosys-deliberate |
| linux | 424 | `pidfd_send_signal` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 425 | `io_uring_setup` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 426 | `io_uring_enter` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 427 | `io_uring_register` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 428 | `open_tree` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 429 | `move_mount` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 430 | `fsopen` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 431 | `fsconfig` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 432 | `fsmount` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 433 | `fspick` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 434 | `pidfd_open` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 435 | `clone3` | translated | `kernel/subsystems/translation/translate.cpp::TranslateDeliberateEnosys` | synthetic:enosys-no-process-create |
| linux | 436 | `close_range` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 437 | `openat2` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 438 | `pidfd_getfd` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 439 | `faccessat2` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 440 | `process_madvise` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 441 | `epoll_pwait2` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 442 | `mount_setattr` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 443 | `quotactl_fd` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 444 | `landlock_create_ruleset` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 445 | `landlock_add_rule` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 446 | `landlock_restrict_self` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 447 | `memfd_secret` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 448 | `process_mrelease` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 449 | `futex_waitv` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 450 | `set_mempolicy_home_node` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 451 | `cachestat` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 452 | `fchmodat2` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 453 | `map_shadow_stack` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 454 | `futex_wake` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 455 | `futex_wait` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 456 | `futex_requeue` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 457 | `statmount` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 458 | `listmount` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 459 | `lsm_get_self_attr` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 460 | `lsm_set_self_attr` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 461 | `lsm_list_modules` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| linux | 462 | `mseal` | unimplemented | `kernel/subsystems/linux/syscall.cpp::DispatchSyscall` | -ENOSYS |
| native | 0 | `SYS_EXIT` | implemented | `kernel/syscall/syscall.h::SyscallNumber` | none (native syscall entry) |
| native | 1 | `SYS_GETPID` | implemented | `kernel/syscall/syscall.h::SyscallNumber` | none (native syscall entry) |
| native | 2 | `SYS_WRITE` | implemented | `kernel/syscall/syscall.h::SyscallNumber` | none (native syscall entry) |
| native | 3 | `SYS_YIELD` | implemented | `kernel/syscall/syscall.h::SyscallNumber` | none (native syscall entry) |
| native | 4 | `SYS_STAT` | implemented | `kernel/syscall/syscall.h::SyscallNumber` | none (native syscall entry) |
| native | 5 | `SYS_READ` | implemented | `kernel/syscall/syscall.h::SyscallNumber` | none (native syscall entry) |
| native | 6 | `SYS_DROPCAPS` | implemented | `kernel/syscall/syscall.h::SyscallNumber` | none (native syscall entry) |
| native | 7 | `SYS_SPAWN` | implemented | `kernel/syscall/syscall.h::SyscallNumber` | none (native syscall entry) |
| native | 8 | `SYS_GETPROCID` | implemented | `kernel/syscall/syscall.h::SyscallNumber` | none (native syscall entry) |
| native | 9 | `SYS_GETLASTERROR` | implemented | `kernel/syscall/syscall.h::SyscallNumber` | none (native syscall entry) |
| native | 10 | `SYS_SETLASTERROR` | implemented | `kernel/syscall/syscall.h::SyscallNumber` | none (native syscall entry) |
| native | 11 | `SYS_HEAP_ALLOC` | implemented | `kernel/syscall/syscall.h::SyscallNumber` | none (native syscall entry) |
| native | 12 | `SYS_HEAP_FREE` | implemented | `kernel/syscall/syscall.h::SyscallNumber` | none (native syscall entry) |
| native | 13 | `SYS_PERF_COUNTER` | implemented | `kernel/syscall/syscall.h::SyscallNumber` | none (native syscall entry) |
| native | 14 | `SYS_HEAP_SIZE` | implemented | `kernel/syscall/syscall.h::SyscallNumber` | none (native syscall entry) |
| native | 15 | `SYS_HEAP_REALLOC` | implemented | `kernel/syscall/syscall.h::SyscallNumber` | none (native syscall entry) |
| native | 16 | `SYS_WIN32_MISS_LOG` | implemented | `kernel/syscall/syscall.h::SyscallNumber` | none (native syscall entry) |
| native | 17 | `SYS_GETTIME_FT` | implemented | `kernel/syscall/syscall.h::SyscallNumber` | none (native syscall entry) |
| native | 18 | `SYS_NOW_NS` | implemented | `kernel/syscall/syscall.h::SyscallNumber` | none (native syscall entry) |
| native | 19 | `SYS_SLEEP_MS` | implemented | `kernel/syscall/syscall.h::SyscallNumber` | none (native syscall entry) |
| native | 20 | `SYS_FILE_OPEN` | implemented | `kernel/syscall/syscall.h::SyscallNumber` | none (native syscall entry) |
| native | 21 | `SYS_FILE_READ` | implemented | `kernel/syscall/syscall.h::SyscallNumber` | none (native syscall entry) |
| native | 22 | `SYS_FILE_CLOSE` | implemented | `kernel/syscall/syscall.h::SyscallNumber` | none (native syscall entry) |
| native | 23 | `SYS_FILE_SEEK` | implemented | `kernel/syscall/syscall.h::SyscallNumber` | none (native syscall entry) |
| native | 24 | `SYS_FILE_FSTAT` | implemented | `kernel/syscall/syscall.h::SyscallNumber` | none (native syscall entry) |
| native | 25 | `SYS_MUTEX_CREATE` | implemented | `kernel/syscall/syscall.h::SyscallNumber` | none (native syscall entry) |
| native | 26 | `SYS_MUTEX_WAIT` | implemented | `kernel/syscall/syscall.h::SyscallNumber` | none (native syscall entry) |
| native | 27 | `SYS_MUTEX_RELEASE` | implemented | `kernel/syscall/syscall.h::SyscallNumber` | none (native syscall entry) |
| native | 28 | `SYS_VMAP` | implemented | `kernel/syscall/syscall.h::SyscallNumber` | none (native syscall entry) |
| native | 29 | `SYS_VUNMAP` | implemented | `kernel/syscall/syscall.h::SyscallNumber` | none (native syscall entry) |
| native | 30 | `SYS_EVENT_CREATE` | implemented | `kernel/syscall/syscall.h::SyscallNumber` | none (native syscall entry) |
| native | 31 | `SYS_EVENT_SET` | implemented | `kernel/syscall/syscall.h::SyscallNumber` | none (native syscall entry) |
| native | 32 | `SYS_EVENT_RESET` | implemented | `kernel/syscall/syscall.h::SyscallNumber` | none (native syscall entry) |
| native | 33 | `SYS_EVENT_WAIT` | implemented | `kernel/syscall/syscall.h::SyscallNumber` | none (native syscall entry) |
| native | 34 | `SYS_TLS_ALLOC` | implemented | `kernel/syscall/syscall.h::SyscallNumber` | none (native syscall entry) |
| native | 35 | `SYS_TLS_FREE` | implemented | `kernel/syscall/syscall.h::SyscallNumber` | none (native syscall entry) |
| native | 36 | `SYS_TLS_GET` | implemented | `kernel/syscall/syscall.h::SyscallNumber` | none (native syscall entry) |
| native | 37 | `SYS_TLS_SET` | implemented | `kernel/syscall/syscall.h::SyscallNumber` | none (native syscall entry) |
| native | 38 | `SYS_BP_INSTALL` | implemented | `kernel/syscall/syscall.h::SyscallNumber` | none (native syscall entry) |
| native | 39 | `SYS_BP_REMOVE` | implemented | `kernel/syscall/syscall.h::SyscallNumber` | none (native syscall entry) |
| native | 40 | `SYS_GETTIME_ST` | implemented | `kernel/syscall/syscall.h::SyscallNumber` | none (native syscall entry) |
| native | 41 | `SYS_ST_TO_FT` | implemented | `kernel/syscall/syscall.h::SyscallNumber` | none (native syscall entry) |
| native | 42 | `SYS_FT_TO_ST` | implemented | `kernel/syscall/syscall.h::SyscallNumber` | none (native syscall entry) |
| native | 43 | `SYS_FILE_WRITE` | implemented | `kernel/syscall/syscall.h::SyscallNumber` | none (native syscall entry) |
| native | 44 | `SYS_FILE_CREATE` | implemented | `kernel/syscall/syscall.h::SyscallNumber` | none (native syscall entry) |
| native | 45 | `SYS_THREAD_CREATE` | implemented | `kernel/syscall/syscall.h::SyscallNumber` | none (native syscall entry) |
| native | 46 | `SYS_DEBUG_PRINT` | implemented | `kernel/syscall/syscall.h::SyscallNumber` | none (native syscall entry) |
| native | 47 | `SYS_MEM_STATUS` | implemented | `kernel/syscall/syscall.h::SyscallNumber` | none (native syscall entry) |
| native | 48 | `SYS_WAIT_MULTI` | implemented | `kernel/syscall/syscall.h::SyscallNumber` | none (native syscall entry) |
| native | 49 | `SYS_SYSTEM_INFO` | implemented | `kernel/syscall/syscall.h::SyscallNumber` | none (native syscall entry) |
| native | 50 | `SYS_DEBUG_PRINTW` | implemented | `kernel/syscall/syscall.h::SyscallNumber` | none (native syscall entry) |
| native | 51 | `SYS_SEM_CREATE` | implemented | `kernel/syscall/syscall.h::SyscallNumber` | none (native syscall entry) |
| native | 52 | `SYS_SEM_RELEASE` | implemented | `kernel/syscall/syscall.h::SyscallNumber` | none (native syscall entry) |
| native | 53 | `SYS_SEM_WAIT` | implemented | `kernel/syscall/syscall.h::SyscallNumber` | none (native syscall entry) |
| native | 54 | `SYS_THREAD_WAIT` | implemented | `kernel/syscall/syscall.h::SyscallNumber` | none (native syscall entry) |
| native | 55 | `SYS_THREAD_EXIT_CODE` | implemented | `kernel/syscall/syscall.h::SyscallNumber` | none (native syscall entry) |
| native | 56 | `SYS_NT_INVOKE` | implemented | `kernel/syscall/syscall.h::SyscallNumber` | none (native syscall entry) |
| native | 57 | `SYS_DLL_PROC_ADDRESS` | implemented | `kernel/syscall/syscall.h::SyscallNumber` | none (native syscall entry) |
| native | 58 | `SYS_WIN_CREATE` | implemented | `kernel/syscall/syscall.h::SyscallNumber` | none (native syscall entry) |
| native | 59 | `SYS_WIN_DESTROY` | implemented | `kernel/syscall/syscall.h::SyscallNumber` | none (native syscall entry) |
| native | 60 | `SYS_WIN_SHOW` | implemented | `kernel/syscall/syscall.h::SyscallNumber` | none (native syscall entry) |
| native | 61 | `SYS_WIN_MSGBOX` | implemented | `kernel/syscall/syscall.h::SyscallNumber` | none (native syscall entry) |
| native | 62 | `SYS_WIN_PEEK_MSG` | implemented | `kernel/syscall/syscall.h::SyscallNumber` | none (native syscall entry) |
| native | 63 | `SYS_WIN_GET_MSG` | implemented | `kernel/syscall/syscall.h::SyscallNumber` | none (native syscall entry) |
| native | 64 | `SYS_WIN_POST_MSG` | implemented | `kernel/syscall/syscall.h::SyscallNumber` | none (native syscall entry) |
| native | 65 | `SYS_GDI_FILL_RECT` | implemented | `kernel/syscall/syscall.h::SyscallNumber` | none (native syscall entry) |
| native | 66 | `SYS_GDI_TEXT_OUT` | implemented | `kernel/syscall/syscall.h::SyscallNumber` | none (native syscall entry) |
| native | 67 | `SYS_GDI_RECTANGLE` | implemented | `kernel/syscall/syscall.h::SyscallNumber` | none (native syscall entry) |
| native | 68 | `SYS_GDI_CLEAR` | implemented | `kernel/syscall/syscall.h::SyscallNumber` | none (native syscall entry) |
| native | 69 | `SYS_WIN_MOVE` | implemented | `kernel/syscall/syscall.h::SyscallNumber` | none (native syscall entry) |
| native | 70 | `SYS_WIN_GET_RECT` | implemented | `kernel/syscall/syscall.h::SyscallNumber` | none (native syscall entry) |
| native | 71 | `SYS_WIN_SET_TEXT` | implemented | `kernel/syscall/syscall.h::SyscallNumber` | none (native syscall entry) |
| native | 72 | `SYS_WIN_TIMER_SET` | implemented | `kernel/syscall/syscall.h::SyscallNumber` | none (native syscall entry) |
| native | 73 | `SYS_WIN_TIMER_KILL` | implemented | `kernel/syscall/syscall.h::SyscallNumber` | none (native syscall entry) |
| native | 74 | `SYS_GDI_LINE` | implemented | `kernel/syscall/syscall.h::SyscallNumber` | none (native syscall entry) |
| native | 75 | `SYS_GDI_ELLIPSE` | implemented | `kernel/syscall/syscall.h::SyscallNumber` | none (native syscall entry) |
| native | 76 | `SYS_GDI_SET_PIXEL` | implemented | `kernel/syscall/syscall.h::SyscallNumber` | none (native syscall entry) |
| native | 77 | `SYS_WIN_GET_KEYSTATE` | implemented | `kernel/syscall/syscall.h::SyscallNumber` | none (native syscall entry) |
| native | 78 | `SYS_WIN_GET_CURSOR` | implemented | `kernel/syscall/syscall.h::SyscallNumber` | none (native syscall entry) |
| native | 79 | `SYS_WIN_SET_CURSOR` | implemented | `kernel/syscall/syscall.h::SyscallNumber` | none (native syscall entry) |
| native | 80 | `SYS_WIN_SET_CAPTURE` | implemented | `kernel/syscall/syscall.h::SyscallNumber` | none (native syscall entry) |
| native | 81 | `SYS_WIN_RELEASE_CAPTURE` | implemented | `kernel/syscall/syscall.h::SyscallNumber` | none (native syscall entry) |
| native | 82 | `SYS_WIN_GET_CAPTURE` | implemented | `kernel/syscall/syscall.h::SyscallNumber` | none (native syscall entry) |
| native | 83 | `SYS_WIN_CLIP_SET_TEXT` | implemented | `kernel/syscall/syscall.h::SyscallNumber` | none (native syscall entry) |
| native | 84 | `SYS_WIN_CLIP_GET_TEXT` | implemented | `kernel/syscall/syscall.h::SyscallNumber` | none (native syscall entry) |
| native | 85 | `SYS_WIN_GET_LONG` | implemented | `kernel/syscall/syscall.h::SyscallNumber` | none (native syscall entry) |
| native | 86 | `SYS_WIN_SET_LONG` | implemented | `kernel/syscall/syscall.h::SyscallNumber` | none (native syscall entry) |
| native | 87 | `SYS_WIN_INVALIDATE` | implemented | `kernel/syscall/syscall.h::SyscallNumber` | none (native syscall entry) |
| native | 88 | `SYS_WIN_VALIDATE` | implemented | `kernel/syscall/syscall.h::SyscallNumber` | none (native syscall entry) |
| native | 89 | `SYS_WIN_GET_ACTIVE` | implemented | `kernel/syscall/syscall.h::SyscallNumber` | none (native syscall entry) |
| native | 90 | `SYS_WIN_SET_ACTIVE` | implemented | `kernel/syscall/syscall.h::SyscallNumber` | none (native syscall entry) |
| native | 91 | `SYS_WIN_GET_METRIC` | implemented | `kernel/syscall/syscall.h::SyscallNumber` | none (native syscall entry) |
| native | 92 | `SYS_WIN_ENUM` | implemented | `kernel/syscall/syscall.h::SyscallNumber` | none (native syscall entry) |
| native | 93 | `SYS_WIN_FIND` | implemented | `kernel/syscall/syscall.h::SyscallNumber` | none (native syscall entry) |
| native | 94 | `SYS_WIN_SET_PARENT` | implemented | `kernel/syscall/syscall.h::SyscallNumber` | none (native syscall entry) |
| native | 95 | `SYS_WIN_GET_PARENT` | implemented | `kernel/syscall/syscall.h::SyscallNumber` | none (native syscall entry) |
| native | 96 | `SYS_WIN_GET_RELATED` | implemented | `kernel/syscall/syscall.h::SyscallNumber` | none (native syscall entry) |
| native | 97 | `SYS_WIN_SET_FOCUS` | implemented | `kernel/syscall/syscall.h::SyscallNumber` | none (native syscall entry) |
| native | 98 | `SYS_WIN_GET_FOCUS` | implemented | `kernel/syscall/syscall.h::SyscallNumber` | none (native syscall entry) |
| native | 99 | `SYS_WIN_CARET` | implemented | `kernel/syscall/syscall.h::SyscallNumber` | none (native syscall entry) |
| native | 100 | `SYS_WIN_BEEP` | implemented | `kernel/syscall/syscall.h::SyscallNumber` | none (native syscall entry) |
| native | 101 | `SYS_GFX_D3D_STUB` | implemented | `kernel/syscall/syscall.h::SyscallNumber` | none (native syscall entry) |
| native | 102 | `SYS_GDI_BITBLT` | implemented | `kernel/syscall/syscall.h::SyscallNumber` | none (native syscall entry) |
| native | 103 | `SYS_WIN_BEGIN_PAINT` | implemented | `kernel/syscall/syscall.h::SyscallNumber` | none (native syscall entry) |
| native | 104 | `SYS_WIN_END_PAINT` | implemented | `kernel/syscall/syscall.h::SyscallNumber` | none (native syscall entry) |
| native | 105 | `SYS_GDI_FILL_RECT_USER` | implemented | `kernel/syscall/syscall.h::SyscallNumber` | none (native syscall entry) |
| native | 106 | `SYS_GDI_CREATE_COMPAT_DC` | implemented | `kernel/syscall/syscall.h::SyscallNumber` | none (native syscall entry) |
| native | 107 | `SYS_GDI_CREATE_COMPAT_BITMAP` | implemented | `kernel/syscall/syscall.h::SyscallNumber` | none (native syscall entry) |
| native | 108 | `SYS_GDI_CREATE_SOLID_BRUSH` | implemented | `kernel/syscall/syscall.h::SyscallNumber` | none (native syscall entry) |
| native | 109 | `SYS_GDI_GET_STOCK_OBJECT` | implemented | `kernel/syscall/syscall.h::SyscallNumber` | none (native syscall entry) |
| native | 110 | `SYS_GDI_SELECT_OBJECT` | implemented | `kernel/syscall/syscall.h::SyscallNumber` | none (native syscall entry) |
| native | 111 | `SYS_GDI_DELETE_DC` | implemented | `kernel/syscall/syscall.h::SyscallNumber` | none (native syscall entry) |
| native | 112 | `SYS_GDI_DELETE_OBJECT` | implemented | `kernel/syscall/syscall.h::SyscallNumber` | none (native syscall entry) |
| native | 113 | `SYS_GDI_BITBLT_DC` | implemented | `kernel/syscall/syscall.h::SyscallNumber` | none (native syscall entry) |
| native | 114 | `SYS_GDI_SET_TEXT_COLOR` | implemented | `kernel/syscall/syscall.h::SyscallNumber` | none (native syscall entry) |
| native | 115 | `SYS_GDI_SET_BK_COLOR` | implemented | `kernel/syscall/syscall.h::SyscallNumber` | none (native syscall entry) |
| native | 116 | `SYS_GDI_SET_BK_MODE` | implemented | `kernel/syscall/syscall.h::SyscallNumber` | none (native syscall entry) |
| native | 117 | `SYS_GDI_STRETCH_BLT_DC` | implemented | `kernel/syscall/syscall.h::SyscallNumber` | none (native syscall entry) |
| native | 118 | `SYS_GDI_CREATE_PEN` | implemented | `kernel/syscall/syscall.h::SyscallNumber` | none (native syscall entry) |
| native | 119 | `SYS_GDI_MOVE_TO_EX` | implemented | `kernel/syscall/syscall.h::SyscallNumber` | none (native syscall entry) |
| native | 120 | `SYS_GDI_LINE_TO` | implemented | `kernel/syscall/syscall.h::SyscallNumber` | none (native syscall entry) |
| native | 121 | `SYS_GDI_DRAW_TEXT_USER` | implemented | `kernel/syscall/syscall.h::SyscallNumber` | none (native syscall entry) |
| native | 122 | `SYS_GDI_RECTANGLE_FILLED` | implemented | `kernel/syscall/syscall.h::SyscallNumber` | none (native syscall entry) |
| native | 123 | `SYS_GDI_ELLIPSE_FILLED` | implemented | `kernel/syscall/syscall.h::SyscallNumber` | none (native syscall entry) |
| native | 124 | `SYS_GDI_PAT_BLT` | implemented | `kernel/syscall/syscall.h::SyscallNumber` | none (native syscall entry) |
| native | 125 | `SYS_GDI_TEXT_OUT_W` | implemented | `kernel/syscall/syscall.h::SyscallNumber` | none (native syscall entry) |
| native | 126 | `SYS_GDI_DRAW_TEXT_W` | implemented | `kernel/syscall/syscall.h::SyscallNumber` | none (native syscall entry) |
| native | 127 | `SYS_GDI_GET_SYS_COLOR` | implemented | `kernel/syscall/syscall.h::SyscallNumber` | none (native syscall entry) |
| native | 128 | `SYS_GDI_GET_SYS_COLOR_BRUSH` | implemented | `kernel/syscall/syscall.h::SyscallNumber` | none (native syscall entry) |
| native | 129 | `SYS_WIN32_CUSTOM` | implemented | `kernel/syscall/syscall.h::SyscallNumber` | none (native syscall entry) |
| native | 130 | `SYS_REGISTRY` | implemented | `kernel/syscall/syscall.h::SyscallNumber` | none (native syscall entry) |
| native | 131 | `SYS_PROCESS_OPEN` | implemented | `kernel/syscall/syscall.h::SyscallNumber` | none (native syscall entry) |
| native | 132 | `SYS_PROCESS_VM_READ` | implemented | `kernel/syscall/syscall.h::SyscallNumber` | none (native syscall entry) |
| native | 133 | `SYS_PROCESS_VM_WRITE` | implemented | `kernel/syscall/syscall.h::SyscallNumber` | none (native syscall entry) |
| native | 134 | `SYS_PROCESS_VM_QUERY` | implemented | `kernel/syscall/syscall.h::SyscallNumber` | none (native syscall entry) |
| native | 135 | `SYS_THREAD_SUSPEND` | implemented | `kernel/syscall/syscall.h::SyscallNumber` | none (native syscall entry) |
| native | 136 | `SYS_THREAD_RESUME` | implemented | `kernel/syscall/syscall.h::SyscallNumber` | none (native syscall entry) |
| native | 137 | `SYS_THREAD_GET_CONTEXT` | implemented | `kernel/syscall/syscall.h::SyscallNumber` | none (native syscall entry) |
| native | 138 | `SYS_THREAD_SET_CONTEXT` | implemented | `kernel/syscall/syscall.h::SyscallNumber` | none (native syscall entry) |
| native | 139 | `SYS_THREAD_OPEN` | implemented | `kernel/syscall/syscall.h::SyscallNumber` | none (native syscall entry) |
| native | 140 | `SYS_SECTION_CREATE` | implemented | `kernel/syscall/syscall.h::SyscallNumber` | none (native syscall entry) |
| native | 141 | `SYS_SECTION_MAP` | implemented | `kernel/syscall/syscall.h::SyscallNumber` | none (native syscall entry) |
| native | 142 | `SYS_SECTION_UNMAP` | implemented | `kernel/syscall/syscall.h::SyscallNumber` | none (native syscall entry) |
| native | 143 | `SYS_FILE_UNLINK` | implemented | `kernel/syscall/syscall.h::SyscallNumber` | none (native syscall entry) |
| native | 144 | `SYS_FILE_RENAME` | implemented | `kernel/syscall/syscall.h::SyscallNumber` | none (native syscall entry) |
| native | 145 | `SYS_PROCESS_TERMINATE` | implemented | `kernel/syscall/syscall.h::SyscallNumber` | none (native syscall entry) |
| native | 146 | `SYS_THREAD_TERMINATE` | implemented | `kernel/syscall/syscall.h::SyscallNumber` | none (native syscall entry) |
| native | 147 | `SYS_PROCESS_QUERY_INFO` | implemented | `kernel/syscall/syscall.h::SyscallNumber` | none (native syscall entry) |
| native | 148 | `SYS_VM_ALLOCATE` | implemented | `kernel/syscall/syscall.h::SyscallNumber` | none (native syscall entry) |
| native | 149 | `SYS_VM_FREE` | implemented | `kernel/syscall/syscall.h::SyscallNumber` | none (native syscall entry) |
| native | 150 | `SYS_VM_PROTECT` | implemented | `kernel/syscall/syscall.h::SyscallNumber` | none (native syscall entry) |
| native | 151 | `SYS_FILE_QUERY_ATTRIBUTES` | implemented | `kernel/syscall/syscall.h::SyscallNumber` | none (native syscall entry) |
| native | 512 | `native_gapfill_0x200` | translated | `kernel/subsystems/translation/translate.cpp::NativeClockNs` | linux-self:NowNs |
| native | 513 | `native_gapfill_0x201` | translated | `kernel/subsystems/translation/translate.cpp::NativeGetRandom` | synthetic:xorshift-from-rdtsc |
| native | 528 | `native_gapfill_0x210` | translated | `kernel/subsystems/translation/translate.cpp::NativeWin32Alloc` | win32:HeapAlloc |
| native | 529 | `native_gapfill_0x211` | translated | `kernel/subsystems/translation/translate.cpp::NativeWin32Free` | win32:HeapFree |
| nt | 0 | `NtAccessCheck` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 1 | `NtWorkerFactoryWorkerReady` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 2 | `NtAcceptConnectPort` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 3 | `NtMapUserPhysicalPagesScatter` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 4 | `NtWaitForSingleObject` | translated | `kernel/subsystems/win32/nt_syscall_table_generated.h::SYS_MUTEX_WAIT` | routes to native SYS_MUTEX_WAIT |
| nt | 5 | `NtCallbackReturn` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 6 | `NtReadFile` | translated | `kernel/subsystems/win32/nt_syscall_table_generated.h::SYS_FILE_READ` | routes to native SYS_FILE_READ |
| nt | 7 | `NtDeviceIoControlFile` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 8 | `NtWriteFile` | translated | `kernel/subsystems/win32/nt_syscall_table_generated.h::SYS_FILE_WRITE` | routes to native SYS_FILE_WRITE |
| nt | 9 | `NtRemoveIoCompletion` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 10 | `NtReleaseSemaphore` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 11 | `NtReplyWaitReceivePort` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 12 | `NtReplyPort` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 13 | `NtSetInformationThread` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 14 | `NtSetEvent` | translated | `kernel/subsystems/win32/nt_syscall_table_generated.h::SYS_EVENT_SET` | routes to native SYS_EVENT_SET |
| nt | 15 | `NtClose` | translated | `kernel/subsystems/win32/nt_syscall_table_generated.h::SYS_FILE_CLOSE` | routes to native SYS_FILE_CLOSE |
| nt | 16 | `NtQueryObject` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 17 | `NtQueryInformationFile` | translated | `kernel/subsystems/win32/nt_syscall_table_generated.h::SYS_FILE_FSTAT` | routes to native SYS_FILE_FSTAT |
| nt | 18 | `NtOpenKey` | translated | `kernel/subsystems/win32/nt_syscall_table_generated.h::SYS_REGISTRY` | routes to native SYS_REGISTRY |
| nt | 19 | `NtEnumerateValueKey` | translated | `kernel/subsystems/win32/nt_syscall_table_generated.h::SYS_REGISTRY` | routes to native SYS_REGISTRY |
| nt | 20 | `NtFindAtom` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 21 | `NtQueryDefaultLocale` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 22 | `NtQueryKey` | translated | `kernel/subsystems/win32/nt_syscall_table_generated.h::SYS_REGISTRY` | routes to native SYS_REGISTRY |
| nt | 23 | `NtQueryValueKey` | translated | `kernel/subsystems/win32/nt_syscall_table_generated.h::SYS_REGISTRY` | routes to native SYS_REGISTRY |
| nt | 24 | `NtAllocateVirtualMemory` | translated | `kernel/subsystems/win32/nt_syscall_table_generated.h::SYS_VM_ALLOCATE` | routes to native SYS_VM_ALLOCATE |
| nt | 25 | `NtQueryInformationProcess` | translated | `kernel/subsystems/win32/nt_syscall_table_generated.h::SYS_PROCESS_QUERY_INFO` | routes to native SYS_PROCESS_QUERY_INFO |
| nt | 26 | `NtWaitForMultipleObjects32` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 27 | `NtWriteFileGather` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 28 | `NtSetInformationProcess` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 29 | `NtCreateKey` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 30 | `NtFreeVirtualMemory` | translated | `kernel/subsystems/win32/nt_syscall_table_generated.h::SYS_VM_FREE` | routes to native SYS_VM_FREE |
| nt | 31 | `NtImpersonateClientOfPort` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 32 | `NtReleaseMutant` | translated | `kernel/subsystems/win32/nt_syscall_table_generated.h::SYS_MUTEX_RELEASE` | routes to native SYS_MUTEX_RELEASE |
| nt | 33 | `NtQueryInformationToken` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 34 | `NtRequestWaitReplyPort` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 35 | `NtQueryVirtualMemory` | translated | `kernel/subsystems/win32/nt_syscall_table_generated.h::SYS_PROCESS_VM_QUERY` | routes to native SYS_PROCESS_VM_QUERY |
| nt | 36 | `NtOpenThreadToken` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 37 | `NtQueryInformationThread` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 38 | `NtOpenProcess` | translated | `kernel/subsystems/win32/nt_syscall_table_generated.h::SYS_PROCESS_OPEN` | routes to native SYS_PROCESS_OPEN |
| nt | 39 | `NtSetInformationFile` | translated | `kernel/subsystems/win32/nt_syscall_table_generated.h::SYS_FILE_SEEK` | routes to native SYS_FILE_SEEK |
| nt | 40 | `NtMapViewOfSection` | translated | `kernel/subsystems/win32/nt_syscall_table_generated.h::SYS_SECTION_MAP` | routes to native SYS_SECTION_MAP |
| nt | 41 | `NtAccessCheckAndAuditAlarm` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 42 | `NtUnmapViewOfSection` | translated | `kernel/subsystems/win32/nt_syscall_table_generated.h::SYS_SECTION_UNMAP` | routes to native SYS_SECTION_UNMAP |
| nt | 43 | `NtReplyWaitReceivePortEx` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 44 | `NtTerminateProcess` | translated | `kernel/subsystems/win32/nt_syscall_table_generated.h::SYS_PROCESS_TERMINATE` | routes to native SYS_PROCESS_TERMINATE |
| nt | 45 | `NtSetEventBoostPriority` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 46 | `NtReadFileScatter` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 47 | `NtOpenThreadTokenEx` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 48 | `NtOpenProcessTokenEx` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 49 | `NtQueryPerformanceCounter` | translated | `kernel/subsystems/win32/nt_syscall_table_generated.h::SYS_PERF_COUNTER` | routes to native SYS_PERF_COUNTER |
| nt | 50 | `NtEnumerateKey` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 51 | `NtOpenFile` | translated | `kernel/subsystems/win32/nt_syscall_table_generated.h::SYS_FILE_OPEN` | routes to native SYS_FILE_OPEN |
| nt | 52 | `NtDelayExecution` | translated | `kernel/subsystems/win32/nt_syscall_table_generated.h::SYS_SLEEP_MS` | routes to native SYS_SLEEP_MS |
| nt | 53 | `NtQueryDirectoryFile` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 54 | `NtQuerySystemInformation` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 55 | `NtOpenSection` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 56 | `NtQueryTimer` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 57 | `NtFsControlFile` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 58 | `NtWriteVirtualMemory` | translated | `kernel/subsystems/win32/nt_syscall_table_generated.h::SYS_PROCESS_VM_WRITE` | routes to native SYS_PROCESS_VM_WRITE |
| nt | 59 | `NtCloseObjectAuditAlarm` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 60 | `NtDuplicateObject` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 61 | `NtQueryAttributesFile` | translated | `kernel/subsystems/win32/nt_syscall_table_generated.h::SYS_FILE_QUERY_ATTRIBUTES` | routes to native SYS_FILE_QUERY_ATTRIBUTES |
| nt | 62 | `NtClearEvent` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 63 | `NtReadVirtualMemory` | translated | `kernel/subsystems/win32/nt_syscall_table_generated.h::SYS_PROCESS_VM_READ` | routes to native SYS_PROCESS_VM_READ |
| nt | 64 | `NtOpenEvent` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 65 | `NtAdjustPrivilegesToken` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 66 | `NtDuplicateToken` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 67 | `NtContinue` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 68 | `NtQueryDefaultUILanguage` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 69 | `NtQueueApcThread` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 70 | `NtYieldExecution` | translated | `kernel/subsystems/win32/nt_syscall_table_generated.h::SYS_YIELD` | routes to native SYS_YIELD |
| nt | 71 | `NtAddAtom` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 72 | `NtCreateEvent` | translated | `kernel/subsystems/win32/nt_syscall_table_generated.h::SYS_EVENT_CREATE` | routes to native SYS_EVENT_CREATE |
| nt | 73 | `NtQueryVolumeInformationFile` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 74 | `NtCreateSection` | translated | `kernel/subsystems/win32/nt_syscall_table_generated.h::SYS_SECTION_CREATE` | routes to native SYS_SECTION_CREATE |
| nt | 75 | `NtFlushBuffersFile` | translated | `kernel/subsystems/win32/nt_syscall_table_generated.h::SYS_NT_INVOKE` | routes to native SYS_NT_INVOKE |
| nt | 76 | `NtApphelpCacheControl` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 77 | `NtCreateProcessEx` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 78 | `NtCreateThread` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 79 | `NtIsProcessInJob` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 80 | `NtProtectVirtualMemory` | translated | `kernel/subsystems/win32/nt_syscall_table_generated.h::SYS_VM_PROTECT` | routes to native SYS_VM_PROTECT |
| nt | 81 | `NtQuerySection` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 82 | `NtResumeThread` | translated | `kernel/subsystems/win32/nt_syscall_table_generated.h::SYS_THREAD_RESUME` | routes to native SYS_THREAD_RESUME |
| nt | 83 | `NtTerminateThread` | translated | `kernel/subsystems/win32/nt_syscall_table_generated.h::SYS_NT_INVOKE` | routes to native SYS_NT_INVOKE |
| nt | 84 | `NtReadRequestData` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 85 | `NtCreateFile` | translated | `kernel/subsystems/win32/nt_syscall_table_generated.h::SYS_FILE_OPEN` | routes to native SYS_FILE_OPEN |
| nt | 86 | `NtQueryEvent` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 87 | `NtWriteRequestData` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 88 | `NtOpenDirectoryObject` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 89 | `NtAccessCheckByTypeAndAuditAlarm` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 90 | `NtQuerySystemTime` | translated | `kernel/subsystems/win32/nt_syscall_table_generated.h::SYS_GETTIME_FT` | routes to native SYS_GETTIME_FT |
| nt | 91 | `NtWaitForMultipleObjects` | translated | `kernel/subsystems/win32/nt_syscall_table_generated.h::SYS_EVENT_WAIT` | routes to native SYS_EVENT_WAIT |
| nt | 92 | `NtSetInformationObject` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 93 | `NtCancelIoFile` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 94 | `NtTraceEvent` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 95 | `NtPowerInformation` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 96 | `NtSetValueKey` | translated | `kernel/subsystems/win32/nt_syscall_table_generated.h::SYS_REGISTRY` | routes to native SYS_REGISTRY |
| nt | 97 | `NtCancelTimer` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 98 | `NtSetTimer` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 99 | `NtAccessCheckByType` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 100 | `NtAccessCheckByTypeResultList` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 101 | `NtAccessCheckByTypeResultListAndAuditAlarm` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 102 | `NtAccessCheckByTypeResultListAndAuditAlarmByHandle` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 103 | `NtAcquireCrossVmMutant` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 104 | `NtAcquireProcessActivityReference` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 105 | `NtAddAtomEx` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 106 | `NtAddBootEntry` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 107 | `NtAddDriverEntry` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 108 | `NtAdjustGroupsToken` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 109 | `NtAdjustTokenClaimsAndDeviceGroups` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 110 | `NtAlertMultipleThreadByThreadId` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 111 | `NtAlertResumeThread` | translated | `kernel/subsystems/win32/nt_syscall_table_generated.h::SYS_THREAD_RESUME` | routes to native SYS_THREAD_RESUME |
| nt | 112 | `NtAlertThread` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 113 | `NtAlertThreadByThreadId` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 114 | `NtAlertThreadByThreadIdEx` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 115 | `NtAllocateLocallyUniqueId` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 116 | `NtAllocateReserveObject` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 117 | `NtAllocateUserPhysicalPages` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 118 | `NtAllocateUserPhysicalPagesEx` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 119 | `NtAllocateUuids` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 120 | `NtAllocateVirtualMemoryEx` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 121 | `NtAlpcAcceptConnectPort` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 122 | `NtAlpcCancelMessage` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 123 | `NtAlpcConnectPort` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 124 | `NtAlpcConnectPortEx` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 125 | `NtAlpcCreatePort` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 126 | `NtAlpcCreatePortSection` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 127 | `NtAlpcCreateResourceReserve` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 128 | `NtAlpcCreateSectionView` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 129 | `NtAlpcCreateSecurityContext` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 130 | `NtAlpcDeletePortSection` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 131 | `NtAlpcDeleteResourceReserve` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 132 | `NtAlpcDeleteSectionView` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 133 | `NtAlpcDeleteSecurityContext` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 134 | `NtAlpcDisconnectPort` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 135 | `NtAlpcImpersonateClientContainerOfPort` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 136 | `NtAlpcImpersonateClientOfPort` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 137 | `NtAlpcOpenSenderProcess` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 138 | `NtAlpcOpenSenderThread` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 139 | `NtAlpcQueryInformation` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 140 | `NtAlpcQueryInformationMessage` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 141 | `NtAlpcRevokeSecurityContext` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 142 | `NtAlpcSendWaitReceivePort` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 143 | `NtAlpcSetInformation` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 144 | `NtAreMappedFilesTheSame` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 145 | `NtAssignProcessToJobObject` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 146 | `NtAssociateWaitCompletionPacket` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 147 | `NtCallEnclave` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 148 | `NtCancelIoFileEx` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 149 | `NtCancelSynchronousIoFile` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 150 | `NtCancelTimer2` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 151 | `NtCancelWaitCompletionPacket` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 152 | `NtChangeProcessState` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 153 | `NtChangeThreadState` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 154 | `NtCommitComplete` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 155 | `NtCommitEnlistment` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 156 | `NtCommitRegistryTransaction` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 157 | `NtCommitTransaction` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 158 | `NtCompactKeys` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 159 | `NtCompareObjects` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 160 | `NtCompareSigningLevels` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 161 | `NtCompareTokens` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 162 | `NtCompleteConnectPort` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 163 | `NtCompressKey` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 164 | `NtConnectPort` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 165 | `NtContinueEx` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 166 | `NtConvertBetweenAuxiliaryCounterAndPerformanceCounter` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 167 | `NtCopyFileChunk` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 168 | `NtCreateCpuPartition` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 169 | `NtCreateCrossVmEvent` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 170 | `NtCreateCrossVmMutant` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 171 | `NtCreateDebugObject` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 172 | `NtCreateDirectoryObject` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 173 | `NtCreateDirectoryObjectEx` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 174 | `NtCreateEnclave` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 175 | `NtCreateEnlistment` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 176 | `NtCreateEventPair` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 177 | `NtCreateIRTimer` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 178 | `NtCreateIoCompletion` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 179 | `NtCreateIoRing` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 180 | `NtCreateJobObject` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 181 | `NtCreateJobSet` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 182 | `NtCreateKeyTransacted` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 183 | `NtCreateKeyedEvent` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 184 | `NtCreateLowBoxToken` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 185 | `NtCreateMailslotFile` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 186 | `NtCreateMutant` | translated | `kernel/subsystems/win32/nt_syscall_table_generated.h::SYS_MUTEX_CREATE` | routes to native SYS_MUTEX_CREATE |
| nt | 187 | `NtCreateNamedPipeFile` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 188 | `NtCreatePagingFile` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 189 | `NtCreatePartition` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 190 | `NtCreatePort` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 191 | `NtCreatePrivateNamespace` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 192 | `NtCreateProcess` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 193 | `NtCreateProcessStateChange` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 194 | `NtCreateProfile` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 195 | `NtCreateProfileEx` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 196 | `NtCreateRegistryTransaction` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 197 | `NtCreateResourceManager` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 198 | `NtCreateSectionEx` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 199 | `NtCreateSemaphore` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 200 | `NtCreateSymbolicLinkObject` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 201 | `NtCreateThreadEx` | translated | `kernel/subsystems/win32/nt_syscall_table_generated.h::SYS_THREAD_CREATE` | routes to native SYS_THREAD_CREATE |
| nt | 202 | `NtCreateThreadStateChange` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 203 | `NtCreateTimer` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 204 | `NtCreateTimer2` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 205 | `NtCreateToken` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 206 | `NtCreateTokenEx` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 207 | `NtCreateTransaction` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 208 | `NtCreateTransactionManager` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 209 | `NtCreateUserProcess` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 210 | `NtCreateWaitCompletionPacket` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 211 | `NtCreateWaitablePort` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 212 | `NtCreateWnfStateName` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 213 | `NtCreateWorkerFactory` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 214 | `NtDebugActiveProcess` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 215 | `NtDebugContinue` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 216 | `NtDeleteAtom` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 217 | `NtDeleteBootEntry` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 218 | `NtDeleteDriverEntry` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 219 | `NtDeleteFile` | translated | `kernel/subsystems/win32/nt_syscall_table_generated.h::SYS_FILE_UNLINK` | routes to native SYS_FILE_UNLINK |
| nt | 220 | `NtDeleteKey` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 221 | `NtDeleteObjectAuditAlarm` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 222 | `NtDeletePrivateNamespace` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 223 | `NtDeleteValueKey` | translated | `kernel/subsystems/win32/nt_syscall_table_generated.h::SYS_REGISTRY` | routes to native SYS_REGISTRY |
| nt | 224 | `NtDeleteWnfStateData` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 225 | `NtDeleteWnfStateName` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 226 | `NtDirectGraphicsCall` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 227 | `NtDisableLastKnownGood` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 228 | `NtDisplayString` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 229 | `NtDrawText` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 230 | `NtEnableLastKnownGood` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 231 | `NtEnumerateBootEntries` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 232 | `NtEnumerateDriverEntries` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 233 | `NtEnumerateSystemEnvironmentValuesEx` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 234 | `NtEnumerateTransactionObject` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 235 | `NtExtendSection` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 236 | `NtFilterBootOption` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 237 | `NtFilterToken` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 238 | `NtFilterTokenEx` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 239 | `NtFlushBuffersFileEx` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 240 | `NtFlushInstallUILanguage` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 241 | `NtFlushInstructionCache` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 242 | `NtFlushKey` | translated | `kernel/subsystems/win32/nt_syscall_table_generated.h::SYS_REGISTRY` | routes to native SYS_REGISTRY |
| nt | 243 | `NtFlushProcessWriteBuffers` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 244 | `NtFlushVirtualMemory` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 245 | `NtFlushWriteBuffer` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 246 | `NtFreeUserPhysicalPages` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 247 | `NtFreezeRegistry` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 248 | `NtFreezeTransactions` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 249 | `NtGetCachedSigningLevel` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 250 | `NtGetCompleteWnfStateSubscription` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 251 | `NtGetContextThread` | translated | `kernel/subsystems/win32/nt_syscall_table_generated.h::SYS_THREAD_GET_CONTEXT` | routes to native SYS_THREAD_GET_CONTEXT |
| nt | 252 | `NtGetCurrentProcessorNumber` | translated | `kernel/subsystems/win32/nt_syscall_table_generated.h::SYS_NT_INVOKE` | routes to native SYS_NT_INVOKE |
| nt | 253 | `NtGetCurrentProcessorNumberEx` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 254 | `NtGetDevicePowerState` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 255 | `NtGetMUIRegistryInfo` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 256 | `NtGetNextProcess` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 257 | `NtGetNextThread` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 258 | `NtGetNlsSectionPtr` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 259 | `NtGetNotificationResourceManager` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 260 | `NtGetWriteWatch` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 261 | `NtImpersonateAnonymousToken` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 262 | `NtImpersonateThread` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 263 | `NtInitializeEnclave` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 264 | `NtInitializeNlsFiles` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 265 | `NtInitializeRegistry` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 266 | `NtInitiatePowerAction` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 267 | `NtIsSystemResumeAutomatic` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 268 | `NtIsUILanguageComitted` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 269 | `NtListenPort` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 270 | `NtLoadDriver` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 271 | `NtLoadEnclaveData` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 272 | `NtLoadKey` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 273 | `NtLoadKey2` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 274 | `NtLoadKey3` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 275 | `NtLoadKeyEx` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 276 | `NtLockFile` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 277 | `NtLockProductActivationKeys` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 278 | `NtLockRegistryKey` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 279 | `NtLockVirtualMemory` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 280 | `NtMakePermanentObject` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 281 | `NtMakeTemporaryObject` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 282 | `NtManageHotPatch` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 283 | `NtManagePartition` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 284 | `NtMapCMFModule` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 285 | `NtMapUserPhysicalPages` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 286 | `NtMapViewOfSectionEx` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 287 | `NtModifyBootEntry` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 288 | `NtModifyDriverEntry` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 289 | `NtNotifyChangeDirectoryFile` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 290 | `NtNotifyChangeDirectoryFileEx` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 291 | `NtNotifyChangeKey` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 292 | `NtNotifyChangeMultipleKeys` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 293 | `NtNotifyChangeSession` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 294 | `NtOpenCpuPartition` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 295 | `NtOpenEnlistment` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 296 | `NtOpenEventPair` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 297 | `NtOpenIoCompletion` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 298 | `NtOpenJobObject` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 299 | `NtOpenKeyEx` | translated | `kernel/subsystems/win32/nt_syscall_table_generated.h::SYS_REGISTRY` | routes to native SYS_REGISTRY |
| nt | 300 | `NtOpenKeyTransacted` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 301 | `NtOpenKeyTransactedEx` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 302 | `NtOpenKeyedEvent` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 303 | `NtOpenMutant` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 304 | `NtOpenObjectAuditAlarm` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 305 | `NtOpenPartition` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 306 | `NtOpenPrivateNamespace` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 307 | `NtOpenProcessToken` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 308 | `NtOpenRegistryTransaction` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 309 | `NtOpenResourceManager` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 310 | `NtOpenSemaphore` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 311 | `NtOpenSession` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 312 | `NtOpenSymbolicLinkObject` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 313 | `NtOpenThread` | translated | `kernel/subsystems/win32/nt_syscall_table_generated.h::SYS_THREAD_OPEN` | routes to native SYS_THREAD_OPEN |
| nt | 314 | `NtOpenTimer` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 315 | `NtOpenTransaction` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 316 | `NtOpenTransactionManager` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 317 | `NtPlugPlayControl` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 318 | `NtPrePrepareComplete` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 319 | `NtPrePrepareEnlistment` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 320 | `NtPrepareComplete` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 321 | `NtPrepareEnlistment` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 322 | `NtPrivilegeCheck` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 323 | `NtPrivilegeObjectAuditAlarm` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 324 | `NtPrivilegedServiceAuditAlarm` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 325 | `NtPropagationComplete` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 326 | `NtPropagationFailed` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 327 | `NtPssCaptureVaSpaceBulk` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 328 | `NtPulseEvent` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 329 | `NtQueryAuxiliaryCounterFrequency` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 330 | `NtQueryBootEntryOrder` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 331 | `NtQueryBootOptions` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 332 | `NtQueryDebugFilterState` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 333 | `NtQueryDirectoryFileEx` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 334 | `NtQueryDirectoryObject` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 335 | `NtQueryDriverEntryOrder` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 336 | `NtQueryEaFile` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 337 | `NtQueryFullAttributesFile` | translated | `kernel/subsystems/win32/nt_syscall_table_generated.h::SYS_FILE_QUERY_ATTRIBUTES` | routes to native SYS_FILE_QUERY_ATTRIBUTES |
| nt | 338 | `NtQueryInformationAtom` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 339 | `NtQueryInformationByName` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 340 | `NtQueryInformationCpuPartition` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 341 | `NtQueryInformationEnlistment` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 342 | `NtQueryInformationJobObject` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 343 | `NtQueryInformationPort` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 344 | `NtQueryInformationResourceManager` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 345 | `NtQueryInformationTransaction` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 346 | `NtQueryInformationTransactionManager` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 347 | `NtQueryInformationWorkerFactory` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 348 | `NtQueryInstallUILanguage` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 349 | `NtQueryIntervalProfile` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 350 | `NtQueryIoCompletion` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 351 | `NtQueryIoRingCapabilities` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 352 | `NtQueryLicenseValue` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 353 | `NtQueryMultipleValueKey` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 354 | `NtQueryMutant` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 355 | `NtQueryOpenSubKeys` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 356 | `NtQueryOpenSubKeysEx` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 357 | `NtQueryPortInformationProcess` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 358 | `NtQueryQuotaInformationFile` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 359 | `NtQuerySecurityAttributesToken` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 360 | `NtQuerySecurityObject` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 361 | `NtQuerySecurityPolicy` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 362 | `NtQuerySemaphore` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 363 | `NtQuerySymbolicLinkObject` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 364 | `NtQuerySystemEnvironmentValue` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 365 | `NtQuerySystemEnvironmentValueEx` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 366 | `NtQuerySystemInformationEx` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 367 | `NtQueryTimerResolution` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 368 | `NtQueryWnfStateData` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 369 | `NtQueryWnfStateNameInformation` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 370 | `NtQueueApcThreadEx` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 371 | `NtQueueApcThreadEx2` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 372 | `NtRaiseException` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 373 | `NtRaiseHardError` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 374 | `NtReadOnlyEnlistment` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 375 | `NtReadVirtualMemoryEx` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 376 | `NtRecoverEnlistment` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 377 | `NtRecoverResourceManager` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 378 | `NtRecoverTransactionManager` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 379 | `NtRegisterProtocolAddressInformation` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 380 | `NtRegisterThreadTerminatePort` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 381 | `NtReleaseKeyedEvent` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 382 | `NtReleaseWorkerFactoryWorker` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 383 | `NtRemoveIoCompletionEx` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 384 | `NtRemoveProcessDebug` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 385 | `NtRenameKey` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 386 | `NtRenameTransactionManager` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 387 | `NtReplaceKey` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 388 | `NtReplacePartitionUnit` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 389 | `NtReplyWaitReplyPort` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 390 | `NtRequestPort` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 391 | `NtResetEvent` | translated | `kernel/subsystems/win32/nt_syscall_table_generated.h::SYS_EVENT_RESET` | routes to native SYS_EVENT_RESET |
| nt | 392 | `NtResetWriteWatch` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 393 | `NtRestoreKey` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 394 | `NtResumeProcess` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 395 | `NtRevertContainerImpersonation` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 396 | `NtRollbackComplete` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 397 | `NtRollbackEnlistment` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 398 | `NtRollbackRegistryTransaction` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 399 | `NtRollbackTransaction` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 400 | `NtRollforwardTransactionManager` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 401 | `NtSaveKey` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 402 | `NtSaveKeyEx` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 403 | `NtSaveMergedKeys` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 404 | `NtSecureConnectPort` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 405 | `NtSerializeBoot` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 406 | `NtSetBootEntryOrder` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 407 | `NtSetBootOptions` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 408 | `NtSetCachedSigningLevel` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 409 | `NtSetCachedSigningLevel2` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 410 | `NtSetContextThread` | translated | `kernel/subsystems/win32/nt_syscall_table_generated.h::SYS_THREAD_SET_CONTEXT` | routes to native SYS_THREAD_SET_CONTEXT |
| nt | 411 | `NtSetDebugFilterState` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 412 | `NtSetDefaultHardErrorPort` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 413 | `NtSetDefaultLocale` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 414 | `NtSetDefaultUILanguage` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 415 | `NtSetDriverEntryOrder` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 416 | `NtSetEaFile` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 417 | `NtSetEventEx` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 418 | `NtSetHighEventPair` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 419 | `NtSetHighWaitLowEventPair` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 420 | `NtSetIRTimer` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 421 | `NtSetInformationCpuPartition` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 422 | `NtSetInformationDebugObject` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 423 | `NtSetInformationEnlistment` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 424 | `NtSetInformationIoRing` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 425 | `NtSetInformationJobObject` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 426 | `NtSetInformationKey` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 427 | `NtSetInformationResourceManager` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 428 | `NtSetInformationSymbolicLink` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 429 | `NtSetInformationToken` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 430 | `NtSetInformationTransaction` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 431 | `NtSetInformationTransactionManager` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 432 | `NtSetInformationVirtualMemory` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 433 | `NtSetInformationWorkerFactory` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 434 | `NtSetIntervalProfile` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 435 | `NtSetIoCompletion` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 436 | `NtSetIoCompletionEx` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 437 | `NtSetLdtEntries` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 438 | `NtSetLowEventPair` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 439 | `NtSetLowWaitHighEventPair` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 440 | `NtSetQuotaInformationFile` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 441 | `NtSetSecurityObject` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 442 | `NtSetSystemEnvironmentValue` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 443 | `NtSetSystemEnvironmentValueEx` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 444 | `NtSetSystemInformation` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 445 | `NtSetSystemPowerState` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 446 | `NtSetSystemTime` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 447 | `NtSetThreadExecutionState` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 448 | `NtSetTimer2` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 449 | `NtSetTimerEx` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 450 | `NtSetTimerResolution` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 451 | `NtSetUuidSeed` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 452 | `NtSetVolumeInformationFile` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 453 | `NtSetWnfProcessNotificationEvent` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 454 | `NtShutdownSystem` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 455 | `NtShutdownWorkerFactory` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 456 | `NtSignalAndWaitForSingleObject` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 457 | `NtSinglePhaseReject` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 458 | `NtStartProfile` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 459 | `NtStopProfile` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 460 | `NtSubmitIoRing` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 461 | `NtSubscribeWnfStateChange` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 462 | `NtSuspendProcess` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 463 | `NtSuspendThread` | translated | `kernel/subsystems/win32/nt_syscall_table_generated.h::SYS_THREAD_SUSPEND` | routes to native SYS_THREAD_SUSPEND |
| nt | 464 | `NtSystemDebugControl` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 465 | `NtTerminateEnclave` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 466 | `NtTerminateJobObject` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 467 | `NtTestAlert` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 468 | `NtThawRegistry` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 469 | `NtThawTransactions` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 470 | `NtTraceControl` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 471 | `NtTranslateFilePath` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 472 | `NtUmsThreadYield` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 473 | `NtUnloadDriver` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 474 | `NtUnloadKey` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 475 | `NtUnloadKey2` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 476 | `NtUnloadKeyEx` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 477 | `NtUnlockFile` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 478 | `NtUnlockVirtualMemory` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 479 | `NtUnmapViewOfSectionEx` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 480 | `NtUnsubscribeWnfStateChange` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 481 | `NtUpdateWnfStateData` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 482 | `NtVdmControl` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 483 | `NtWaitForAlertByThreadId` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 484 | `NtWaitForDebugEvent` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 485 | `NtWaitForKeyedEvent` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 486 | `NtWaitForWorkViaWorkerFactory` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 487 | `NtWaitHighEventPair` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 488 | `NtWaitLowEventPair` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |

## Syscall Handler Inventory

<!-- AUTO:syscall_list -->
| # | Symbol |
|---|--------|
| 0 | `SYS_EXIT` |
| 1 | `SYS_GETPID` |
| 2 | `SYS_WRITE` |
| 3 | `SYS_YIELD` |
| 4 | `SYS_STAT` |
| 5 | `SYS_READ` |
| 6 | `SYS_DROPCAPS` |
| 7 | `SYS_SPAWN` |
| 8 | `SYS_GETPROCID` |
| 9 | `SYS_GETLASTERROR` |
| 10 | `SYS_SETLASTERROR` |
| 11 | `SYS_HEAP_ALLOC` |
| 12 | `SYS_HEAP_FREE` |
| 13 | `SYS_PERF_COUNTER` |
| 14 | `SYS_HEAP_SIZE` |
| 15 | `SYS_HEAP_REALLOC` |
| 16 | `SYS_WIN32_MISS_LOG` |
| 17 | `SYS_GETTIME_FT` |
| 18 | `SYS_NOW_NS` |
| 19 | `SYS_SLEEP_MS` |
| 20 | `SYS_FILE_OPEN` |
| 21 | `SYS_FILE_READ` |
| 22 | `SYS_FILE_CLOSE` |
| 23 | `SYS_FILE_SEEK` |
| 24 | `SYS_FILE_FSTAT` |
| 25 | `SYS_MUTEX_CREATE` |
| 26 | `SYS_MUTEX_WAIT` |
| 27 | `SYS_MUTEX_RELEASE` |
| 28 | `SYS_VMAP` |
| 29 | `SYS_VUNMAP` |
| 30 | `SYS_EVENT_CREATE` |
| 31 | `SYS_EVENT_SET` |
| 32 | `SYS_EVENT_RESET` |
| 33 | `SYS_EVENT_WAIT` |
| 34 | `SYS_TLS_ALLOC` |
| 35 | `SYS_TLS_FREE` |
| 36 | `SYS_TLS_GET` |
| 37 | `SYS_TLS_SET` |
| 38 | `SYS_BP_INSTALL` |
| 39 | `SYS_BP_REMOVE` |
| 40 | `SYS_GETTIME_ST` |
| 41 | `SYS_ST_TO_FT` |
| 42 | `SYS_FT_TO_ST` |
| 43 | `SYS_FILE_WRITE` |
| 44 | `SYS_FILE_CREATE` |
| 45 | `SYS_THREAD_CREATE` |
| 46 | `SYS_DEBUG_PRINT` |
| 47 | `SYS_MEM_STATUS` |
| 48 | `SYS_WAIT_MULTI` |
| 49 | `SYS_SYSTEM_INFO` |
| 50 | `SYS_DEBUG_PRINTW` |
| 51 | `SYS_SEM_CREATE` |
| 52 | `SYS_SEM_RELEASE` |
| 53 | `SYS_SEM_WAIT` |
| 54 | `SYS_THREAD_WAIT` |
| 55 | `SYS_THREAD_EXIT_CODE` |
| 56 | `SYS_NT_INVOKE` |
| 57 | `SYS_DLL_PROC_ADDRESS` |
| 58 | `SYS_WIN_CREATE` |
| 59 | `SYS_WIN_DESTROY` |
| 60 | `SYS_WIN_SHOW` |
| 61 | `SYS_WIN_MSGBOX` |
| 62 | `SYS_WIN_PEEK_MSG` |
| 63 | `SYS_WIN_GET_MSG` |
| 64 | `SYS_WIN_POST_MSG` |
| 65 | `SYS_GDI_FILL_RECT` |
| 66 | `SYS_GDI_TEXT_OUT` |
| 67 | `SYS_GDI_RECTANGLE` |
| 68 | `SYS_GDI_CLEAR` |
| 69 | `SYS_WIN_MOVE` |
| 70 | `SYS_WIN_GET_RECT` |
| 71 | `SYS_WIN_SET_TEXT` |
| 72 | `SYS_WIN_TIMER_SET` |
| 73 | `SYS_WIN_TIMER_KILL` |
| 74 | `SYS_GDI_LINE` |
| 75 | `SYS_GDI_ELLIPSE` |
| 76 | `SYS_GDI_SET_PIXEL` |
| 77 | `SYS_WIN_GET_KEYSTATE` |
| 78 | `SYS_WIN_GET_CURSOR` |
| 79 | `SYS_WIN_SET_CURSOR` |
| 80 | `SYS_WIN_SET_CAPTURE` |
| 81 | `SYS_WIN_RELEASE_CAPTURE` |
| 82 | `SYS_WIN_GET_CAPTURE` |
| 83 | `SYS_WIN_CLIP_SET_TEXT` |
| 84 | `SYS_WIN_CLIP_GET_TEXT` |
| 85 | `SYS_WIN_GET_LONG` |
| 86 | `SYS_WIN_SET_LONG` |
| 87 | `SYS_WIN_INVALIDATE` |
| 88 | `SYS_WIN_VALIDATE` |
| 89 | `SYS_WIN_GET_ACTIVE` |
| 90 | `SYS_WIN_SET_ACTIVE` |
| 91 | `SYS_WIN_GET_METRIC` |
| 92 | `SYS_WIN_ENUM` |
| 93 | `SYS_WIN_FIND` |
| 94 | `SYS_WIN_SET_PARENT` |
| 95 | `SYS_WIN_GET_PARENT` |
| 96 | `SYS_WIN_GET_RELATED` |
| 97 | `SYS_WIN_SET_FOCUS` |
| 98 | `SYS_WIN_GET_FOCUS` |
| 99 | `SYS_WIN_CARET` |
| 100 | `SYS_WIN_BEEP` |
| 101 | `SYS_GFX_D3D_STUB` |
| 102 | `SYS_GDI_BITBLT` |
| 103 | `SYS_WIN_BEGIN_PAINT` |
| 104 | `SYS_WIN_END_PAINT` |
| 105 | `SYS_GDI_FILL_RECT_USER` |
| 106 | `SYS_GDI_CREATE_COMPAT_DC` |
| 107 | `SYS_GDI_CREATE_COMPAT_BITMAP` |
| 108 | `SYS_GDI_CREATE_SOLID_BRUSH` |
| 109 | `SYS_GDI_GET_STOCK_OBJECT` |
| 110 | `SYS_GDI_SELECT_OBJECT` |
| 111 | `SYS_GDI_DELETE_DC` |
| 112 | `SYS_GDI_DELETE_OBJECT` |
| 113 | `SYS_GDI_BITBLT_DC` |
| 114 | `SYS_GDI_SET_TEXT_COLOR` |
| 115 | `SYS_GDI_SET_BK_COLOR` |
| 116 | `SYS_GDI_SET_BK_MODE` |
| 117 | `SYS_GDI_STRETCH_BLT_DC` |
| 118 | `SYS_GDI_CREATE_PEN` |
| 119 | `SYS_GDI_MOVE_TO_EX` |
| 120 | `SYS_GDI_LINE_TO` |
| 121 | `SYS_GDI_DRAW_TEXT_USER` |
| 122 | `SYS_GDI_RECTANGLE_FILLED` |
| 123 | `SYS_GDI_ELLIPSE_FILLED` |
| 124 | `SYS_GDI_PAT_BLT` |
| 125 | `SYS_GDI_TEXT_OUT_W` |
| 126 | `SYS_GDI_DRAW_TEXT_W` |
| 127 | `SYS_GDI_GET_SYS_COLOR` |
| 128 | `SYS_GDI_GET_SYS_COLOR_BRUSH` |
| 144 | `SYS_FILE_RENAME` |
| 151 | `SYS_FILE_QUERY_ATTRIBUTES` |
| 152 | `SYS_EXECVE` |
| 153 | `SYS_SOCKET_OP` |
| 154 | `SYS_DIR_OPEN` |
| 155 | `SYS_DIR_NEXT` |
| 156 | `SYS_DIR_REWIND` |
| 170 | `SYS_WIN_GET_MOUSE_DELTA` |
| 171 | `SYS_STDIN_READ` |
| 173 | `SYS_WIN_TRACK_POPUP` |
| 174 | `SYS_GDI_SET_CURSOR` |
| 175 | `SYS_GDI_CREATE_CURSOR` |
| 180 | `SYS_FILE_MKDIR` |
| 181 | `SYS_FILE_SYMLINK` |
| 182 | `SYS_FILE_LINK` |
| 183 | `SYS_FILE_READLINK` |
| 184 | `SYS_SYSTEM_PERFORMANCE_INFO` |
| 185 | `SYS_NAMED_KOBJ_OPEN_OR_CREATE` |
| 186 | `SYS_WIN32_CREATE_PIPE` |
| 187 | `SYS_QUEUE_USER_APC` |
| 188 | `SYS_DRAIN_USER_APC` |
| 189 | `SYS_PRIORITY_CLASS` |
| 190 | `SYS_PROCESS_SPAWN_EX` |
| 191 | `SYS_GET_INHERITED_STD` |
| 192 | `SYS_HEAPEX_CREATE` |
| 193 | `SYS_HEAPEX_DESTROY` |
| 194 | `SYS_HEAPEX_ALLOC` |
| 195 | `SYS_HEAPEX_FREE` |
| 196 | `SYS_HEAPEX_SIZE` |
| 197 | `SYS_HEAPEX_REALLOC` |
| 198 | `SYS_AUDIO_DEVICE_INFO` |
| 199 | `SYS_VIRTUAL_ALLOC` |
| 200 | `SYS_VIRTUAL_FREE` |
| 201 | `SYS_VIRTUAL_PROTECT` |
| 202 | `SYS_NAMED_PIPE_CREATE` |
| 203 | `SYS_NAMED_PIPE_OPEN` |
<!-- /AUTO:syscall_list -->

## Native Syscall Argument / Return Reference

> Auto-generated from `kernel/syscall/syscall.h` doc-comments by
> `tools/build/gen-syscall-doc.py`. Each row records what the
> handler expects in registers and what it returns. A `—` cell
> means the upstream comment didn't surface enough information
> for the extractor — fix the doc-comment in `syscall.h`, then
> regenerate. The script also warns on any number drift between
> the enum and `syscall_names.def` so a doc rebuild can detect
> ABI-number collisions before they ship.
>
> Regenerate via:
>
> ```bash
> python3 tools/build/gen-syscall-doc.py \
>     --out /tmp/syscall-args.md
> ```
>
> Then paste the output between the AUTO markers below; the wiki
> sync script (`docs/sync-wiki.sh`) calls the same generator on
> every sync.

<!-- AUTO:syscall_args -->
| # | Symbol | Args | Returns |
|---|--------|------|---------|
| 0 | `SYS_EXIT` | — | — |
| 1 | `SYS_GETPID` | — | — |
| 2 | `SYS_WRITE` | — | — |
| 3 | `SYS_YIELD` | — | — |
| 4 | `SYS_STAT` | `rdi` = user pointer to NUL-terminated path; `rsi` = user pointer to a u64 output slot that receives the file ... | 0 on success, -1 on any failure (path not found, path out of jail, bad user p... |
| 5 | `SYS_READ` | `rdi` = user pointer to NUL-terminated path; `rsi` = user pointer to destination buffer; `rdx` = buffer capacity in bytes | number of bytes actually written on success (≤ both the file size and the buf... |
| 6 | `SYS_DROPCAPS` | `rdi` = bitmask of caps to remove from the calling process's CapSet | 0 always |
| 7 | `SYS_SPAWN` | `rdi` = user pointer to NUL-terminated ELF path; `rsi` = path length (caller-supplied to bound the CopyFromUser) | the new child pid on success, or (u64)-1 on any failure (cap missing, path ou... |
| 8 | `SYS_GETPROCID` | — | CurrentProcess()->pid — distinct from SYS_GETPID, which returns the scheduler... |
| 9 | `SYS_GETLASTERROR` | `rdi` = new error code (low 32 bits) and returns the previous val... | the caller's task-local Win32 error slot |
| 10 | `SYS_SETLASTERROR` | — | — |
| 11 | `SYS_HEAP_ALLOC` | `rdi` = size in bytes | the user VA of the allocation (0 on OOM) |
| 12 | `SYS_HEAP_FREE` | — | — |
| 13 | `SYS_PERF_COUNTER` | — | the kernel tick counter from arch::TimerTicks() — a monotonically increasing ... |
| 14 | `SYS_HEAP_SIZE` | `rdi` = user pointer previously returned by SYS_HEAP_ALLOC | the block's payload capacity in bytes (the rounded-up allocation size recorde... |
| 15 | `SYS_HEAP_REALLOC` | `rdi` = existing user pointer (may be 0 to request a fresh alloca...; `rsi` = new requested size in bytes | the new user VA (possibly equal to rdi if the existing block already fit) or ... |
| 16 | `SYS_WIN32_MISS_LOG` | `rdi` = VA of the IAT slot that was just called (produced by the ... | address to compute the slot) |
| 17 | `SYS_GETTIME_FT` | — | the current wall-clock time as a Windows FILETIME — a u64 count of 100-nanose... |
| 18 | `SYS_NOW_NS` | — | nanoseconds since boot in rax |
| 19 | `SYS_SLEEP_MS` | `rdi` = milliseconds to block | 0 on wake |
| 20 | `SYS_FILE_OPEN` | `rdi` = user pointer to NUL-terminated ASCII path; `rsi` = path-length cap (caller-supplied to bound the CopyFromUser) | a Win32-shaped handle (Process::kWin32HandleBase + slot_idx, i |
| 21 | `SYS_FILE_READ` | `rdi` = handle (Win32-shaped); `rsi` = user dst buffer; `rdx` = byte count cap | bytes actually copied (≤ both `rdx` and remaining bytes in the file from the ... |
| 22 | `SYS_FILE_CLOSE` | `rdi` = handle | 0 on success or no-op (closing an already-closed / never-opened handle is a d... |
| 23 | `SYS_FILE_SEEK` | `rdi` = handle; `rsi` = signed offset; `rdx` = whence (0 = SET | the new cursor position (relative to file start) on success, or u64(-1) on fa... |
| 24 | `SYS_FILE_FSTAT` | `rdi` = handle; `rsi` = user pointer to a u64 output slot that receives the file ... | 0 on success, u64(-1) on bad handle / bad user pointer |
| 25 | `SYS_MUTEX_CREATE` | `rdi` = bInitialOwner (0 or 1) | a Win32 pseudo-handle (Process::kWin32MutexBase + slot_idx, i |
| 26 | `SYS_MUTEX_WAIT` | `rdi` = mutex handle; `rsi` = timeout in ms (0xFFFFFFFF = INFINITE) | WAIT_OBJECT_0 immediately |
| 27 | `SYS_MUTEX_RELEASE` | `rdi` = mutex handle | 0 on success, u64(-1) on bad handle or non-owner release (ERROR_NOT_OWNER) |
| 28 | `SYS_VMAP` | `rdi` = byte size (rounded up to next page) | the base VA of the allocation on success, or 0 on failure (arena exhausted / ... |
| 29 | `SYS_VUNMAP` | `rdi` = VA; `rsi` = size | 0 on success, u64(-1) on failure |
| 30 | `SYS_EVENT_CREATE` | `rdi` = bManualReset (0 or 1); `rsi` = bInitialState (0 or 1) | Process::kWin32EventBase + slot (= 0x300 |
| 31 | `SYS_EVENT_SET` | `rdi` = event handle | 0 on success, u64(-1) on bad handle |
| 32 | `SYS_EVENT_RESET` | `rdi` = event handle | 0 on success, u64(-1) on bad handle |
| 33 | `SYS_EVENT_WAIT` | `rdi` = event handle; `rsi` = timeout_ms | WAIT_OBJECT_0 (0) on success, WAIT_TIMEOUT (0x102) on timeout, or u64(-1) on ... |
| 34 | `SYS_TLS_ALLOC` | — | the lowest unused TLS slot index (0 |
| 35 | `SYS_TLS_FREE` | `rdi` = slot index | 0 on success, u64(-1) on bad index / unallocated slot |
| 36 | `SYS_TLS_GET` | `rdi` = slot index | the stored u64 value, or 0 if the index is invalid / unallocated (Win32 TlsGe... |
| 37 | `SYS_TLS_SET` | `rdi` = slot index; `rsi` = value | 0 on success, u64(-1) on bad index |
| 38 | `SYS_BP_INSTALL` | `rdi` = va; `rsi` = BpKind (1=exec; `rdx` = length (1/2/4/8) | a non-zero breakpoint id on success, or u64(-1) on error |
| 39 | `SYS_BP_REMOVE` | `rdi` = id | 0 on success, u64(-1) on unknown id |
| 40 | `SYS_GETTIME_ST` | `rdi` = user pointer to a 16-byte SYSTEMTIME struct | 0 on success, u64(-1) on EFAULT |
| 41 | `SYS_ST_TO_FT` | `rdi` = user pointer to an input SYSTEMTIME; `rsi` = user pointer to an output FILETIME | 0 on success |
| 42 | `SYS_FT_TO_ST` | `rdi` = user pointer to an input FILETIME; `rsi` = user pointer to an output SYSTEMTIME | — |
| 43 | `SYS_FILE_WRITE` | `rdi` = handle (Win32-shaped; `rsi` = user pointer to source bytes; `rdx` = byte count | bytes written (0 |
| 44 | `SYS_FILE_CREATE` | `rdi` = user pointer to NUL-terminated ASCII path; `rsi` = path-buffer cap (bytes); `rdx` = user pointer to initial bytes (may be 0/null for empty file); `r10` = initial byte count | a Win32 pseudo- handle (kWin32HandleBase + slot_idx) on success, u64(-1) on f... |
| 45 | `SYS_THREAD_CREATE` | `rdi` = user-mode start VA (thread proc); `rsi` = user-mode parameter (passed as RCX on thread entry per Wi... | a Win32 pseudo-handle (kWin32ThreadBase + slot_idx, i |
| 46 | `SYS_DEBUG_PRINT` | `rdi` = user pointer to NUL-terminated ASCII string | — |
| 47 | `SYS_MEM_STATUS` | `rdi` = user pointer to a 64-byte Win32 MEMORYSTATUSEX struct | — |
| 48 | `SYS_WAIT_MULTI` | `rdi` = count; `rsi` = user pointer to handle array; `rdx` = bWaitAll; `r10` = timeout_ms | WAIT_OBJECT_0+i / WAIT_TIMEOUT / WAIT_FAILED |
| 49 | `SYS_SYSTEM_INFO` | `rdi` = user pointer to Win32 SYSTEM_INFO (48 bytes) | — |
| 50 | `SYS_DEBUG_PRINTW` | `rdi` = user pointer to NUL-terminated UTF-16LE string | — |
| 51 | `SYS_SEM_CREATE` | `rdi` = initial count; `rsi` = max count | Win32SemaphoreHandle (0x500 |
| 52 | `SYS_SEM_RELEASE` | `rdi` = handle; `rsi` = release count | PREVIOUS count on success |
| 53 | `SYS_SEM_WAIT` | `rdi` = handle; `rsi` = timeout_ms | 0 (WAIT_OBJECT_0) |
| 54 | `SYS_THREAD_WAIT` | `rdi` = thread handle (0x400; `rsi` = timeout_ms | — |
| 55 | `SYS_THREAD_EXIT_CODE` | `rdi` = thread handle (0x400 | the recorded exit code (u32) as u64, or 0x103 (STILL_ACTIVE) if the thread is... |
| 56 | `SYS_NT_INVOKE` | `rdi` = NT syscall number (e | the translated NTSTATUS in rax, or STATUS_NOT_IMPLEMENTED (0xC0000002) for an... |
| 57 | `SYS_DLL_PROC_ADDRESS` | `rdi` = HMODULE (the DLL's load base VA; `rsi` = user pointer to a NUL-terminated ASCII function name | the absolute VA of the exported function on hit, or 0 on miss (module not in ... |
| 58 | `SYS_WIN_CREATE` | `rdi` = x (u32; `rsi` = y (u32) rdx = width (u32; `r10` = height (u32; `r8` = user pointer to NUL-terminated ASCII title (bounded copy | 0 (WM_QUIT) |
| 59 | `SYS_WIN_DESTROY` | `rdi` = HWND returned by SYS_WIN_CREATE (biased | — |
| 60 | `SYS_WIN_SHOW` | `rdi` = HWND (biased) rsi = cmd rax = 0 (Win32 ShowWindow's "BOOL... | — |
| 61 | `SYS_WIN_MSGBOX` | `rdi` = user pointer to NUL-terminated ASCII text (bounded to kWi... | — |
| 62 | `SYS_WIN_PEEK_MSG` | `rdi` = user pointer to a 4×u64 output slot: [hwnd_biased; `rsi` = HWND filter (biased) — 0 = any window owned by the caller...; `rdx` = bRemove (0 = peek only | — |
| 63 | `SYS_WIN_GET_MSG` | `rdi` = user pointer to a 4×u64 output slot (same layout as PEEK_...; `rsi` = HWND filter (biased) — 0 = any | — |
| 64 | `SYS_WIN_POST_MSG` | `rdi` = HWND (biased) rsi = message code (UINT — WM_* id) rdx = w... | — |
| 65 | `SYS_GDI_FILL_RECT` | `rdi` = HWND (biased) rsi = x (i32 client-local) rdx = y (i32 cli... | — |
| 66 | `SYS_GDI_TEXT_OUT` | `rdi` = HWND (biased) rsi = x (i32 client-local) rdx = y (i32 cli...; `r8` = text length (bytes; `r9` = COLORREF (0x00BBGGRR | — |
| 67 | `SYS_GDI_RECTANGLE` | — | — |
| 68 | `SYS_GDI_CLEAR` | `rdi` = HWND (biased) rax = 1 on success | — |
| 69 | `SYS_WIN_MOVE` | `rdi` = HWND (biased) rsi = x (u32; `rdx` = y (u32)                     — ignored if r9 bit 0 r10 = w...; `r8` = h (u32; `r9` = flags: bit 0 = nomove (SWP_NOMOVE) | — |
| 70 | `SYS_WIN_GET_RECT` | `rdi` = HWND (biased) rsi = rect selector: 0 = window rect (outer...; `rdx` = user pointer to a 16-byte RECT (left | — |
| 71 | `SYS_WIN_SET_TEXT` | `rdi` = HWND (biased) rsi = user pointer to ASCII text (NUL-termi... | — |
| 72 | `SYS_WIN_TIMER_SET` | `rdi` = HWND (biased) rsi = timer_id (u32; `rdx` = interval in ms (rounds up to scheduler ticks) rax = timer... | — |
| 73 | `SYS_WIN_TIMER_KILL` | `rdi` = HWND (biased) rsi = timer_id rax = 1 on success | — |
| 74 | `SYS_GDI_LINE` | `rdi` = HWND (biased) rsi = x0; `rdx` = y0; `r10` = x1; `r8` = y1 (i32 client-local) r9  = COLORREF | — |
| 75 | `SYS_GDI_ELLIPSE` | — | — |
| 76 | `SYS_GDI_SET_PIXEL` | `rdi` = HWND; `rsi` = x; `rdx` = y; `r10` = COLORREF | — |
| 77 | `SYS_WIN_GET_KEYSTATE` | `rdi` = virtual-key / character code (low 8 bits used) | — |
| 78 | `SYS_WIN_GET_CURSOR` | `rdi` = user pointer to a 2×i32 POINT (x | — |
| 79 | `SYS_WIN_SET_CURSOR` | `rdi` = x; `rsi` = y (framebuffer coords | — |
| 80 | `SYS_WIN_SET_CAPTURE` | `rdi` = HWND | — |
| 81 | `SYS_WIN_RELEASE_CAPTURE` | — | — |
| 82 | `SYS_WIN_GET_CAPTURE` | — | — |
| 83 | `SYS_WIN_CLIP_SET_TEXT` | `rdi` = user pointer to NUL-terminated ASCII (nullable) | — |
| 84 | `SYS_WIN_CLIP_GET_TEXT` | `rdi` = user buffer pointer; `rsi` = buffer capacity | — |
| 85 | `SYS_WIN_GET_LONG` | `rdi` = HWND (biased) rsi = slot index (0=WNDPROC | — |
| 86 | `SYS_WIN_SET_LONG` | `rdi` = HWND; `rsi` = index; `rdx` = value | — |
| 87 | `SYS_WIN_INVALIDATE` | `rdi` = HWND; `rsi` = bErase (ignored in v1 | — |
| 88 | `SYS_WIN_VALIDATE` | `rdi` = HWND | — |
| 89 | `SYS_WIN_GET_ACTIVE` | — | — |
| 90 | `SYS_WIN_SET_ACTIVE` | `rdi` = HWND | — |
| 91 | `SYS_WIN_GET_METRIC` | `rdi` = SM_* index (see user32 stub) | — |
| 92 | `SYS_WIN_ENUM` | `rdi` = user pointer to u64[cap] rsi = cap (#entries) rax = actua... | — |
| 93 | `SYS_WIN_FIND` | `rdi` = user pointer to ASCII title (NUL-terminated) rax = biased... | — |
| 94 | `SYS_WIN_SET_PARENT` | `rdi` = HWND (child; `rsi` = HWND (parent | — |
| 95 | `SYS_WIN_GET_PARENT` | `rdi` = HWND | — |
| 96 | `SYS_WIN_GET_RELATED` | `rdi` = HWND; `rsi` = rel kind (0=Next | — |
| 97 | `SYS_WIN_SET_FOCUS` | `rdi` = HWND (0 = clear focus) | — |
| 98 | `SYS_WIN_GET_FOCUS` | — | — |
| 99 | `SYS_WIN_CARET` | `rdi` = op (0=Create; `rsi` = arg1 (Create: width; `rdx` = arg2 (Create: height; `r10` = arg3 (Create: HWND owner | — |
| 100 | `SYS_WIN_BEEP` | `rdi` = frequency in Hz (0 = use Win32 MB_OK default 800) rsi = d... | — |
| 101 | `SYS_GFX_D3D_STUB` | `rdi` = kind: 1 = D3D11CreateDevice / D3D11CreateDeviceAndSwapCha... | E_FAIL from a D3D/DXGI IAT stub |
| 102 | `SYS_GDI_BITBLT` | `rdi` = HWND (biased Win32 handle; `rsi` = dst_x (client-relative; `rdx` = dst_y r10 = src_w (pixels; `r8` = src_h r9  = user VA of `src_w * src_h` BGRA8888 pixels (r... | — |
| 103 | `SYS_WIN_BEGIN_PAINT` | `rdi` = HWND (biased) rsi = user VA of PAINTSTRUCT (72 B) to fill | — |
| 104 | `SYS_WIN_END_PAINT` | `rdi` = HWND (biased); `rsi` = PAINTSTRUCT* (ignored) | — |
| 105 | `SYS_GDI_FILL_RECT_USER` | `rdi` = HWND (biased) rsi = user VA of RECT { i32 left; `rdx` = colour (treated as RGB u32 | — |
| 106 | `SYS_GDI_CREATE_COMPAT_DC` | `rdi` = hdc_src (ignored in v0) | — |
| 107 | `SYS_GDI_CREATE_COMPAT_BITMAP` | `rdi` = hdc (ignored); `rsi` = width; `rdx` = height | — |
| 108 | `SYS_GDI_CREATE_SOLID_BRUSH` | `rdi` = COLORREF (0x00BBGGRR Win32 layout) | — |
| 109 | `SYS_GDI_GET_STOCK_OBJECT` | `rdi` = stock index (0 | 0 in v0) |
| 110 | `SYS_GDI_SELECT_OBJECT` | `rdi` = HDC; `rsi` = HGDIOBJ | previously-selected object in rax |
| 111 | `SYS_GDI_DELETE_DC` | `rdi` = HDC | 1) on window DCs or invalid handles |
| 112 | `SYS_GDI_DELETE_OBJECT` | `rdi` = HGDIOBJ | — |
| 114 | `SYS_GDI_SET_TEXT_COLOR` | `rdi` = HDC; `rsi` = COLORREF (0x00BBGGRR) | `rsi` unchanged so SetTextColor / GetTextColor pairs keep their Win32 semanti... |
| 115 | `SYS_GDI_SET_BK_COLOR` | — | — |
| 116 | `SYS_GDI_SET_BK_MODE` | `rdi` = HDC; `rsi` = mode (1 = TRANSPARENT | — |
| 117 | `SYS_GDI_STRETCH_BLT_DC` | — | — |
| 118 | `SYS_GDI_CREATE_PEN` | `rdi` = style (ignored in v0); `rsi` = width; `rdx` = COLORREF | — |
| 119 | `SYS_GDI_MOVE_TO_EX` | `rdi` = HDC; `rsi` = x; `rdx` = y; `r10` = user LPPOINT (may be 0) | — |
| 120 | `SYS_GDI_LINE_TO` | `rdi` = HDC; `rsi` = x1 (end); `rdx` = y1 | — |
| 121 | `SYS_GDI_DRAW_TEXT_USER` | `rdi` = HDC rsi = user text pointer rdx = text length (-1 for NUL... | — |
| 122 | `SYS_GDI_RECTANGLE_FILLED` | `rdi` = HDC; `rsi` = x; `rdx` = y; `r10` = w; `r8` = h | — |
| 123 | `SYS_GDI_ELLIPSE_FILLED` | — | — |
| 124 | `SYS_GDI_PAT_BLT` | `rdi` = HDC; `rsi` = x; `rdx` = y; `r10` = w; `r8` = h | — |
| 125 | `SYS_GDI_TEXT_OUT_W` | — | — |
| 126 | `SYS_GDI_DRAW_TEXT_W` | — | — |
| 127 | `SYS_GDI_GET_SYS_COLOR` | `rdi` = nIndex (COLOR_WINDOW=5 | — |
| 128 | `SYS_GDI_GET_SYS_COLOR_BRUSH` | `rdi` = nIndex | — |
| 113 | `SYS_GDI_BITBLT_DC` | — | — |
| 129 | `SYS_WIN32_CUSTOM` | — | — |
| 130 | `SYS_REGISTRY` | — | NTSTATUS in rax (kNtStatusSuccess = 0, STATUS_OBJECT_NAME_NOT_FOUND = 0xC0000... |
| 131 | `SYS_PROCESS_OPEN` | `rdi` = target PID (u64) | — |
| 132 | `SYS_PROCESS_VM_READ` | `rdi` = target process handle (kWin32ProcessBase + idx) rsi = tar... | STATUS_PARTIAL_COPY (0x8000000D) with the byte count populated |
| 133 | `SYS_PROCESS_VM_WRITE` | `rdi` = target process handle rsi = target VA (in the target's us... | — |
| 134 | `SYS_PROCESS_VM_QUERY` | `rdi` = target process handle rsi = target VA to probe rdx = call... | a single-page region: BaseAddress = the 4 KiB-aligned start of the page conta... |
| 135 | `SYS_THREAD_SUSPEND` | `rdi` = thread handle (kWin32ThreadBase + idx in caller's own win... | — |
| 136 | `SYS_THREAD_RESUME` | — | shape as SYS_THREAD_SUSPEND |
| 137 | `SYS_THREAD_GET_CONTEXT` | `rdi` = thread handle (caller's win32_threads[] entry); `rsi` = user pointer to a Win32Context buffer (defined in this he...; `rdx` = ContextFlags filter (CONTEXT_INTEGER / CONTEXT_CONTROL / ... | — |
| 138 | `SYS_THREAD_SET_CONTEXT` | — | — |
| 139 | `SYS_THREAD_OPEN` | `rdi` = target TID (the unique Task::id | — |
| 140 | `SYS_SECTION_CREATE` | `rdi` = size_bytes (1; `rsi` = Win32 PAGE_* protection on creation; `rdx` = inout u64* base_va; `r10` = inout u64* view_size; `r8` = Win32 PAGE_* view protection | STATUS_NOT_IMPLEMENTED |
| 141 | `SYS_SECTION_MAP` | — | — |
| 142 | `SYS_SECTION_UNMAP` | — | — |
| 143 | `SYS_FILE_UNLINK` | `rdi` = const char* user_path; `rsi` = path_len (excluding NUL); `rdx` = const char* user_dst; `r10` = dst_len | — |
| 144 | `SYS_FILE_RENAME` | — | — |
| 145 | `SYS_PROCESS_TERMINATE` | `rdi` = ProcessHandle (NtCurrentProcess = -1 → self-task-exit; `rsi` = exit status (passed through to SchedExit on the self path); `rdx` = user buffer; `r10` = buffer cap; `r8` = user u32* return_length | — |
| 146 | `SYS_THREAD_TERMINATE` | — | — |
| 147 | `SYS_PROCESS_QUERY_INFO` | — | — |
| 148 | `SYS_VM_ALLOCATE` | `rdi` = ProcessHandle (-1 = self); `rsi` = base_addr (0 = pick any aligned); `rdx` = size in bytes (rounded up to a page); `r10` = AllocationType (MEM_COMMIT | MEM_RESERVE; `r8` = protect flags (PAGE_*; `r9` = user u64* base out (set on success) | — |
| 149 | `SYS_VM_FREE` | — | — |
| 150 | `SYS_VM_PROTECT` | — | — |
| 151 | `SYS_FILE_QUERY_ATTRIBUTES` | `rdi` = const char* user_path (NUL-terminated; `rsi` = path_len (excluding NUL); `rdx` = u8* user out buffer (FILE_NETWORK_OPEN_INFORMATION layout...; `r10` = buffer cap | — |
| 152 | `SYS_EXECVE` | `rdi` = const char* user_path (NUL-terminated; `rsi` = path_len | NTSTATUS / -errno on failure |
| 153 | `SYS_SOCKET_OP` | `rdi` = op (kSockOp* below) rsi/rdx/r10/r8/r9 = op-specific args ...; `rdx` = type (SOCK_STREAM=1 / SOCK_DGRAM=2); `rsi` = sock idx; `r10` = addrlen; `r8` = user dest sockaddr; `r9` = dest addrlen | kernel socket pool index >= 0 on success, negative errno on failure |
| 154 | `SYS_DIR_OPEN` | `rdi` = const char* user_path | kWin32DirBase + idx (= 0xA00 |
| 155 | `SYS_DIR_NEXT` | — | — |
| 156 | `SYS_DIR_REWIND` | `rdi` = HANDLE | 0 on success, -1 on bad handle |
| 157 | `SYS_DIR_NOTIFY` | `rdi` = HANDLE  (must be a kWin32DirBase-range dir handle) rsi = ...; `r10` = u64 user_buffer  (FILE_NOTIFY_INFORMATION sequence) r8  =... | bytes written or -1 on bad handle / overrun |
| 158 | `SYS_PROCESS_SPAWN` | — | the new pid or -1 |
| 159 | `SYS_IOCP_CREATE` | — | — |
| 160 | `SYS_IOCP_SET` | — | — |
| 161 | `SYS_IOCP_REMOVE` | — | — |
| 162 | `SYS_IOCP_CLOSE` | — | — |
| 163 | `SYS_JOB_CREATE` | — | — |
| 164 | `SYS_JOB_ASSIGN` | — | — |
| 165 | `SYS_JOB_IS_IN` | — | — |
| 166 | `SYS_JOB_TERMINATE` | — | — |
| 167 | `SYS_JOB_QUERY` | — | — |
| 168 | `SYS_JOB_CLOSE` | — | — |
| 169 | `SYS_TOKEN_ADJUST` | `rdi` = u32 disable_all       (0 / 1) rsi = const u8* user_new   ...; `rdx` = u32 user_new_byte_len (0 if disable_all == 1) r10 = u8* u...; `r8` = u32 user_prev_byte_cap  Returns: 0  on full success (ever... | — |
| 170 | `SYS_WIN_GET_MOUSE_DELTA` | `rdi` = user pointer to a 16-byte DIMOUSESTATE-shaped buffer { i3... | — |
| 171 | `SYS_STDIN_READ` | `rdi` = user pointer to a destination byte buffer; `rsi` = capacity in bytes (must be > 0 | "as much as is ready," not "fill the buffer") |
| 172 | `SYS_DLL_BASE_BY_NAME` | `rdi` = user pointer to NUL-terminated ASCII name; `rsi` = name length in bytes (excluding the NUL) | its base VA |
| 173 | `SYS_WIN_TRACK_POPUP` | `rdi` = user pointer to a TrackPopupReq struct (see below): u32 c...; `rsi` = u32 max_count          // sanity cap | — |
| 174 | `SYS_GDI_SET_CURSOR` | `rdi` = u32 shape    // GdiCursorShape enum (below) rax = previou... | — |
| 175 | `SYS_GDI_CREATE_CURSOR` | `rdi` = const u8* mask_ptr   // 240 bytes (12*20); `rsi` = u32 size             // sanity-check; `rdx` = (y_hot << 8) | x_hot // hotspot inside sprite | a u32 HCURSOR sentinel (≥ 256) the PE then hands to SetCursor via the existin... |
| 180 | `SYS_FILE_MKDIR` | `rdi` = const char* user_path; `rsi` = path_len (excluding NUL); `rdx` = const char* user_target; `r10` = target_len | -1 (other backends will hook in as they grow these primitives) |
| 181 | `SYS_FILE_SYMLINK` | — | — |
| 182 | `SYS_FILE_LINK` | — | — |
| 183 | `SYS_FILE_READLINK` | — | — |
| 184 | `SYS_SYSTEM_PERFORMANCE_INFO` | `rdi` = user SystemPerformanceInfo* rsi = byte capacity | 0 on success, -1 on bad pointer / short buffer |
| 185 | `SYS_NAMED_KOBJ_OPEN_OR_CREATE` | `rdi` = type (0 = mutex; `rsi` = user const char* name (UTF-8 NUL-terminated) rdx = name l...; `r10` = init_state_or_owner — type-specific: mutex:     bInitialO...; `r8` = open_only (1 = OpenMutex/Event/Semaphore semantics — fail... | — |
| 186 | `SYS_WIN32_CREATE_PIPE` | `rdi` = user u64* read_handle_out  — caller-allocated rsi = user ... | 0 on success, (u64)-1 on table-full / pipe-pool-full |
| 187 | `SYS_QUEUE_USER_APC` | `rdi` = u64 target_tid          // 0 / -2 / current tid = self rs... | 0 on success, (u64)-1 on table-full / cross-process / unknown tid |
| 188 | `SYS_DRAIN_USER_APC` | `rdi` = u64* user out_pfn        // VA written on success rsi = u... | 1 if an APC was drained, 0 if the queue was empty for the caller, (u64)-1 on ... |
| 189 | `SYS_PRIORITY_CLASS` | `rdi` = u64 op                   // 0 = get; `rsi` = u32 new_class            // ignored when op == 0 Returns ... | the current (post-op) priority class on success, 0 on bad op |
| 190 | `SYS_PROCESS_SPAWN_EX` | `rdi` = const char* user path           // NUL-terminated rsi = u... | the new pid on success, (u64)-1 on failure (any inherited handle resolves to ... |
| 191 | `SYS_GET_INHERITED_STD` | `rdi` = u64 idx                  // 0=stdin | the inherited Win32 file handle (kWin32HandleBase range) on success, 0 if no ... |
| 192 | `SYS_HEAPEX_CREATE` | `rdi` = u64 pages   (clamped to kWin32ExtraHeapPagesMax) Returns ... | the heap handle (also the base VA) on success, 0 on table-full / OOM |
| 193 | `SYS_HEAPEX_DESTROY` | `rdi` = u64 heap_handle | 1 on success, 0 on bad handle |
| 194 | `SYS_HEAPEX_ALLOC` | `rdi` = u64 heap_handle (0 = default) rsi = u64 size Returns user... | user VA or 0 on OOM |
| 195 | `SYS_HEAPEX_FREE` | `rdi` = u64 heap_handle rsi = u64 ptr Returns 0 | 0 |
| 196 | `SYS_HEAPEX_SIZE` | `rdi` = u64 heap_handle rsi = u64 ptr | bytes or 0 on bad handle / pointer |
| 197 | `SYS_HEAPEX_REALLOC` | `rdi` = u64 heap_handle rsi = u64 ptr        (0 = alloc) rdx = u6... | the new VA or 0 on failure |
| 198 | `SYS_AUDIO_DEVICE_INFO` | `rdi` = u64 op 0 = number of HDA-class output devices (typically ... | 48000 |
| 199 | `SYS_VIRTUAL_ALLOC` | `rdi` = u64 size_bytes        // rounded up to page multiples rsi...; `r10` = u64 hint_va            // 0 = pick from arena bump cursor | the region's base VA on success (each call returns the SAME base when committ... |
| 200 | `SYS_VIRTUAL_FREE` | `rdi` = u64 base_va rsi = u64 size_bytes        // 0 with MEM_REL... | 1 on success, 0 on bad VA / size / type mix |
| 201 | `SYS_VIRTUAL_PROTECT` | `rdi` = u64 base_va rsi = u64 size_bytes rdx = u64 new_protection... | 1 on success, 0 on miss / W^X violation |
| 202 | `SYS_NAMED_PIPE_CREATE` | `rdi` = const char* user name      // bare pipe name (no //  "\; `rsi` = u64 name_len_cap           // bounds the name copy rdx = ... | a Win32-shaped file handle (kWin32HandleBase + slot) for the server end on su... |
| 203 | `SYS_NAMED_PIPE_OPEN` | `rdi` = const char* user name      // bare pipe name rsi = u64 na... | a Win32-shaped file handle for the client end on success, (u64)-1 on miss (na... |
<!-- /AUTO:syscall_args -->
