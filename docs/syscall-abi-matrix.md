# Syscall ABI Coverage Matrix

_Auto-generated; do not edit by hand._



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
| nt | 8 | `NtWriteFile` | translated | `kernel/subsystems/win32/nt_syscall_table_generated.h::SYS_WRITE` | routes to native SYS_WRITE |
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
| nt | 19 | `NtEnumerateValueKey` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 20 | `NtFindAtom` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 21 | `NtQueryDefaultLocale` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 22 | `NtQueryKey` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 23 | `NtQueryValueKey` | translated | `kernel/subsystems/win32/nt_syscall_table_generated.h::SYS_REGISTRY` | routes to native SYS_REGISTRY |
| nt | 24 | `NtAllocateVirtualMemory` | translated | `kernel/subsystems/win32/nt_syscall_table_generated.h::SYS_VMAP` | routes to native SYS_VMAP |
| nt | 25 | `NtQueryInformationProcess` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 26 | `NtWaitForMultipleObjects32` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 27 | `NtWriteFileGather` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 28 | `NtSetInformationProcess` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 29 | `NtCreateKey` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 30 | `NtFreeVirtualMemory` | translated | `kernel/subsystems/win32/nt_syscall_table_generated.h::SYS_VUNMAP` | routes to native SYS_VUNMAP |
| nt | 31 | `NtImpersonateClientOfPort` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 32 | `NtReleaseMutant` | translated | `kernel/subsystems/win32/nt_syscall_table_generated.h::SYS_MUTEX_RELEASE` | routes to native SYS_MUTEX_RELEASE |
| nt | 33 | `NtQueryInformationToken` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 34 | `NtRequestWaitReplyPort` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 35 | `NtQueryVirtualMemory` | translated | `kernel/subsystems/win32/nt_syscall_table_generated.h::SYS_PROCESS_VM_QUERY` | routes to native SYS_PROCESS_VM_QUERY |
| nt | 36 | `NtOpenThreadToken` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 37 | `NtQueryInformationThread` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 38 | `NtOpenProcess` | translated | `kernel/subsystems/win32/nt_syscall_table_generated.h::SYS_PROCESS_OPEN` | routes to native SYS_PROCESS_OPEN |
| nt | 39 | `NtSetInformationFile` | translated | `kernel/subsystems/win32/nt_syscall_table_generated.h::SYS_FILE_SEEK` | routes to native SYS_FILE_SEEK |
| nt | 40 | `NtMapViewOfSection` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 41 | `NtAccessCheckAndAuditAlarm` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 42 | `NtUnmapViewOfSection` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 43 | `NtReplyWaitReceivePortEx` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 44 | `NtTerminateProcess` | translated | `kernel/subsystems/win32/nt_syscall_table_generated.h::SYS_EXIT` | routes to native SYS_EXIT |
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
| nt | 61 | `NtQueryAttributesFile` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
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
| nt | 74 | `NtCreateSection` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 75 | `NtFlushBuffersFile` | translated | `kernel/subsystems/win32/nt_syscall_table_generated.h::SYS_NT_INVOKE` | routes to native SYS_NT_INVOKE |
| nt | 76 | `NtApphelpCacheControl` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 77 | `NtCreateProcessEx` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 78 | `NtCreateThread` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 79 | `NtIsProcessInJob` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 80 | `NtProtectVirtualMemory` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
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
| nt | 96 | `NtSetValueKey` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
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
| nt | 201 | `NtCreateThreadEx` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
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
| nt | 219 | `NtDeleteFile` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 220 | `NtDeleteKey` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 221 | `NtDeleteObjectAuditAlarm` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 222 | `NtDeletePrivateNamespace` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
| nt | 223 | `NtDeleteValueKey` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
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
| nt | 242 | `NtFlushKey` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
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
| nt | 337 | `NtQueryFullAttributesFile` | unimplemented | `kernel/subsystems/win32/thunks.cpp::NtStubCatchAll` | STATUS_NOT_IMPLEMENTED |
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
