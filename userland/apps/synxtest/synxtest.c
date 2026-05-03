// Linux-ABI syscall exerciser. No libc — all inline asm.
// Tests a spread of syscalls; prints a tag for each so the boot
// log shows exactly which ones the kernel understood.
typedef unsigned long u64;
typedef long i64;

// Compiler-emitted helpers for zero-init of stack arrays. clang
// emits implicit calls to memset/memcpy for `char buf[N] = {0}`
// even with -fno-builtin; provide the symbols ourselves so the
// freestanding link stays self-contained (no libc, no libgcc).
__attribute__((used)) void* memset(void* d, int c, unsigned long n)
{
    unsigned char* p = (unsigned char*)d;
    for (unsigned long i = 0; i < n; ++i)
        p[i] = (unsigned char)c;
    return d;
}
__attribute__((used)) void* memcpy(void* d, const void* s, unsigned long n)
{
    unsigned char* dp = (unsigned char*)d;
    const unsigned char* sp = (const unsigned char*)s;
    for (unsigned long i = 0; i < n; ++i)
        dp[i] = sp[i];
    return d;
}

static inline i64 sc1(long nr, u64 a1)
{
    i64 r;
    __asm__ volatile("syscall" : "=a"(r) : "a"(nr), "D"(a1) : "rcx", "r11", "memory");
    return r;
}
static inline i64 sc2(long nr, u64 a1, u64 a2)
{
    i64 r;
    __asm__ volatile("syscall" : "=a"(r) : "a"(nr), "D"(a1), "S"(a2) : "rcx", "r11", "memory");
    return r;
}
static inline i64 sc3(long nr, u64 a1, u64 a2, u64 a3)
{
    i64 r;
    __asm__ volatile("syscall" : "=a"(r) : "a"(nr), "D"(a1), "S"(a2), "d"(a3) : "rcx", "r11", "memory");
    return r;
}
static inline i64 sc6(long nr, u64 a1, u64 a2, u64 a3, u64 a4, u64 a5, u64 a6)
{
    i64 r;
    register u64 r10 __asm__("r10") = a4;
    register u64 r8 __asm__("r8") = a5;
    register u64 r9 __asm__("r9") = a6;
    __asm__ volatile("syscall"
                     : "=a"(r)
                     : "a"(nr), "D"(a1), "S"(a2), "d"(a3), "r"(r10), "r"(r8), "r"(r9)
                     : "rcx", "r11", "memory");
    return r;
}

static void write_cstr(const char* s)
{
    unsigned n = 0;
    while (s[n])
        ++n;
    sc3(1 /*write*/, 1, (u64)s, n);
}

#define TAG(s) write_cstr(s)

void _start(void)
{
    TAG("[exe] start\n");

    // getpid
    i64 pid = sc1(39 /*getpid*/, 0);
    TAG("[exe] getpid ok\n");
    (void)pid;

    // gettid
    sc1(186 /*gettid*/, 0);
    TAG("[exe] gettid ok\n");

    // clock_gettime(CLOCK_REALTIME, &ts)
    u64 ts[2] = {0, 0};
    i64 r = sc2(228 /*clock_gettime*/, 0 /*CLOCK_REALTIME*/, (u64)&ts[0]);
    if (r == 0)
        TAG("[exe] clock_gettime ok\n");
    else
        TAG("[exe] clock_gettime FAIL\n");

    // uname
    char uts[390] = {0};
    r = sc1(63 /*uname*/, (u64)uts);
    if (r == 0)
        TAG("[exe] uname ok\n");
    else
        TAG("[exe] uname FAIL\n");

    // getrandom(buf, 32, 0)
    char rnd[32];
    r = sc3(318 /*getrandom*/, (u64)rnd, 32, 0);
    if (r == 32)
        TAG("[exe] getrandom ok\n");
    else
        TAG("[exe] getrandom FAIL\n");

    // mmap anonymous
    i64 p = sc6(9 /*mmap*/, 0, 4096, 3 /*RW*/, 0x22 /*MAP_PRIVATE|MAP_ANON*/, (u64)-1, 0);
    if (p > 0)
        TAG("[exe] mmap anon ok\n");
    else
        TAG("[exe] mmap anon FAIL\n");

    // open HELLO.TXT, fstat, pread, close
    i64 fd = sc3(2 /*open*/, (u64) "HELLO.TXT", 0, 0);
    if (fd >= 0)
    {
        TAG("[exe] open ok\n");
        char stbuf[144] = {0};
        r = sc2(5 /*fstat*/, (u64)fd, (u64)stbuf);
        if (r == 0)
            TAG("[exe] fstat ok\n");
        else
            TAG("[exe] fstat FAIL\n");
        char rb[32] = {0};
        r = sc6(17 /*pread64*/, (u64)fd, (u64)rb, 17, 0, 0, 0);
        if (r == 17)
            TAG("[exe] pread ok\n");
        else
            TAG("[exe] pread FAIL\n");
        // file-backed mmap — the slice just added
        i64 q = sc6(9 /*mmap*/, 0, 17, 1 /*PROT_READ*/, 2 /*MAP_PRIVATE*/, (u64)fd, 0);
        if (q > 0)
        {
            TAG("[exe] mmap file ok\n");
            sc3(1, 1, (u64)q, 17); // write mapped contents
        }
        else
        {
            TAG("[exe] mmap file FAIL\n");
        }
        sc1(3 /*close*/, fd);
        TAG("[exe] close ok\n");
    }
    else
    {
        TAG("[exe] open FAIL\n");
    }

    // sched_yield
    sc1(24 /*sched_yield*/, 0);
    TAG("[exe] yield ok\n");

    // --- boundary probes: exercise the translation gap-fill
    // layer. Print the exact rc so the boot log shows whether
    // each call is implemented, gap-filled, or rejected.
    char numbuf[160];

// Inline decimal formatter — no libc.
#define FMTI(num_expr)                                                                                                 \
    do                                                                                                                 \
    {                                                                                                                  \
        i64 v = (num_expr);                                                                                            \
        int neg = 0;                                                                                                   \
        if (v < 0)                                                                                                     \
        {                                                                                                              \
            neg = 1;                                                                                                   \
            v = -v;                                                                                                    \
        }                                                                                                              \
        int i = 0;                                                                                                     \
        if (v == 0)                                                                                                    \
            numbuf[i++] = '0';                                                                                         \
        else                                                                                                           \
        {                                                                                                              \
            char tmp[20];                                                                                              \
            int j = 0;                                                                                                 \
            while (v > 0)                                                                                              \
            {                                                                                                          \
                tmp[j++] = '0' + (int)(v % 10);                                                                        \
                v /= 10;                                                                                               \
            }                                                                                                          \
            if (neg)                                                                                                   \
                numbuf[i++] = '-';                                                                                     \
            while (j > 0)                                                                                              \
                numbuf[i++] = tmp[--j];                                                                                \
        }                                                                                                              \
        numbuf[i++] = '\n';                                                                                            \
        sc3(1, 1, (u64)numbuf, i);                                                                                     \
    } while (0)

// Atomic-line variant: builds "[exe] LABEL rc=NUM\n" in one buffer
// and writes it with a single sc3(SYS_write). The TAG-then-FMTI
// shape leaves the rc syscall (and its kernel logs) BETWEEN the
// prefix write and the value write — on a busy serial port that
// makes ^\[exe\] greps miss the rc. Synfs/synet adopted this
// pattern; synxtest now uses it for every "rc=N" call too.
#define RC(label, num_expr)                                                                                            \
    do                                                                                                                 \
    {                                                                                                                  \
        i64 v = (num_expr);                                                                                            \
        const char* lbl = (label);                                                                                     \
        int i = 0;                                                                                                     \
        const char* prefix = "[exe] ";                                                                                 \
        for (int k = 0; prefix[k] && i < (int)sizeof(numbuf) - 16; ++k)                                                \
            numbuf[i++] = prefix[k];                                                                                   \
        for (int k = 0; lbl[k] && i < (int)sizeof(numbuf) - 16; ++k)                                                   \
            numbuf[i++] = lbl[k];                                                                                      \
        numbuf[i++] = ' ';                                                                                             \
        numbuf[i++] = 'r';                                                                                             \
        numbuf[i++] = 'c';                                                                                             \
        numbuf[i++] = '=';                                                                                             \
        int neg = 0;                                                                                                   \
        if (v < 0)                                                                                                     \
        {                                                                                                              \
            neg = 1;                                                                                                   \
            v = -v;                                                                                                    \
        }                                                                                                              \
        if (v == 0)                                                                                                    \
            numbuf[i++] = '0';                                                                                         \
        else                                                                                                           \
        {                                                                                                              \
            char tmp[20];                                                                                              \
            int j = 0;                                                                                                 \
            while (v > 0)                                                                                              \
            {                                                                                                          \
                tmp[j++] = '0' + (int)(v % 10);                                                                        \
                v /= 10;                                                                                               \
            }                                                                                                          \
            if (neg)                                                                                                   \
                numbuf[i++] = '-';                                                                                     \
            while (j > 0)                                                                                              \
                numbuf[i++] = tmp[--j];                                                                                \
        }                                                                                                              \
        numbuf[i++] = '\n';                                                                                            \
        sc3(1, 1, (u64)numbuf, i);                                                                                     \
    } while (0)

    // readv/writev (translation gap-fills these into a DoRead/DoWrite loop)
    struct iov
    {
        void* base;
        u64 len;
    } wiov;
    const char* wmsg = "writev-ok\n";
    wiov.base = (void*)wmsg;
    wiov.len = 10;
    RC("writev", sc3(20 /*writev*/, 1, (u64)&wiov, 1));

    // gettimeofday (translator synthesizes from clock_gettime)
    u64 tv[2] = {0, 0};
    RC("gettimeofday", sc2(96 /*gettimeofday*/, (u64)&tv[0], 0));

    // sysinfo
    char si[112];
    for (int i = 0; i < 112; ++i)
        si[i] = 0;
    RC("sysinfo", sc1(99 /*sysinfo*/, (u64)si));

    // prlimit64(0, RLIMIT_NOFILE=7, NULL, &rlim) — translator fills
    u64 rlim[2] = {0, 0};
    RC("prlimit64", sc6(302 /*prlimit64*/, 0, 7, 0, (u64)&rlim[0], 0, 0));

    // madvise — translator accepts + no-ops
    RC("madvise", sc3(28 /*madvise*/, (u64)p, 4096, 0));

    // rseq — translator deliberately returns -ENOSYS
    RC("rseq", sc6(334 /*rseq*/, 0, 0, 0, 0, 0, 0));

    // fork — not implemented at all
    RC("fork", sc1(57 /*fork*/, 0));

    // socket — no user-space net
    RC("socket", sc3(41 /*socket*/, 2 /*AF_INET*/, 1 /*SOCK_STREAM*/, 0));

    // pipe — no in-kernel pipe yet
    int pipefds[2] = {-1, -1};
    RC("pipe", sc1(22 /*pipe*/, (u64)pipefds));

    // access("HELLO.TXT", F_OK=0)
    RC("access", sc2(21 /*access*/, (u64) "HELLO.TXT", 0));

    // getcwd
    char cwdbuf[64];
    for (int i = 0; i < 64; ++i)
        cwdbuf[i] = 0;
    RC("getcwd", sc2(79 /*getcwd*/, (u64)cwdbuf, sizeof(cwdbuf)));

    // futex(uaddr, FUTEX_WAKE=1, 0, ...) — zero waiters is the
    // well-defined return
    static u64 fut = 0;
    RC("futex", sc6(202 /*futex*/, (u64)&fut, 1 /*FUTEX_WAKE*/, 0, 0, 0, 0));

    // getppid / getuid / getgid — rare-used but quick
    RC("getppid", sc1(110 /*getppid*/, 0));
    RC("getuid", sc1(102 /*getuid*/, 0));
    RC("getgid", sc1(104 /*getgid*/, 0));

    // === tier 3: new primary-dispatch syscalls (this slice) ===
    //
    // openat(AT_FDCWD=-100, "HELLO.TXT", O_RDONLY=0, 0)
    i64 fd2 = sc6(257 /*openat*/, (u64)-100, (u64) "HELLO.TXT", 0, 0, 0, 0);
    RC("openat", fd2);
    if (fd2 >= 0)
    {
        // newfstatat(fd2, "", stbuf, AT_EMPTY_PATH=0x1000)
        char st[144] = {0};
        RC("newfstatat(AT_EMPTY_PATH)", sc6(262 /*newfstatat*/, (u64)fd2, (u64) "", (u64)st, 0x1000, 0, 0));

        // dup3(fd2, fd3=11, 0) — duplicate onto a specific fd slot
        RC("dup3", sc3(292 /*dup3*/, fd2, 11, 0));

        sc1(3 /*close*/, 11);
        sc1(3 /*close*/, fd2);
    }

    // newfstatat(AT_FDCWD, "HELLO.TXT", stbuf, 0) — path form
    {
        char st[144] = {0};
        RC("newfstatat(path)", sc6(262 /*newfstatat*/, (u64)-100, (u64) "HELLO.TXT", (u64)st, 0, 0, 0));
    }

    // getrusage(RUSAGE_SELF=0, &ru)
    {
        char ru[144] = {0};
        RC("getrusage", sc2(98 /*getrusage*/, 0, (u64)ru));
    }

    // poll: one pollfd for stdin wanting POLLIN. The stub marks
    // it ready immediately (tty "ready to read" forever semantics).
    {
        struct
        {
            int fd;
            short events;
            short revents;
        } pfd = {0, 0x0001 /*POLLIN*/, 0};
        RC("poll(nfds=1,stdin)", sc3(7 /*poll*/, (u64)&pfd, 1, 0));
    }

    // select: all fd_sets NULL, nfds=0, timeout=NULL — the stub
    // returns 0 regardless.
    RC("select", sc6(23 /*select*/, 0, 0, 0, 0, 0, 0));

    // getdents64(fd, buf, sizeof(buf)) — stub returns 0 (=EOF).
    {
        char dbuf[256];
        i64 df = sc3(2 /*open*/, (u64) "HELLO.TXT", 0, 0); // can't open a dir yet; reuse a file fd
        if (df >= 0)
        {
            RC("getdents64", sc3(217 /*getdents64*/, (u64)df, (u64)dbuf, sizeof(dbuf)));
            sc1(3, df);
        }
    }

    // set_robust_list: accepting + no-op
    RC("set_robust_list", sc2(273 /*set_robust_list*/, 0, 24));

    // === tier 5: I/O + memory primitives ===
    // dup(fd) / dup2(fd, newfd): both should produce a fresh fd
    {
        i64 dfd = sc3(2 /*open*/, (u64) "HELLO.TXT", 0, 0);
        if (dfd >= 0)
        {
            RC("dup", sc1(32 /*dup*/, dfd));
            RC("dup2", sc2(33 /*dup2*/, dfd, 12));
            sc1(3, 12);
            sc1(3, dfd);
        }
    }

    // fcntl(fd, F_GETFL): kernel reports current flags. Run on
    // stdout (always-open).
    RC("fcntl(F_GETFL stdout)", sc3(72 /*fcntl*/, 1, 3 /*F_GETFL*/, 0));

    // brk(0): asks the kernel for the current break. Returns the
    // current break address (positive) or -ENOMEM.
    RC("brk(0)", sc1(12 /*brk*/, 0));

    // mprotect: change protection on the anonymous mmap'd page
    // from RW to R-only. Expect 0 on success.
    if (p > 0)
    {
        RC("mprotect(R)", sc3(10 /*mprotect*/, (u64)p, 4096, 1 /*PROT_READ*/));
    }

    // munmap: drop the anonymous mmap'd page. Don't dereference p
    // after this point.
    if (p > 0)
    {
        RC("munmap", sc2(11 /*munmap*/, (u64)p, 4096));
    }

    // === tier 6: pipe round-trip + eventfd round-trip + timerfd ===
    {
        int pfds[2] = {-1, -1};
        i64 prc = sc1(22 /*pipe*/, (u64)pfds);
        RC("pipe(create)", prc);
        if (prc == 0 && pfds[0] >= 0 && pfds[1] >= 0)
        {
            const char* msg = "ping";
            i64 wn = sc3(1 /*write*/, pfds[1], (u64)msg, 4);
            RC("pipe.write", wn);
            char rb[8] = {0};
            i64 rn = sc3(0 /*read*/, pfds[0], (u64)rb, 4);
            RC("pipe.read", rn);
            sc1(3, pfds[0]);
            sc1(3, pfds[1]);
        }
    }

    // eventfd2(initval=5, flags=0). Then read returns the counter.
    {
        i64 efd = sc2(290 /*eventfd2*/, 5, 0);
        RC("eventfd2", efd);
        if (efd >= 0)
        {
            unsigned long long buf = 0;
            i64 rn = sc3(0 /*read*/, efd, (u64)&buf, 8);
            RC("eventfd.read", rn);
            sc1(3, efd);
        }
    }

    // timerfd_create(CLOCK_MONOTONIC, 0). No setting; just create+close.
    {
        i64 tfd = sc2(283 /*timerfd_create*/, 1 /*CLOCK_MONOTONIC*/, 0);
        RC("timerfd_create", tfd);
        if (tfd >= 0)
            sc1(3, tfd);
    }

    // === tier 7: epoll + signalfd + inotify ===
    {
        i64 ep = sc1(291 /*epoll_create1*/, 0);
        RC("epoll_create1", ep);
        if (ep >= 0)
        {
            // epoll_wait with timeout=0 should return 0 immediately.
            char evbuf[16];
            RC("epoll_wait(t=0)", sc6(232 /*epoll_wait*/, ep, (u64)evbuf, 1, 0, 0, 0));
            sc1(3, ep);
        }
    }

    // signalfd4(-1, &mask, 8, 0): create a fresh signalfd masked
    // for SIGUSR1. Reading with no pending signal should return
    // -EAGAIN.
    {
        u64 mask = 1ull << (10 - 1); // SIGUSR1 = 10, bit 9
        i64 sfd = sc6(289 /*signalfd4*/, (u64)-1, (u64)&mask, 8, 0, 0, 0);
        RC("signalfd4", sfd);
        if (sfd >= 0)
            sc1(3, sfd);
    }

    // inotify_init1 + add_watch + rm_watch
    {
        i64 ifd = sc1(294 /*inotify_init1*/, 0);
        RC("inotify_init1", ifd);
        if (ifd >= 0)
        {
            i64 wd = sc3(254 /*inotify_add_watch*/, ifd, (u64) "HELLO.TXT", 0xFFF);
            RC("inotify_add_watch", wd);
            if (wd >= 0)
            {
                RC("inotify_rm_watch", sc2(255 /*inotify_rm_watch*/, ifd, wd));
            }
            sc1(3, ifd);
        }
    }

    // === tier 8: pidfd + memfd + statx ===
    {
        i64 pid_self = sc1(39 /*getpid*/, 0);
        i64 pfd_self = sc3(434 /*pidfd_open*/, (u64)pid_self, 0, 0);
        RC("pidfd_open(self)", pfd_self);
        if (pfd_self >= 0)
            sc1(3, pfd_self);
    }

    // memfd_create("synx", 0): anonymous memory fd. Should be a
    // fresh fd >= 0.
    {
        i64 mfd = sc2(319 /*memfd_create*/, (u64) "synx", 0);
        RC("memfd_create", mfd);
        if (mfd >= 0)
            sc1(3, mfd);
    }

    // statx(AT_FDCWD, "HELLO.TXT", AT_NO_AUTOMOUNT, STATX_BASIC_STATS, &buf)
    {
        char stxbuf[256];
        for (int i = 0; i < 256; ++i)
            stxbuf[i] = 0;
        RC("statx", sc6(332 /*statx*/, (u64)-100, (u64) "HELLO.TXT", 0x800 /*NO_AUTOMOUNT*/,
                        0x7ff /*STATX_BASIC_STATS*/, (u64)stxbuf, 0));
    }

    // === tier 9: FS metadata + path probes ===
    // chdir + getcwd round-trip. Use a path we know to exist.
    {
        RC("chdir(\"/\")", sc1(80 /*chdir*/, (u64) "/"));
    }

    // readlink on a non-symlink: expect -EINVAL on Linux.
    {
        char lbuf[64];
        RC("readlink", sc3(89 /*readlink*/, (u64) "HELLO.TXT", (u64)lbuf, sizeof(lbuf)));
    }

    // === tier 10: signal mask + alt stack (real engines) ===
    {
        // rt_sigprocmask(SIG_BLOCK, NULL, &oldset, 8) — query current mask.
        u64 oldset = 0;
        RC("rt_sigprocmask", sc6(14 /*rt_sigprocmask*/, 0 /*SIG_BLOCK*/, 0, (u64)&oldset, 8, 0, 0));

        // sigaltstack(NULL, &oldss) — query current alt stack.
        char oldss[24] = {0};
        RC("sigaltstack", sc2(131 /*sigaltstack*/, 0, (u64)oldss));
    }

    // === tier 11: -EPERM / -ENOSYS facades (verify honest refusal) ===
    // bpf — currently -EPERM (matches Linux CAP_SYS_ADMIN gating)
    RC("bpf", sc3(321 /*bpf*/, 0, 0, 0));

    // perf_event_open — -EPERM
    RC("perf_event_open", sc6(298 /*perf_event_open*/, 0, 0, 0, 0, 0, 0));

    // mount — -EPERM (containers blocked)
    RC("mount", sc6(165 /*mount*/, 0, 0, 0, 0, 0, 0));

    // userfaultfd — -ENOSYS (facade only)
    RC("userfaultfd", sc1(323 /*userfaultfd*/, 0));

    // io_uring_setup — -ENOSYS
    RC("io_uring_setup", sc2(425 /*io_uring_setup*/, 1, 0));

    // landlock_create_ruleset — -ENOSYS (avoids false sandbox advertise)
    RC("landlock_create_ruleset", sc3(444 /*landlock_create_ruleset*/, 0, 0, 0));

    // ptrace — kCapDebug-gated; without the cap returns -EPERM
    RC("ptrace", sc6(101 /*ptrace*/, 0 /*PTRACE_TRACEME*/, 0, 0, 0, 0, 0));

    // === tier 4: process creation (fork/clone/execve/wait4) ===
    // fork is LANDED — handle parent/child split so the child
    // doesn't re-run the entire test body.
    i64 fpid = sc1(57 /*fork*/, 0);
    if (fpid == 0)
    {
        // Child path: print one line and exit immediately.
        TAG("[exe] fork.child running\n");
        sc1(231 /*exit_group*/, 0);
        __builtin_unreachable();
    }
    RC("fork", fpid);
    if (fpid > 0)
    {
        // Reap the child so we don't leak a zombie.
        char wstatus[8] = {0};
        RC("wait4(child)", sc6(61 /*wait4*/, (u64)fpid, (u64)wstatus, 0, 0, 0, 0));
    }

    // vfork is wired to the same DoFork — same parent/child rules.
    i64 vpid = sc1(58 /*vfork*/, 0);
    if (vpid == 0)
    {
        sc1(231 /*exit_group*/, 0);
        __builtin_unreachable();
    }
    RC("vfork", vpid);
    if (vpid > 0)
    {
        char wstatus[8] = {0};
        sc6(61 /*wait4*/, (u64)vpid, (u64)wstatus, 0, 0, 0, 0);
    }

    // clone(0,0,0,0,0,0): no flags, no stack — usually -EINVAL.
    RC("clone(0)", sc6(56 /*clone*/, 0, 0, 0, 0, 0, 0));

    // execve("HELLO.TXT", ...): not a valid ELF/PE, expect failure.
    RC("execve", sc3(59 /*execve*/, (u64) "HELLO.TXT", 0, 0));

    // exit_group(0x55)
    TAG("[exe] all done, exit 0x55\n");
    sc1(231 /*exit_group*/, 0x55);
    __builtin_unreachable();
}
