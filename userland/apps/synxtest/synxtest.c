// Linux-ABI syscall exerciser. No libc — all inline asm.
// Tests a spread of syscalls; prints a tag for each so the boot
// log shows exactly which ones the kernel understood.
typedef unsigned long u64;
typedef long i64;

static inline i64 sc1(long nr, u64 a1) {
    i64 r;
    __asm__ volatile("syscall" : "=a"(r) : "a"(nr), "D"(a1) : "rcx","r11","memory");
    return r;
}
static inline i64 sc2(long nr, u64 a1, u64 a2) {
    i64 r;
    __asm__ volatile("syscall" : "=a"(r) : "a"(nr), "D"(a1), "S"(a2) : "rcx","r11","memory");
    return r;
}
static inline i64 sc3(long nr, u64 a1, u64 a2, u64 a3) {
    i64 r;
    __asm__ volatile("syscall" : "=a"(r) : "a"(nr), "D"(a1), "S"(a2), "d"(a3) : "rcx","r11","memory");
    return r;
}
static inline i64 sc6(long nr, u64 a1, u64 a2, u64 a3, u64 a4, u64 a5, u64 a6) {
    i64 r;
    register u64 r10 __asm__("r10") = a4;
    register u64 r8  __asm__("r8")  = a5;
    register u64 r9  __asm__("r9")  = a6;
    __asm__ volatile("syscall" : "=a"(r) : "a"(nr), "D"(a1), "S"(a2), "d"(a3), "r"(r10), "r"(r8), "r"(r9) : "rcx","r11","memory");
    return r;
}

static void write_cstr(const char* s) {
    unsigned n = 0;
    while (s[n]) ++n;
    sc3(1 /*write*/, 1, (u64)s, n);
}

#define TAG(s) write_cstr(s)

void _start(void) {
    TAG("[exe] start\n");

    // getpid
    i64 pid = sc1(39 /*getpid*/, 0);
    TAG("[exe] getpid ok\n");
    (void)pid;

    // gettid
    sc1(186 /*gettid*/, 0);
    TAG("[exe] gettid ok\n");

    // clock_gettime(CLOCK_REALTIME, &ts)
    u64 ts[2] = {0,0};
    i64 r = sc2(228 /*clock_gettime*/, 0 /*CLOCK_REALTIME*/, (u64)&ts[0]);
    if (r == 0) TAG("[exe] clock_gettime ok\n"); else TAG("[exe] clock_gettime FAIL\n");

    // uname
    char uts[390] = {0};
    r = sc1(63 /*uname*/, (u64)uts);
    if (r == 0) TAG("[exe] uname ok\n"); else TAG("[exe] uname FAIL\n");

    // getrandom(buf, 32, 0)
    char rnd[32];
    r = sc3(318 /*getrandom*/, (u64)rnd, 32, 0);
    if (r == 32) TAG("[exe] getrandom ok\n"); else TAG("[exe] getrandom FAIL\n");

    // mmap anonymous
    i64 p = sc6(9 /*mmap*/, 0, 4096, 3 /*RW*/, 0x22 /*MAP_PRIVATE|MAP_ANON*/, (u64)-1, 0);
    if (p > 0) TAG("[exe] mmap anon ok\n"); else TAG("[exe] mmap anon FAIL\n");

    // open HELLO.TXT, fstat, pread, close
    i64 fd = sc3(2 /*open*/, (u64)"HELLO.TXT", 0, 0);
    if (fd >= 0) {
        TAG("[exe] open ok\n");
        char stbuf[144] = {0};
        r = sc2(5 /*fstat*/, (u64)fd, (u64)stbuf);
        if (r == 0) TAG("[exe] fstat ok\n"); else TAG("[exe] fstat FAIL\n");
        char rb[32] = {0};
        r = sc6(17 /*pread64*/, (u64)fd, (u64)rb, 17, 0, 0, 0);
        if (r == 17) TAG("[exe] pread ok\n"); else TAG("[exe] pread FAIL\n");
        // file-backed mmap — the slice just added
        i64 q = sc6(9 /*mmap*/, 0, 17, 1 /*PROT_READ*/, 2 /*MAP_PRIVATE*/, (u64)fd, 0);
        if (q > 0) {
            TAG("[exe] mmap file ok\n");
            sc3(1, 1, (u64)q, 17);  // write mapped contents
        } else {
            TAG("[exe] mmap file FAIL\n");
        }
        sc1(3 /*close*/, fd);
        TAG("[exe] close ok\n");
    } else {
        TAG("[exe] open FAIL\n");
    }

    // sched_yield
    sc1(24 /*sched_yield*/, 0);
    TAG("[exe] yield ok\n");

    // --- boundary probes: exercise the translation gap-fill
    // layer. Print the exact rc so the boot log shows whether
    // each call is implemented, gap-filled, or rejected.
    char numbuf[32];

    // Inline decimal formatter — no libc.
    #define FMTI(num_expr) do { \
        i64 v = (num_expr); \
        int neg = 0; \
        if (v < 0) { neg = 1; v = -v; } \
        int i = 0; \
        if (v == 0) numbuf[i++] = '0'; \
        else { \
            char tmp[20]; int j = 0; \
            while (v > 0) { tmp[j++] = '0' + (int)(v % 10); v /= 10; } \
            if (neg) numbuf[i++] = '-'; \
            while (j > 0) numbuf[i++] = tmp[--j]; \
        } \
        numbuf[i++] = '\n'; \
        sc3(1, 1, (u64)numbuf, i); \
    } while (0)

    // readv/writev (translation gap-fills these into a DoRead/DoWrite loop)
    struct iov { void* base; u64 len; } wiov;
    const char* wmsg = "writev-ok\n";
    wiov.base = (void*)wmsg;
    wiov.len = 10;
    TAG("[exe] writev rc=");
    FMTI(sc3(20 /*writev*/, 1, (u64)&wiov, 1));

    // gettimeofday (translator synthesizes from clock_gettime)
    u64 tv[2] = {0,0};
    TAG("[exe] gettimeofday rc=");
    FMTI(sc2(96 /*gettimeofday*/, (u64)&tv[0], 0));

    // sysinfo
    char si[112];
    for (int i=0;i<112;++i) si[i]=0;
    TAG("[exe] sysinfo rc=");
    FMTI(sc1(99 /*sysinfo*/, (u64)si));

    // prlimit64(0, RLIMIT_NOFILE=7, NULL, &rlim) — translator fills
    u64 rlim[2] = {0,0};
    TAG("[exe] prlimit64 rc=");
    FMTI(sc6(302 /*prlimit64*/, 0, 7, 0, (u64)&rlim[0], 0, 0));

    // madvise — translator accepts + no-ops
    TAG("[exe] madvise rc=");
    FMTI(sc3(28 /*madvise*/, (u64)p, 4096, 0));

    // rseq — translator deliberately returns -ENOSYS
    TAG("[exe] rseq rc=");
    FMTI(sc6(334 /*rseq*/, 0, 0, 0, 0, 0, 0));

    // fork — not implemented at all
    TAG("[exe] fork rc=");
    FMTI(sc1(57 /*fork*/, 0));

    // socket — no user-space net
    TAG("[exe] socket rc=");
    FMTI(sc3(41 /*socket*/, 2 /*AF_INET*/, 1 /*SOCK_STREAM*/, 0));

    // pipe — no in-kernel pipe yet
    int pipefds[2] = {-1,-1};
    TAG("[exe] pipe rc=");
    FMTI(sc1(22 /*pipe*/, (u64)pipefds));

    // access("HELLO.TXT", F_OK=0)
    TAG("[exe] access rc=");
    FMTI(sc2(21 /*access*/, (u64)"HELLO.TXT", 0));

    // getcwd
    char cwdbuf[64];
    for (int i=0;i<64;++i) cwdbuf[i]=0;
    TAG("[exe] getcwd rc=");
    FMTI(sc2(79 /*getcwd*/, (u64)cwdbuf, sizeof(cwdbuf)));

    // futex(uaddr, FUTEX_WAKE=1, 0, ...) — zero waiters is the
    // well-defined return
    static u64 fut = 0;
    TAG("[exe] futex rc=");
    FMTI(sc6(202 /*futex*/, (u64)&fut, 1 /*FUTEX_WAKE*/, 0, 0, 0, 0));

    // getppid / getuid / getgid — rare-used but quick
    TAG("[exe] getppid rc=");
    FMTI(sc1(110 /*getppid*/, 0));
    TAG("[exe] getuid rc=");
    FMTI(sc1(102 /*getuid*/, 0));
    TAG("[exe] getgid rc=");
    FMTI(sc1(104 /*getgid*/, 0));

    // === tier 3: new primary-dispatch syscalls (this slice) ===
    //
    // openat(AT_FDCWD=-100, "HELLO.TXT", O_RDONLY=0, 0)
    i64 fd2 = sc6(257 /*openat*/, (u64)-100, (u64)"HELLO.TXT", 0, 0, 0, 0);
    TAG("[exe] openat rc=");
    FMTI(fd2);
    if (fd2 >= 0) {
        // newfstatat(fd2, "", stbuf, AT_EMPTY_PATH=0x1000)
        char st[144] = {0};
        TAG("[exe] newfstatat(AT_EMPTY_PATH) rc=");
        FMTI(sc6(262 /*newfstatat*/, (u64)fd2, (u64)"", (u64)st, 0x1000, 0, 0));

        // dup3(fd2, fd3=11, 0) — duplicate onto a specific fd slot
        TAG("[exe] dup3 rc=");
        FMTI(sc3(292 /*dup3*/, fd2, 11, 0));

        sc1(3 /*close*/, 11);
        sc1(3 /*close*/, fd2);
    }

    // newfstatat(AT_FDCWD, "HELLO.TXT", stbuf, 0) — path form
    {
        char st[144] = {0};
        TAG("[exe] newfstatat(path) rc=");
        FMTI(sc6(262 /*newfstatat*/, (u64)-100, (u64)"HELLO.TXT", (u64)st, 0, 0, 0));
    }

    // getrusage(RUSAGE_SELF=0, &ru)
    {
        char ru[144] = {0};
        TAG("[exe] getrusage rc=");
        FMTI(sc2(98 /*getrusage*/, 0, (u64)ru));
    }

    // poll: one pollfd for stdin wanting POLLIN. The stub marks
    // it ready immediately (tty "ready to read" forever semantics).
    {
        struct { int fd; short events; short revents; } pfd = {0, 0x0001 /*POLLIN*/, 0};
        TAG("[exe] poll(nfds=1,stdin) rc=");
        FMTI(sc3(7 /*poll*/, (u64)&pfd, 1, 0));
    }

    // select: all fd_sets NULL, nfds=0, timeout=NULL — the stub
    // returns 0 regardless.
    TAG("[exe] select rc=");
    FMTI(sc6(23 /*select*/, 0, 0, 0, 0, 0, 0));

    // getdents64(fd, buf, sizeof(buf)) — stub returns 0 (=EOF).
    {
        char dbuf[256];
        i64 df = sc3(2 /*open*/, (u64)"HELLO.TXT", 0, 0); // can't open a dir yet; reuse a file fd
        if (df >= 0) {
            TAG("[exe] getdents64 rc=");
            FMTI(sc3(217 /*getdents64*/, (u64)df, (u64)dbuf, sizeof(dbuf)));
            sc1(3, df);
        }
    }

    // set_robust_list: accepting + no-op
    TAG("[exe] set_robust_list rc=");
    FMTI(sc2(273 /*set_robust_list*/, 0, 24));

    // === tier 4: deliberately unimplemented (should -ENOSYS via translator) ===
    // fork / vfork / clone / clone3 / execve / wait4 — all route
    // through the translator's synthetic:enosys-no-process-create
    // branch (added previous slice). Verify they still come back
    // with -ENOSYS = -38.
    TAG("[exe] vfork rc=");
    FMTI(sc1(58 /*vfork*/, 0));
    TAG("[exe] clone rc=");
    FMTI(sc6(56 /*clone*/, 0, 0, 0, 0, 0, 0));
    TAG("[exe] execve rc=");
    FMTI(sc3(59 /*execve*/, (u64)"HELLO.TXT", 0, 0));
    TAG("[exe] wait4 rc=");
    FMTI(sc6(61 /*wait4*/, (u64)-1, 0, 0, 0, 0, 0));

    // exit_group(0x55)
    TAG("[exe] all done, exit 0x55\n");
    sc1(231 /*exit_group*/, 0x55);
    __builtin_unreachable();
}
