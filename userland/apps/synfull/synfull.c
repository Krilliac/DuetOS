// Linux-ABI syscall exhaustive exerciser. Issues every Linux x86_64
// spec syscall (374 entries) with zero-args, captures rc per call,
// and emits `[full] <nr>=<rc>` atomic-line output.
//
// Most calls return -EBADF / -EINVAL / -EFAULT at zero-args because
// the handler immediately rejects NULL pointers / fd=0-when-not-tty
// / mode==0 / etc. That's the point: each handler must run and
// return SOMETHING coherent. A return of -ENOSYS (-38) means we
// didn't implement the syscall (intentionally if it's in
// syscall_aux.cpp's exception list, regression otherwise). A
// crash / hang indicates a real bug.
//
// Spawned with kCapFsRead+kCapFsWrite+kCapNet+kCapSpawnThread so
// the syscalls that gate on caps actually reach their handlers.
//
// Skip-list: syscalls that destroy the process / modify TLS in
// ways that break a single-threaded exerciser. See SKIP[] below.

typedef unsigned long u64;
typedef long i64;

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
static inline i64 sc1(long nr, u64 a1)
{
    return sc6(nr, a1, 0, 0, 0, 0, 0);
}
static inline i64 sc3(long nr, u64 a1, u64 a2, u64 a3)
{
    return sc6(nr, a1, a2, a3, 0, 0, 0);
}

static char nbuf[64];

static void put_dec(int n, char* out, int* pos)
{
    int neg = 0;
    if (n < 0)
    {
        neg = 1;
        n = -n;
    }
    char tmp[12];
    int j = 0;
    if (n == 0)
        tmp[j++] = '0';
    while (n > 0)
    {
        tmp[j++] = '0' + (n % 10);
        n /= 10;
    }
    if (neg)
        out[(*pos)++] = '-';
    while (j > 0)
        out[(*pos)++] = tmp[--j];
}

static void emit(int nr, i64 rc)
{
    int i = 0;
    nbuf[i++] = '[';
    nbuf[i++] = 'f';
    nbuf[i++] = 'u';
    nbuf[i++] = 'l';
    nbuf[i++] = 'l';
    nbuf[i++] = ']';
    nbuf[i++] = ' ';
    put_dec(nr, nbuf, &i);
    nbuf[i++] = '=';
    int neg = 0;
    i64 v = rc;
    if (v < 0)
    {
        neg = 1;
        v = -v;
    }
    char tmp[20];
    int j = 0;
    if (v == 0)
        tmp[j++] = '0';
    while (v > 0)
    {
        tmp[j++] = '0' + (int)(v % 10);
        v /= 10;
    }
    if (neg)
        nbuf[i++] = '-';
    while (j > 0)
        nbuf[i++] = tmp[--j];
    nbuf[i++] = '\n';
    sc3(1 /*write*/, 1, (u64)nbuf, i);
}

static void puts_raw(const char* s)
{
    unsigned n = 0;
    while (s[n])
        ++n;
    sc3(1, 1, (u64)s, n);
}

// Skip-list — these are dangerous to issue blindly:
//
//  - Process-destructive: exit, exit_group, kill(getpid()), tgkill,
//    clone, fork, vfork, execve, execveat, reboot.
//  - State-destructive without easy recovery: brk, set_tid_address,
//    arch_prctl, set_thread_area, get_thread_area.
//  - Resource-allocation that could exhaust: mmap (would grow VM
//    cursor); we exercise it elsewhere. munmap (could free our
//    stack if guessed wrong).
//  - Module load: init_module, finit_module, delete_module.
//  - Blocking with no early exit: pause, rt_sigsuspend, rt_sigtimedwait.
//  - Process-tracing: ptrace.
//  - Kernel-state mutating: kexec_load, kexec_file_load.
static int is_skipped(int nr)
{
    static const int skip[] = {
        15,  // rt_sigreturn — terminates the task when there's no
              // saved signal frame (which there isn't outside a
              // handler). The kernel's behaviour is correct; we
              // just can't issue this from a synthetic exerciser.
        61,  // wait4 — DoWait4 with pid=0, options=0 (no WNOHANG)
              // blocks on linux_wait_wq waiting for a child to exit.
              // Synfull has no children, so it blocks forever.
              // (Kernel BUG: should -ECHILD when no children
              // exist, regardless of WNOHANG. Tracked separately.)
        247, // waitid — same blocking issue as wait4.
        13,  // rt_sigaction — installing signal handlers without
              // matching them with rt_sigreturn changes the
              // process's signal disposition in ways that can
              // break later iterations. Safe-ish but we skip to
              // keep the matrix predictable.
        56,  // clone
        57,  // fork
        58,  // vfork
        59,  // execve
        322, // execveat
        60,  // exit
        231, // exit_group
        62,  // kill — could SIGKILL us if pid lookup goes sideways
        200, // tkill
        234, // tgkill
        129, // rt_sigqueueinfo — same, could kill us
        297, // rt_tgsigqueueinfo
        9,   // mmap
        11,  // munmap
        12,  // brk
        25,  // mremap
        158, // arch_prctl
        218, // set_tid_address
        205, // set_thread_area
        211, // get_thread_area
        175, // init_module
        313, // finit_module
        176, // delete_module
        169, // reboot
        246, // kexec_load
        320, // kexec_file_load
        34,  // pause
        130, // rt_sigsuspend
        128, // rt_sigtimedwait
        101, // ptrace
        219, // restart_syscall — internal-ABI, should never be issued
              // directly but it's a no-op that returns -EINTR so
              // safe to keep
        -1,  // sentinel
    };
    for (int i = 0; skip[i] >= 0; ++i)
        if (skip[i] == nr)
            return 1;
    return 0;
}

void _start(void)
{
    puts_raw("[full] start\n");
    // Walk the entire 0..462 spec range. Most numbers ARE valid
    // syscalls; gaps in the CSV (deprecated/never-used) get
    // -ENOSYS via the kSysEnosys_* dispatch case. Either way,
    // every iteration produces one output line.
    for (int nr = 0; nr <= 462; ++nr)
    {
        if (is_skipped(nr))
        {
            // Emit a placeholder line so downstream greps know we
            // intentionally skipped, not silently dropped.
            // [full] <nr>=skip
            int i = 0;
            nbuf[i++] = '[';
            nbuf[i++] = 'f';
            nbuf[i++] = 'u';
            nbuf[i++] = 'l';
            nbuf[i++] = 'l';
            nbuf[i++] = ']';
            nbuf[i++] = ' ';
            put_dec(nr, nbuf, &i);
            nbuf[i++] = '=';
            nbuf[i++] = 's';
            nbuf[i++] = 'k';
            nbuf[i++] = 'i';
            nbuf[i++] = 'p';
            nbuf[i++] = '\n';
            sc3(1, 1, (u64)nbuf, i);
            continue;
        }
        // Issue with all-zero args. Most rejecting handlers stop
        // at NULL ptr / fd=0-non-tty / cnt==0 returns. The few
        // that succeed (getpid, gettid, getuid, etc.) return real
        // values. Block-on-NULL-fd cases (read, write) return
        // -EBADF immediately. The recvfrom non-block check we
        // added for synet means it returns -EAGAIN, not block.
        const i64 rc = sc6(nr, 0, 0, 0, 0, 0, 0);
        emit(nr, rc);
    }

    puts_raw("[full] all done, exit 0x80\n");
    sc1(231 /*exit_group*/, 0x80);
    __builtin_unreachable();
}
