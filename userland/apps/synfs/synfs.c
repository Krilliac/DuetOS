// Linux-ABI FS-mutation exerciser. No libc — all inline asm.
// Sister of synxtest (which is sandboxed caps=<none>); synfs runs
// with kCapFsRead + kCapFsWrite so each mutation actually reaches
// the filesystem instead of bouncing off the sandbox cap gate.
//
// Each test prints `[fs] <name> rc=<rc>` so the boot log carries
// a per-syscall verdict. Path lifecycle is self-cleaning where it
// can be: a successful mkdir is followed by an rmdir; a creat is
// followed by an unlink. If something earlier in the test leaves a
// stale file, later tests log -EEXIST / -ENOENT but keep running.

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

// Build "[fs] <label> rc=<v>\n" in one buffer and write it atomically.
// Doing it as a single sc3(write) keeps the line uninterrupted by
// kernel logs that fire on a per-syscall basis. Building +
// reporting in TAG() then FMTI() like synxtest does is fine for
// human reading, but mid-line interleaving with kernel logs makes
// the rc invisible in greps. Synfs takes a strict "compute first,
// print whole line" stance.
static char fsbuf[128];
static void report_rc(const char* label, i64 v)
{
    int i = 0;
    fsbuf[i++] = '[';
    fsbuf[i++] = 'f';
    fsbuf[i++] = 's';
    fsbuf[i++] = ']';
    fsbuf[i++] = ' ';
    while (*label && i < (int)sizeof(fsbuf) - 16)
        fsbuf[i++] = *label++;
    fsbuf[i++] = ' ';
    fsbuf[i++] = 'r';
    fsbuf[i++] = 'c';
    fsbuf[i++] = '=';
    int neg = 0;
    if (v < 0)
    {
        neg = 1;
        v = -v;
    }
    if (v == 0)
        fsbuf[i++] = '0';
    else
    {
        char tmp[20];
        int j = 0;
        while (v > 0)
        {
            tmp[j++] = '0' + (int)(v % 10);
            v /= 10;
        }
        if (neg)
            fsbuf[i++] = '-';
        while (j > 0)
            fsbuf[i++] = tmp[--j];
    }
    fsbuf[i++] = '\n';
    sc3(1, 1, (u64)fsbuf, i);
}

void _start(void)
{
    TAG("[fs] start\n");

    // === access() ===
    report_rc("access(HELLO.TXT,F_OK)", sc2(21, (u64) "HELLO.TXT", 0));
    report_rc("access(HELLO.TXT,R_OK)", sc2(21, (u64) "HELLO.TXT", 4));
    report_rc("access(HELLO.TXT,W_OK)", sc2(21, (u64) "HELLO.TXT", 2));
    report_rc("access(NOPE,F_OK)", sc2(21, (u64) "NOPE.QQQ", 0));

    // === statfs / fstatfs ===
    {
        char sfsbuf[120] = {0};
        report_rc("statfs(HELLO.TXT)", sc2(137, (u64) "HELLO.TXT", (u64)sfsbuf));
    }
    {
        i64 fd = sc3(2, (u64) "HELLO.TXT", 0, 0);
        if (fd >= 0)
        {
            char sfsbuf[120] = {0};
            report_rc("fstatfs(HELLO.TXT)", sc2(138, fd, (u64)sfsbuf));
            sc1(3, fd);
        }
    }

    // === mkdir / rmdir round-trip ===
    report_rc("mkdir(SYNFSDIR)", sc2(83, (u64) "SYNFSDIR", 0755));
    report_rc("mkdir(SYNFSDIR,again)", sc2(83, (u64) "SYNFSDIR", 0755));
    report_rc("rmdir(SYNFSDIR)", sc1(84, (u64) "SYNFSDIR"));
    report_rc("rmdir(SYNFSDIR,again)", sc1(84, (u64) "SYNFSDIR"));

    // === openat(O_CREAT) + ftruncate / fchmod / fchown / fsync / fdatasync + close ===
    {
        i64 fd = sc6(257, (u64)-100, (u64) "SYNFS.TMP", 0x41 /*O_WRONLY|O_CREAT*/, 0644, 0, 0);
        report_rc("openat(SYNFS.TMP,O_CREAT)", fd);
        if (fd >= 0)
        {
            report_rc("write(SYNFS.TMP,11)", sc3(1, fd, (u64) "synfs-data\n", 11));
            report_rc("ftruncate(SYNFS.TMP,4)", sc2(77, fd, 4));
            report_rc("ftruncate(SYNFS.TMP,32)", sc2(77, fd, 32));
            report_rc("fchmod(SYNFS.TMP,0600)", sc2(91, fd, 0600));
            report_rc("fchown(SYNFS.TMP,0,0)", sc3(93, fd, 0, 0));
            report_rc("fsync(SYNFS.TMP)", sc1(74, fd));
            report_rc("fdatasync(SYNFS.TMP)", sc1(75, fd));
            sc1(3, fd);
        }
    }

    // === path-form metadata mutators ===
    report_rc("chmod(SYNFS.TMP,0644)", sc2(90, (u64) "SYNFS.TMP", 0644));
    report_rc("chown(SYNFS.TMP,0,0)", sc3(92, (u64) "SYNFS.TMP", 0, 0));
    report_rc("truncate(SYNFS.TMP,8)", sc2(76, (u64) "SYNFS.TMP", 8));

    // === utimensat ===
    {
        u64 times[4] = {0, 0x3fffffff /*UTIME_NOW*/, 0, 0x3fffffff};
        report_rc("utimensat(SYNFS.TMP)", sc6(280, (u64)-100, (u64) "SYNFS.TMP", (u64)times, 0, 0, 0));
    }

    // === rename / renameat2 ===
    report_rc("rename(SYNFS.TMP->SYNFS2.TMP)", sc2(82, (u64) "SYNFS.TMP", (u64) "SYNFS2.TMP"));
    report_rc("renameat2(SYNFS2->SYNFS3)",
              sc6(316, (u64)-100, (u64) "SYNFS2.TMP", (u64)-100, (u64) "SYNFS3.TMP", 0, 0));

    // === copy_file_range ===
    {
        i64 src = sc3(2, (u64) "SYNFS3.TMP", 0, 0);
        i64 dst = sc6(257, (u64)-100, (u64) "SYNFS.COPY", 0x41, 0644, 0, 0);
        report_rc("open(SYNFS3.TMP,r)", src);
        report_rc("open(SYNFS.COPY,w)", dst);
        if (src >= 0 && dst >= 0)
            report_rc("copy_file_range(32)", sc6(326, src, 0, dst, 0, 32, 0));
        if (src >= 0)
            sc1(3, src);
        if (dst >= 0)
            sc1(3, dst);
    }

    // === unlink ===
    report_rc("unlink(SYNFS3.TMP)", sc1(87, (u64) "SYNFS3.TMP"));
    report_rc("unlink(SYNFS.COPY)", sc1(87, (u64) "SYNFS.COPY"));
    report_rc("unlink(NOPE)", sc1(87, (u64) "NOPE.QQQ"));

    // === unlinkat with AT_REMOVEDIR ===
    sc2(83, (u64) "SYNFSDIR2", 0755);
    report_rc("unlinkat(SYNFSDIR2,AT_REMOVEDIR)", sc3(263, (u64)-100, (u64) "SYNFSDIR2", 0x200));

    // === sync / syncfs ===
    report_rc("sync()", sc1(162, 0));
    {
        i64 fd = sc3(2, (u64) "HELLO.TXT", 0, 0);
        if (fd >= 0)
        {
            report_rc("syncfs(HELLO.TXT)", sc1(306, fd));
            sc1(3, fd);
        }
    }

    // === mknod (device) — typically -EPERM ===
    report_rc("mknod(BLK)", sc3(133, (u64) "SYNFS.NOD", 0660 | 0x6000, 0));

    // === link / symlink — facade -ENOSYS in v0 ===
    report_rc("link(HELLO.TXT,HELLO.LNK)", sc2(86, (u64) "HELLO.TXT", (u64) "HELLO.LNK"));
    report_rc("symlink(HELLO.TXT,HELLO.SLK)", sc2(88, (u64) "HELLO.TXT", (u64) "HELLO.SLK"));

    TAG("[fs] all done, exit 0x60\n");
    sc1(231, 0x60);
    __builtin_unreachable();
}
