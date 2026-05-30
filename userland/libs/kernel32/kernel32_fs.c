#include "kernel32_internal.h"

/* ------------------------------------------------------------------
 * File system — Find*, Copy/Move/Delete, dir ops.
 * All report "not found" / ACCESS_DENIED to keep real programs
 * on their graceful-failure paths.
 * ------------------------------------------------------------------ */

/* SYS_DIR_OPEN  = 154,  rdi = const char* path. Returns handle on
 *                       success, -1 on miss / pool full.
 * SYS_DIR_NEXT  = 155,  rdi = HANDLE, rsi = struct
 *                       Win32DirEntryReport*. Returns 1 on success,
 *                       0 at end-of-iteration, -1 on bad handle.
 *
 * The Win32DirEntryReport struct is the kernel-side stable ABI:
 *   char name[64]; u32 attributes; u32 _pad; u64 size_bytes; u8 _r[16];
 * = 96 bytes total. The kernel32 thunks marshal this into the
 * caller's WIN32_FIND_DATA[A|W] (Win32 layout: WIN32_FIND_DATAW is
 * 592 bytes / WIN32_FIND_DATAA 320 bytes, starting with FILETIME * 3
 * + DWORD * 4 + name fields — see the struct + _Static_asserts below).
 *
 * FindFirstFile* + FindNextFile* both hand a 320-byte WIN32_FIND_DATA
 * to user code — we zero-fill the leading FILETIME / size DWORDs we
 * don't have data for, then fill cFileName from report.name. The
 * caller's `void*` is treated as opaque storage; we never read it.
 *
 * Path filter (e.g. "C:\\dir\\*.txt") is NOT honoured — we walk
 * every entry the kernel returns. Sub-GAP: glob filtering. The
 * Win32 enumeration habit is to walk every entry then match
 * cFileName client-side anyway, so most callers don't notice.
 *
 * Path translation: strip a trailing "\\*" / "\\*.*" wildcard, then
 * convert backslashes to forward slashes so the kernel's "/disk/<idx>"
 * routing recognises the path.
 */
struct Win32DirEntryReport_t
{
    char name[64];
    unsigned int attributes;
    unsigned int _pad;
    unsigned long long size_bytes;
    unsigned char _reserved[16];
};

/* WIN32_FIND_DATA shape — must match Microsoft's layout EXACTLY, or
 * a real PE (which reads <windows.h> field offsets) lands on the
 * wrong bytes. The FILETIME fields are TWO 4-byte DWORDs each
 * (`{DWORD dwLowDateTime; DWORD dwHighDateTime;}`), 4-byte aligned —
 * NOT an 8-byte-aligned `long long`. Using `long long` here inserted
 * 4 bytes of pad after `dwFileAttributes` to 8-align it, shifting
 * cFileName to offset 48 (Windows: 44) and the size DWORDs by 4. cmd
 * read cFileName at offset 44 → a malformed UTF-16 name → faulted in
 * its post-enumeration string handling. Keeping the FILETIMEs as
 * 4-byte-aligned DWORD pairs pins cFileName at offset 44 and
 * nFileSizeHigh/Low at 28/32, matching WIN32_FIND_DATAW byte-for-byte
 * (sizeof == 592). */
struct Win32FileTime_t
{
    DWORD dwLowDateTime;
    DWORD dwHighDateTime;
};

struct Win32FindDataW_t
{
    DWORD dwFileAttributes;
    struct Win32FileTime_t ftCreationTime;
    struct Win32FileTime_t ftLastAccessTime;
    struct Win32FileTime_t ftLastWriteTime;
    DWORD nFileSizeHigh;
    DWORD nFileSizeLow;
    DWORD dwReserved0;
    DWORD dwReserved1;
    wchar_t16 cFileName[260];
    wchar_t16 cAlternateFileName[14];
};

/* Lock the Win32 layout at compile time — a future field edit that
 * reintroduces alignment pad (the bug this replaced) fails the build
 * instead of silently breaking every PE that enumerates a directory.
 * Windows: sizeof(WIN32_FIND_DATAW)==592, cFileName@44. */
_Static_assert(sizeof(struct Win32FindDataW_t) == 592, "WIN32_FIND_DATAW must match Microsoft layout (592 bytes)");
_Static_assert(__builtin_offsetof(struct Win32FindDataW_t, cFileName) == 44,
               "WIN32_FIND_DATAW.cFileName must be at offset 44");
_Static_assert(__builtin_offsetof(struct Win32FindDataW_t, nFileSizeHigh) == 28,
               "WIN32_FIND_DATAW.nFileSizeHigh must be at offset 28");

struct Win32FindDataA_t
{
    DWORD dwFileAttributes;
    struct Win32FileTime_t ftCreationTime;
    struct Win32FileTime_t ftLastAccessTime;
    struct Win32FileTime_t ftLastWriteTime;
    DWORD nFileSizeHigh;
    DWORD nFileSizeLow;
    DWORD dwReserved0;
    DWORD dwReserved1;
    char cFileName[260];
    char cAlternateFileName[14];
};

_Static_assert(sizeof(struct Win32FindDataA_t) == 320, "WIN32_FIND_DATAA must match Microsoft layout (320 bytes)");
_Static_assert(__builtin_offsetof(struct Win32FindDataA_t, cFileName) == 44,
               "WIN32_FIND_DATAA.cFileName must be at offset 44");

static long long DirOpenSyscall(const char* path)
{
    long long rv;
    __asm__ volatile("int $0x80" : "=a"(rv) : "a"((long long)154), "D"((long long)path) : "memory");
    return rv;
}

static long long DirNextSyscall(long long handle, void* report)
{
    long long rv;
    __asm__ volatile("int $0x80" : "=a"(rv) : "a"((long long)155), "D"(handle), "S"((long long)report) : "memory");
    return rv;
}

/* True iff `s` contains '*' or '?' before NUL — i.e. a Win32
 * filename glob pattern as opposed to a literal leaf. */
static int LeafIsGlob(const char* s)
{
    while (*s)
    {
        if (*s == '*' || *s == '?')
            return 1;
        ++s;
    }
    return 0;
}

/* Translate a Win32-shaped path prefix into the kernel's
 * "/disk/N" form.
 *
 *   - "\\?\" extended-length prefix is stripped (any depth of
 *     these is collapsed to plain).
 *   - "<letter>:" drive prefix is converted to /disk/<idx> where
 *     idx = uppercase(letter) - 'C' (so C: -> /disk/0, D: -> 1,
 *     E: -> 2, ...). Drive letters before C ('A' / 'B' — the
 *     classic floppy slots on real Windows) map to /disk/0 too;
 *     v0 doesn't expose floppies but the path still has to land
 *     somewhere usable.
 *   - Pure-relative paths and bare-leading-'\\' paths pass
 *     through with the backslash-to-slash conversion only.
 *
 * Returns the number of bytes consumed from `in` (always advances
 * past the drive-prefix if one was present) and writes the
 * canonicalised prefix (or "") to `out`. The caller continues
 * appending the remainder. */
static unsigned long Win32PathPrefixA(const char* in, char* out, unsigned long out_cap, unsigned long* out_written)
{
    *out_written = 0;
    if (out_cap == 0)
        return 0;
    out[0] = '\0';

    unsigned long ci = 0;

    /* Strip any number of repeated "\\?\" / "//?/" extended-
     * length prefixes (case-insensitive, separator-agnostic). */
    for (;;)
    {
        const char a = in[ci];
        const char b = in[ci + 1];
        const char c = in[ci + 2];
        const char d = in[ci + 3];
        if ((a == '\\' || a == '/') && (b == '\\' || b == '/') && c == '?' && (d == '\\' || d == '/'))
            ci += 4;
        else
            break;
    }

    /* Drive-letter prefix? */
    char letter = in[ci];
    if (((letter >= 'A' && letter <= 'Z') || (letter >= 'a' && letter <= 'z')) && in[ci + 1] == ':')
    {
        char upper = (letter >= 'a' && letter <= 'z') ? (char)(letter - 'a' + 'A') : letter;
        int idx = (upper < 'C') ? 0 : (upper - 'C');
        /* "/disk/<idx>" — single-digit suffices for our sane cap. */
        const char* prefix = "/disk/";
        unsigned long pi = 0;
        while (prefix[pi] && pi + 1 < out_cap)
        {
            out[pi] = prefix[pi];
            ++pi;
        }
        if (pi + 1 < out_cap)
        {
            if (idx >= 10)
            {
                /* 2-digit fallback for theoretical ZZ disks. */
                out[pi++] = (char)('0' + (idx / 10));
            }
            if (pi + 1 < out_cap)
                out[pi++] = (char)('0' + (idx % 10));
        }
        out[pi] = '\0';
        *out_written = pi;
        ci += 2; /* past the ':' — the next char is the separator
                  * that introduces the rest of the path. */
    }
    return ci;
}

/* Normalize a Win32 path to the kernel's "/disk/N/..." form:
 *   - translate Win32 drive prefixes ("C:\\...", "\\?\C:\\..."),
 *   - translate '\\' to '/',
 *   - if the leaf component is a glob (contains '*' or '?'),
 *     strip it from `out` and copy it to `pattern_out` (capped).
 *
 * `pattern_out` may be NULL — caller doesn't care about the
 * pattern (no glob filtering). Cap at 63 bytes so the kernel's
 * path-copy buffer doesn't truncate the leaf. */
static void NormalizePathA(const char* in, char* out, unsigned long out_cap, char* pattern_out, unsigned long pat_cap)
{
    if (out_cap == 0)
        return;

    unsigned long prefix_len = 0;
    unsigned long consumed = Win32PathPrefixA(in, out, out_cap, &prefix_len);
    in += consumed;

    unsigned long ci = prefix_len;
    unsigned long last_sep = ci;
    int has_sep = (prefix_len > 0); /* "/disk/N" is itself a separator-bearing prefix. */
    while (in[0] != '\0' && ci + 1 < out_cap)
    {
        char c = (in[0] == '\\') ? '/' : in[0];
        out[ci] = c;
        if (c == '/')
        {
            last_sep = ci;
            has_sep = 1;
        }
        ++ci;
        ++in;
    }
    out[ci] = '\0';
    if (pattern_out && pat_cap > 0)
        pattern_out[0] = '\0';
    if (has_sep)
    {
        const char* tail = out + last_sep + 1;
        if (LeafIsGlob(tail))
        {
            if (pattern_out && pat_cap > 0)
            {
                unsigned long pi = 0;
                for (; tail[pi] != '\0' && pi + 1 < pat_cap; ++pi)
                    pattern_out[pi] = tail[pi];
                pattern_out[pi] = '\0';
            }
            out[last_sep] = '\0';
        }
    }
}

static void NormalizePathW(const wchar_t16* in, char* out, unsigned long out_cap, char* pattern_out,
                           unsigned long pat_cap)
{
    if (out_cap == 0)
        return;
    unsigned long ci = 0;
    while (in[ci] != 0 && ci + 1 < out_cap)
    {
        char c = in[ci] == L'\\' ? '/' : (char)(in[ci] & 0xFF);
        out[ci] = c;
        ++ci;
    }
    out[ci] = '\0';
    /* Reuse the A-variant glob extract by copying through. */
    char tmp[64];
    __builtin_memset(tmp, 0, sizeof(tmp));
    NormalizePathA(out, tmp, sizeof(tmp), pattern_out, pat_cap);
    __builtin_memcpy(out, tmp, sizeof(tmp));
}

/* Case-insensitive Win32 glob matcher. Honours '*' (match any
 * run, including empty) and '?' (match exactly one char).
 * Recursion is bounded by `*` count + pattern length; with the
 * 63-byte pattern cap from NormalizePath* this is safe.
 *
 * Empty pattern means "match anything" (no filter set). */
static int FindGlobLowerA(char c)
{
    if (c >= 'A' && c <= 'Z')
        return c + ('a' - 'A');
    return (int)(unsigned char)c;
}
static int FindGlobMatch(const char* pattern, const char* name)
{
    if (pattern == 0 || pattern[0] == '\0')
        return 1;
    while (*pattern)
    {
        if (*pattern == '*')
        {
            ++pattern;
            if (*pattern == '\0')
                return 1;
            while (*name)
            {
                if (FindGlobMatch(pattern, name))
                    return 1;
                ++name;
            }
            return 0;
        }
        if (*name == '\0')
            return 0;
        if (*pattern != '?' && FindGlobLowerA(*pattern) != FindGlobLowerA(*name))
            return 0;
        ++pattern;
        ++name;
    }
    return *name == '\0';
}

/* Per-handle pattern table — FindFirstFile installs a slot,
 * FindNextFile looks it up, FindClose retires it. 8 slots cover
 * a typical Win32 PE's nested enumerations (most PEs have one
 * outer + one inner enumerate at a time). */
struct FindHandleSlot
{
    long long handle;
    int in_use;
    char pattern[64];
};
static struct FindHandleSlot g_find_slots[8];

static void FindSlotInstall(long long h, const char* pattern)
{
    /* Reuse-or-allocate. A previous handle with the same number
     * (impossible in practice — kernel issues fresh handles) is
     * overwritten cleanly. */
    int free_idx = -1;
    for (int i = 0; i < (int)(sizeof(g_find_slots) / sizeof(g_find_slots[0])); ++i)
    {
        if (g_find_slots[i].in_use && g_find_slots[i].handle == h)
        {
            free_idx = i;
            break;
        }
        if (!g_find_slots[i].in_use && free_idx < 0)
            free_idx = i;
    }
    if (free_idx < 0)
        return; /* table full — fallback to no-filter */
    g_find_slots[free_idx].handle = h;
    g_find_slots[free_idx].in_use = 1;
    unsigned long pi = 0;
    if (pattern)
    {
        for (; pattern[pi] != '\0' && pi + 1 < sizeof(g_find_slots[free_idx].pattern); ++pi)
            g_find_slots[free_idx].pattern[pi] = pattern[pi];
    }
    g_find_slots[free_idx].pattern[pi] = '\0';
}

static const char* FindSlotPattern(long long h)
{
    for (int i = 0; i < (int)(sizeof(g_find_slots) / sizeof(g_find_slots[0])); ++i)
    {
        if (g_find_slots[i].in_use && g_find_slots[i].handle == h)
            return g_find_slots[i].pattern;
    }
    return ""; /* no slot = no filter */
}

static void FindSlotRelease(long long h)
{
    for (int i = 0; i < (int)(sizeof(g_find_slots) / sizeof(g_find_slots[0])); ++i)
    {
        if (g_find_slots[i].in_use && g_find_slots[i].handle == h)
        {
            g_find_slots[i].in_use = 0;
            g_find_slots[i].handle = 0;
            g_find_slots[i].pattern[0] = '\0';
            return;
        }
    }
}

static void ZeroFileTime(struct Win32FileTime_t* ft)
{
    ft->dwLowDateTime = 0;
    ft->dwHighDateTime = 0;
}

static void FillFindDataA(const struct Win32DirEntryReport_t* r, struct Win32FindDataA_t* fd)
{
    fd->dwFileAttributes = r->attributes;
    ZeroFileTime(&fd->ftCreationTime);
    ZeroFileTime(&fd->ftLastAccessTime);
    ZeroFileTime(&fd->ftLastWriteTime);
    fd->nFileSizeLow = (DWORD)(r->size_bytes & 0xFFFFFFFFULL);
    fd->nFileSizeHigh = (DWORD)((r->size_bytes >> 32) & 0xFFFFFFFFULL);
    fd->dwReserved0 = 0;
    fd->dwReserved1 = 0;
    for (unsigned long i = 0; i < 260; ++i)
        fd->cFileName[i] = (i < 64) ? r->name[i] : 0;
    for (unsigned long i = 0; i < 14; ++i)
        fd->cAlternateFileName[i] = 0;
}

static void FillFindDataW(const struct Win32DirEntryReport_t* r, struct Win32FindDataW_t* fd)
{
    fd->dwFileAttributes = r->attributes;
    ZeroFileTime(&fd->ftCreationTime);
    ZeroFileTime(&fd->ftLastAccessTime);
    ZeroFileTime(&fd->ftLastWriteTime);
    fd->nFileSizeLow = (DWORD)(r->size_bytes & 0xFFFFFFFFULL);
    fd->nFileSizeHigh = (DWORD)((r->size_bytes >> 32) & 0xFFFFFFFFULL);
    fd->dwReserved0 = 0;
    fd->dwReserved1 = 0;
    for (unsigned long i = 0; i < 260; ++i)
        fd->cFileName[i] = (i < 64) ? (wchar_t16)(unsigned char)r->name[i] : 0;
    for (unsigned long i = 0; i < 14; ++i)
        fd->cAlternateFileName[i] = 0;
}

/* Walk past kernel-returned entries until one matches `pattern` or
 * the iteration ends. Empty pattern means "no filter". Returns the
 * raw DirNextSyscall return code (1=hit, 0=end, <0=error) for the
 * first matching entry. */
static long long FindWalkUntilMatch(long long h, const char* pattern, struct Win32DirEntryReport_t* r)
{
    for (;;)
    {
        long long rc = DirNextSyscall(h, r);
        if (rc != 1)
            return rc;
        if (FindGlobMatch(pattern, r->name))
            return 1;
    }
}

__declspec(dllexport) HANDLE FindFirstFileA(const char* path, void* find_data)
{
    if (path == (const char*)0 || find_data == (void*)0)
        return (HANDLE)(long long)-1;
    char kpath[64];
    char pattern[64];
    for (unsigned long i = 0; i < sizeof(kpath); ++i)
        kpath[i] = 0;
    NormalizePathA(path, kpath, sizeof(kpath), pattern, sizeof(pattern));
    long long h = DirOpenSyscall(kpath);
    if (h < 0)
        return (HANDLE)(long long)-1;
    struct Win32DirEntryReport_t r;
    long long rc = FindWalkUntilMatch(h, pattern, &r);
    if (rc != 1)
        return (HANDLE)(long long)-1;
    FillFindDataA(&r, (struct Win32FindDataA_t*)find_data);
    FindSlotInstall(h, pattern);
    return (HANDLE)h;
}

__declspec(dllexport) HANDLE FindFirstFileW(const wchar_t16* path, void* find_data)
{
    if (path == (const WCHAR_t*)0 || find_data == (void*)0)
        return (HANDLE)(long long)-1;
    char kpath[64];
    char pattern[64];
    for (unsigned long i = 0; i < sizeof(kpath); ++i)
        kpath[i] = 0;
    NormalizePathW(path, kpath, sizeof(kpath), pattern, sizeof(pattern));
    long long h = DirOpenSyscall(kpath);
    if (h < 0)
        return (HANDLE)(long long)-1;
    struct Win32DirEntryReport_t r;
    long long rc = FindWalkUntilMatch(h, pattern, &r);
    if (rc != 1)
        return (HANDLE)(long long)-1;
    FillFindDataW(&r, (struct Win32FindDataW_t*)find_data);
    FindSlotInstall(h, pattern);
    return (HANDLE)h;
}

__declspec(dllexport) BOOL FindNextFileA(HANDLE h, void* find_data)
{
    if (find_data == (void*)0)
        return 0;
    struct Win32DirEntryReport_t r;
    long long rc = FindWalkUntilMatch((long long)h, FindSlotPattern((long long)h), &r);
    if (rc != 1)
        return 0;
    FillFindDataA(&r, (struct Win32FindDataA_t*)find_data);
    return 1;
}

__declspec(dllexport) BOOL FindNextFileW(HANDLE h, void* find_data)
{
    if (find_data == (void*)0)
        return 0;
    struct Win32DirEntryReport_t r;
    long long rc = FindWalkUntilMatch((long long)h, FindSlotPattern((long long)h), &r);
    if (rc != 1)
        return 0;
    FillFindDataW(&r, (struct Win32FindDataW_t*)find_data);
    return 1;
}

/* FindClose — calls SYS_FILE_CLOSE (= 9), which already routes the
 * kWin32DirBase range to the directory snapshot teardown. Releases
 * the per-handle pattern slot regardless of the kernel return. */
__declspec(dllexport) BOOL FindClose(HANDLE h)
{
    long long discard;
    __asm__ volatile("int $0x80" : "=a"(discard) : "a"((long long)9), "D"((long long)h) : "memory");
    FindSlotRelease((long long)h);
    return 1;
}

/* CreateProcessA / CreateProcessW — subprocess spawn via the new
 * SYS_PROCESS_SPAWN (= 158). v0 ignores most CreateProcess
 * parameters; only the application path is honoured (via
 * lpApplicationName, or extracted from the first token of
 * lpCommandLine if lpApplicationName is NULL).
 *
 * Path translation: forward slashes pass through verbatim. The
 * kernel-side helper accepts only "/disk/<idx>/<rest>" paths;
 * Windows-native "C:\\..." paths need Windows→Unix translation
 * which is its own slice.
 *
 * On success, fills lpProcessInformation->hProcess /
 * dwProcessId / hThread / dwThreadId. hThread is collapsed to 0
 * (no separate Win32 thread handle for the new process's primary
 * thread; callers that need it can NtOpenThread the tid).
 */
struct ProcessInformation_t
{
    HANDLE hProcess;
    HANDLE hThread;
    DWORD dwProcessId;
    DWORD dwThreadId;
};

/* STARTUPINFO layout: Win32's STARTUPINFOA/W is 104 bytes on x64.
 * Field order is shared between A and W (only lpDesktop / lpTitle
 * point at different string types). We decode dwFlags + the three
 * std handles to drive STARTF_USESTDHANDLES inheritance.
 *
 * Offsets (from the SDK):
 *   +0   DWORD cb              ; sizeof(STARTUPINFO)
 *   +8   LPSTR lpReserved      ; (8 bytes)
 *   +16  LPSTR lpDesktop       ; (8 bytes)
 *   +24  LPSTR lpTitle         ; (8 bytes)
 *   +32  DWORD dwX
 *   +36  DWORD dwY
 *   +40  DWORD dwXSize
 *   +44  DWORD dwYSize
 *   +48  DWORD dwXCountChars
 *   +52  DWORD dwYCountChars
 *   +56  DWORD dwFillAttribute
 *   +60  DWORD dwFlags
 *   +64  WORD  wShowWindow
 *   +66  WORD  cbReserved2
 *   +72  LPBYTE lpReserved2
 *   +80  HANDLE hStdInput
 *   +88  HANDLE hStdOutput
 *   +96  HANDLE hStdError
 */
#define STARTF_USESTDHANDLES 0x00000100
#define STARTUPINFO_FLAGS_OFFSET 60
#define STARTUPINFO_STDIN_OFFSET 80
#define STARTUPINFO_STDOUT_OFFSET 88
#define STARTUPINFO_STDERR_OFFSET 96
#define STARTUPINFO_SIZE 104

/* GetStartupInfoW / GetStartupInfoA — fill the caller's STARTUPINFO.
 *
 * Load-bearing for wWinMain PEs: the MSVC CRT startup reads
 * cbReserved2 (+66) / lpReserved2 (+72) to rebuild inherited file
 * handles, walking lpReserved2 as a packed handle array of length
 * cbReserved2. If this were a NO-OP the struct is uninitialised
 * stack garbage, so the CRT iterates a garbage-length loop over a
 * garbage pointer — corrupting state into an intermittent, ASLR-
 * dependent crash at varying RIPs (observed: charmap.exe writing to
 * NULL at a function prologue, ~1 boot in 6). Zero-filling forces
 * cbReserved2 = 0 (CRT skips the inherited-handle walk — the correct
 * "launched normally" state) and dwFlags = 0 (no STARTF_USESTDHANDLES,
 * so the CRT uses default std handles). cb is set to the struct size.
 * A and W share the binary layout (only lpDesktop/lpTitle point at
 * different string types, left NULL here), so A defers to W.
 */
__declspec(dllexport) void GetStartupInfoW(void* lpStartupInfo)
{
    if (lpStartupInfo == (void*)0)
        return;
    unsigned char* p = (unsigned char*)lpStartupInfo;
    for (int i = 0; i < STARTUPINFO_SIZE; ++i)
        p[i] = 0;
    *(unsigned int*)p = (unsigned int)STARTUPINFO_SIZE; /* cb */
}

__declspec(dllexport) void GetStartupInfoA(void* lpStartupInfo)
{
    GetStartupInfoW(lpStartupInfo);
}

struct ProcessSpawnStdio_t
{
    unsigned long long stdin_handle;
    unsigned long long stdout_handle;
    unsigned long long stderr_handle;
};

static void win32_extract_stdio_bundle(const void* lpStartupInfo, BOOL bInheritHandles, struct ProcessSpawnStdio_t* out,
                                       int* have_bundle)
{
    *have_bundle = 0;
    out->stdin_handle = 0;
    out->stdout_handle = 0;
    out->stderr_handle = 0;
    if (lpStartupInfo == (const void*)0)
        return;
    if (!bInheritHandles)
        return;
    const unsigned char* base = (const unsigned char*)lpStartupInfo;
    DWORD flags;
    __builtin_memcpy(&flags, base + STARTUPINFO_FLAGS_OFFSET, sizeof(flags));
    if ((flags & STARTF_USESTDHANDLES) == 0)
        return;
    HANDLE h_in, h_out, h_err;
    __builtin_memcpy(&h_in, base + STARTUPINFO_STDIN_OFFSET, sizeof(h_in));
    __builtin_memcpy(&h_out, base + STARTUPINFO_STDOUT_OFFSET, sizeof(h_out));
    __builtin_memcpy(&h_err, base + STARTUPINFO_STDERR_OFFSET, sizeof(h_err));
    out->stdin_handle = (unsigned long long)(UINT_PTR)h_in;
    out->stdout_handle = (unsigned long long)(UINT_PTR)h_out;
    out->stderr_handle = (unsigned long long)(UINT_PTR)h_err;
    *have_bundle = 1;
}

__declspec(dllexport) BOOL CreateProcessA(const char* lpApplicationName, char* lpCommandLine, void* lpProcessAttributes,
                                          void* lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags,
                                          void* lpEnvironment, const char* lpCurrentDirectory, void* lpStartupInfo,
                                          void* lpProcessInformation)
{
    (void)lpProcessAttributes;
    (void)lpThreadAttributes;
    (void)dwCreationFlags;
    (void)lpEnvironment;
    (void)lpCurrentDirectory;
    const char* path = lpApplicationName;
    if (path == (const char*)0)
        path = lpCommandLine; // first arg of cmdline ≈ executable
    if (path == (const char*)0)
        return 0;

    struct ProcessSpawnStdio_t bundle;
    int have_bundle = 0;
    win32_extract_stdio_bundle(lpStartupInfo, bInheritHandles, &bundle, &have_bundle);

    long long pid;
    if (have_bundle)
    {
        __asm__ volatile("int $0x80"
                         : "=a"(pid)
                         : "a"((long long)190), /* SYS_PROCESS_SPAWN_EX */
                           "D"((long long)path), "S"((long long)0), "d"((long long)&bundle)
                         : "memory");
    }
    else
    {
        __asm__ volatile("int $0x80"
                         : "=a"(pid)
                         : "a"((long long)158), /* SYS_PROCESS_SPAWN */
                           "D"((long long)path), "S"((long long)0)
                         : "memory");
    }
    if (pid < 0)
        return 0;
    if (lpProcessInformation != (void*)0)
    {
        struct ProcessInformation_t* pi = (struct ProcessInformation_t*)lpProcessInformation;
        pi->hProcess = (HANDLE)(long long)pid;
        pi->hThread = (HANDLE)0;
        pi->dwProcessId = (DWORD)pid;
        pi->dwThreadId = (DWORD)pid; // single-thread process; tid == pid
    }
    return 1;
}

__declspec(dllexport) BOOL CreateProcessW(const wchar_t16* lpApplicationName, wchar_t16* lpCommandLine,
                                          void* lpProcessAttributes, void* lpThreadAttributes, BOOL bInheritHandles,
                                          DWORD dwCreationFlags, void* lpEnvironment,
                                          const wchar_t16* lpCurrentDirectory, void* lpStartupInfo,
                                          void* lpProcessInformation)
{
    (void)lpCurrentDirectory;
    /* Strip wide → ASCII (low byte). 128-byte cap matches the
     * kernel-side path buffer. */
    char path[128];
    for (unsigned i = 0; i < sizeof(path); ++i)
        path[i] = 0;
    const wchar_t16* src = lpApplicationName;
    if (src == (const WCHAR_t*)0)
        src = lpCommandLine;
    if (src == (const WCHAR_t*)0)
        return 0;
    unsigned i = 0;
    while (i + 1 < sizeof(path) && src[i] != 0)
    {
        path[i] = (char)(src[i] & 0xFF);
        ++i;
    }
    path[i] = '\0';
    return CreateProcessA(path, (char*)0, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags,
                          lpEnvironment, (const char*)0, lpStartupInfo, lpProcessInformation);
}

__declspec(dllexport) BOOL CopyFileA(const char* src, const char* dst, BOOL fail_if_exists)
{
    (void)src;
    (void)dst;
    (void)fail_if_exists;
    return 0;
}

__declspec(dllexport) BOOL CopyFileW(const wchar_t16* src, const wchar_t16* dst, BOOL fail_if_exists)
{
    (void)src;
    (void)dst;
    (void)fail_if_exists;
    return 0;
}

__declspec(dllexport) BOOL DeleteFileA(const char* path)
{
    if (path == (const char*)0)
        return 0;
    /* Run through the same Win32 path translator the Find* /
     * CreateProcess paths use so a "C:\\..." path resolves
     * through the kernel's "/disk/N" routing. NormalizePathA
     * with no glob-pattern out parameter is a pure translator. */
    char kpath[256];
    for (unsigned long i = 0; i < sizeof(kpath); ++i)
        kpath[i] = 0;
    NormalizePathA(path, kpath, sizeof(kpath), (char*)0, 0);
    int len = 0;
    while (kpath[len] != '\0' && len < 255)
        ++len;
    long long status;
    __asm__ volatile("int $0x80"
                     : "=a"(status)
                     : "a"((long long)143), /* SYS_FILE_UNLINK */
                       "D"((long long)kpath), "S"((long long)len)
                     : "memory");
    return status == 0 ? 1 : 0;
}

__declspec(dllexport) BOOL DeleteFileW(const wchar_t16* path)
{
    if (path == (const WCHAR_t*)0)
        return 0;
    char ascii[256];
    int i = 0;
    while (i < 255 && path[i] != 0)
    {
        ascii[i] = (char)(path[i] & 0xFF);
        ++i;
    }
    ascii[i] = '\0';
    return DeleteFileA(ascii);
}

__declspec(dllexport) BOOL MoveFileA(const char* src, const char* dst)
{
    if (src == (const char*)0 || dst == (const char*)0)
        return 0;
    char ksrc[256];
    char kdst[256];
    for (unsigned long i = 0; i < sizeof(ksrc); ++i)
        ksrc[i] = 0;
    for (unsigned long i = 0; i < sizeof(kdst); ++i)
        kdst[i] = 0;
    NormalizePathA(src, ksrc, sizeof(ksrc), (char*)0, 0);
    NormalizePathA(dst, kdst, sizeof(kdst), (char*)0, 0);
    int slen = 0;
    while (ksrc[slen] != '\0' && slen < 255)
        ++slen;
    int dlen = 0;
    while (kdst[dlen] != '\0' && dlen < 255)
        ++dlen;
    long long status;
    register long long r10 __asm__("r10") = (long long)dlen;
    __asm__ volatile("int $0x80"
                     : "=a"(status)
                     : "a"((long long)144), /* SYS_FILE_RENAME */
                       "D"((long long)ksrc), "S"((long long)slen), "d"((long long)kdst), "r"(r10)
                     : "memory");
    return status == 0 ? 1 : 0;
}

__declspec(dllexport) BOOL MoveFileW(const wchar_t16* src, const wchar_t16* dst)
{
    if (src == (const WCHAR_t*)0 || dst == (const WCHAR_t*)0)
        return 0;
    char ascii_src[256];
    char ascii_dst[256];
    int i = 0;
    while (i < 255 && src[i] != 0)
    {
        ascii_src[i] = (char)(src[i] & 0xFF);
        ++i;
    }
    ascii_src[i] = '\0';
    int j = 0;
    while (j < 255 && dst[j] != 0)
    {
        ascii_dst[j] = (char)(dst[j] & 0xFF);
        ++j;
    }
    ascii_dst[j] = '\0';
    return MoveFileA(ascii_src, ascii_dst);
}

__declspec(dllexport) DWORD GetFileAttributesA(const char* path)
{
    if (path == (const char*)0)
        return 0xFFFFFFFFu;
    char kpath[256];
    for (unsigned long i = 0; i < sizeof(kpath); ++i)
        kpath[i] = 0;
    NormalizePathA(path, kpath, sizeof(kpath), (char*)0, 0);
    int len = 0;
    while (kpath[len] != '\0' && len < 255)
        ++len;
    if (len == 0)
        return 0xFFFFFFFFu;
    /* SYS_FILE_QUERY_ATTRIBUTES = 151. Out buffer is the
     * FILE_NETWORK_OPEN_INFORMATION layout — 56 bytes; we only
     * read the FileAttributes DWORD at offset 48. */
    unsigned char info[56];
    for (unsigned long i = 0; i < sizeof(info); ++i)
        info[i] = 0;
    long long status;
    register long long r10 __asm__("r10") = (long long)sizeof(info);
    __asm__ volatile("int $0x80"
                     : "=a"(status)
                     : "a"((long long)151), "D"((long long)kpath), "S"((long long)len), "d"((long long)info), "r"(r10)
                     : "memory");
    if (status != 0)
        return 0xFFFFFFFFu; /* not found / no read permission */
    return *(unsigned*)(info + 48);
}

__declspec(dllexport) DWORD GetFileAttributesW(const wchar_t16* path)
{
    if (path == (const WCHAR_t*)0)
        return 0xFFFFFFFFu;
    char ascii[256];
    int i = 0;
    while (i < 255 && path[i] != 0)
    {
        ascii[i] = (char)(path[i] & 0xFF);
        ++i;
    }
    ascii[i] = '\0';
    return GetFileAttributesA(ascii);
}

/* SetFileAttributes — v0 has no writable FS backend; pretend
 * success (TRUE). Callers that care check GetFileAttributes
 * afterward and see the attributes unchanged — they proceed
 * on the assumption we lost the write; same observable as
 * "read-only FS". The reg-fattr smoke test in hello_winapi
 * pins this at TRUE. */
__declspec(dllexport) BOOL SetFileAttributesA(const char* path, DWORD attrs)
{
    (void)path;
    (void)attrs;
    return 1;
}

__declspec(dllexport) BOOL SetFileAttributesW(const wchar_t16* path, DWORD attrs)
{
    (void)path;
    (void)attrs;
    return 1;
}

/* LockFile / UnlockFile / *Ex — return TRUE without taking a real
 * lock. v0 has a single-process workload model and a single-writer
 * fat32 layer; no two callers are racing for the same range, so a
 * stub success is the correct answer (and matches what NTFS+
 * Windows used to do for advisory locks back when it was a single-
 * user OS). When a real concurrency story arrives — multi-user
 * sandboxing, a sqlite-like workload that genuinely needs byte-
 * range locks — this grows a per-file range table. Until then a
 * Win32 caller that does
 *   LockFile(h, 0, 0, sz_lo, sz_hi);
 *   ... write ...
 *   UnlockFile(h, 0, 0, sz_lo, sz_hi);
 * proceeds cleanly instead of stalling on a STATUS_NOT_IMPLEMENTED
 * upstream of every write call.
 */
__declspec(dllexport) BOOL LockFile(HANDLE h, DWORD off_lo, DWORD off_hi, DWORD len_lo, DWORD len_hi)
{
    (void)h;
    (void)off_lo;
    (void)off_hi;
    (void)len_lo;
    (void)len_hi;
    return 1;
}

__declspec(dllexport) BOOL UnlockFile(HANDLE h, DWORD off_lo, DWORD off_hi, DWORD len_lo, DWORD len_hi)
{
    (void)h;
    (void)off_lo;
    (void)off_hi;
    (void)len_lo;
    (void)len_hi;
    return 1;
}

__declspec(dllexport) BOOL LockFileEx(HANDLE h, DWORD flags, DWORD reserved, DWORD len_lo, DWORD len_hi,
                                      void* lpOverlapped)
{
    (void)h;
    (void)flags;
    (void)reserved;
    (void)len_lo;
    (void)len_hi;
    (void)lpOverlapped;
    return 1;
}

__declspec(dllexport) BOOL UnlockFileEx(HANDLE h, DWORD reserved, DWORD len_lo, DWORD len_hi, void* lpOverlapped)
{
    (void)h;
    (void)reserved;
    (void)len_lo;
    (void)len_hi;
    (void)lpOverlapped;
    return 1;
}

__declspec(dllexport) BOOL CreateDirectoryA(const char* path, void* sec)
{
    (void)path;
    (void)sec;
    return 0;
}

__declspec(dllexport) BOOL CreateDirectoryW(const wchar_t16* path, void* sec)
{
    (void)path;
    (void)sec;
    return 0;
}

__declspec(dllexport) BOOL RemoveDirectoryA(const char* path)
{
    (void)path;
    return 0;
}

__declspec(dllexport) BOOL RemoveDirectoryW(const wchar_t16* path)
{
    (void)path;
    return 0;
}

__declspec(dllexport) BOOL FlushFileBuffers(HANDLE h)
{
    (void)h;
    return 1;
}

/* System-directory queries — all report L"X:\\" (4 chars incl
 * NUL, 3 chars excl NUL). Matches the flat-stub semantics
 * that hello_winapi's sysdir smoke test pins.
 *
 * Signatures:
 *   DWORD  GetTempPathW(DWORD size, LPWSTR buf);      size-first
 *   UINT   GetWindowsDirectoryW(LPWSTR buf, UINT sz); buffer-first
 *   UINT   GetSystemDirectoryW(LPWSTR buf, UINT sz);  buffer-first
 *
 * All return 3 on success (chars written excl NUL) or 4 if
 * the buffer is too small (chars required incl NUL). */

static DWORD write_xcolon_backslash_w(wchar_t16* out, DWORD cap)
{
    if (!out || cap < 4)
        return 4; /* required incl NUL */
    out[0] = 'X';
    out[1] = ':';
    out[2] = '\\';
    out[3] = 0;
    return 3; /* chars excl NUL */
}

static DWORD write_xcolon_backslash_a(char* out, DWORD cap)
{
    if (!out || cap < 4)
        return 4;
    out[0] = 'X';
    out[1] = ':';
    out[2] = '\\';
    out[3] = 0;
    return 3;
}

__declspec(dllexport) DWORD GetTempPathA(DWORD cb, char* out)
{
    return write_xcolon_backslash_a(out, cb);
}

__declspec(dllexport) DWORD GetTempPathW(DWORD cb, wchar_t16* out)
{
    return write_xcolon_backslash_w(out, cb);
}

__declspec(dllexport) UINT GetWindowsDirectoryA(char* out, UINT cb)
{
    return write_xcolon_backslash_a(out, cb);
}

__declspec(dllexport) UINT GetWindowsDirectoryW(wchar_t16* out, UINT cb)
{
    return write_xcolon_backslash_w(out, cb);
}

__declspec(dllexport) UINT GetSystemDirectoryA(char* out, UINT cb)
{
    return write_xcolon_backslash_a(out, cb);
}

__declspec(dllexport) UINT GetSystemDirectoryW(wchar_t16* out, UINT cb)
{
    return write_xcolon_backslash_w(out, cb);
}

__declspec(dllexport) UINT GetSystemWindowsDirectoryW(wchar_t16* out, UINT cb)
{
    return write_xcolon_backslash_w(out, cb);
}

/* GetTempFileNameA / GetTempFileNameW — synthesise a unique
 * "<dir>\<prefix>NNNN.tmp" path. Win32 contract:
 *   - Combine dir + prefix + 4-hex-digit unique-id + ".TMP".
 *   - If `unique == 0`, the impl picks the id (and creates the
 *     file). v0 doesn't actually create the file (the FS layer
 *     above us is FAT32 + ramfs; SYS_FILE_CREATE on a temp dir
 *     isn't a v0 happy path). We just return the constructed
 *     name and the chosen id, leaving file creation to the
 *     caller's CreateFileW path.
 *   - Returns the chosen id (non-zero on success).
 *   - On caller buffer overflow, returns 0.
 *
 * The id rotation is process-local — incrementing static; that
 * matches Win32's implementation enough that consecutive calls
 * produce distinct names. */
static UINT g_temp_unique = 0xA001;

__declspec(dllexport) UINT GetTempFileNameA(const char* dir, const char* prefix, UINT unique, char* out)
{
    if (out == (char*)0)
        return 0;
    UINT id = unique != 0 ? unique : (g_temp_unique++ & 0xFFFF);
    /* Worst case: dir(MAX_PATH-14) + prefix(3) + 4 hex + ".TMP" + NUL.
     * The Win32 spec caps dir + prefix at MAX_PATH-14 chars; we don't
     * enforce the limit beyond a buffer-overflow guard below. */
    int o = 0;
    /* Copy dir. */
    if (dir != (const char*)0)
    {
        while (o < 250 && dir[o] != 0)
        {
            out[o] = dir[o];
            ++o;
        }
    }
    /* Ensure trailing backslash. */
    if (o == 0 || out[o - 1] != '\\')
    {
        if (o >= 250)
            return 0;
        out[o++] = '\\';
    }
    /* Copy prefix (≤ 3 chars). */
    if (prefix != (const char*)0)
    {
        for (int p = 0; p < 3 && prefix[p] != 0; ++p)
        {
            if (o >= 250)
                return 0;
            out[o++] = prefix[p];
        }
    }
    /* 4-hex unique-id. */
    static const char hex[] = "0123456789ABCDEF";
    if (o + 4 > 250)
        return 0;
    out[o++] = hex[(id >> 12) & 0xF];
    out[o++] = hex[(id >> 8) & 0xF];
    out[o++] = hex[(id >> 4) & 0xF];
    out[o++] = hex[id & 0xF];
    /* ".tmp" suffix + NUL. */
    if (o + 5 > 250)
        return 0;
    out[o++] = '.';
    out[o++] = 't';
    out[o++] = 'm';
    out[o++] = 'p';
    out[o] = 0;
    return id;
}

__declspec(dllexport) UINT GetTempFileNameW(const wchar_t16* dir, const wchar_t16* prefix, UINT unique, wchar_t16* out)
{
    if (out == (wchar_t16*)0)
        return 0;
    char abuf[260];
    char aprefix[8];
    char adir[260];
    int n = 0;
    if (dir != (const wchar_t16*)0)
    {
        while (n < 255 && dir[n] != 0)
        {
            adir[n] = (char)(dir[n] & 0xFF);
            ++n;
        }
    }
    adir[n] = 0;
    n = 0;
    if (prefix != (const wchar_t16*)0)
    {
        while (n < 7 && prefix[n] != 0)
        {
            aprefix[n] = (char)(prefix[n] & 0xFF);
            ++n;
        }
    }
    aprefix[n] = 0;
    UINT id = GetTempFileNameA(adir, aprefix, unique, abuf);
    if (id == 0)
    {
        out[0] = 0;
        return 0;
    }
    int i = 0;
    while (i < 259 && abuf[i] != 0)
    {
        out[i] = (wchar_t16)(unsigned char)abuf[i];
        ++i;
    }
    out[i] = 0;
    return id;
}

__declspec(dllexport) DWORD GetCurrentDirectoryA(DWORD cb, char* out)
{
    /* "X:\" sentinel — see GetCurrentDirectoryW for rationale. */
    static const char dir[] = "X:\\";
    DWORD want = sizeof(dir);
    if (!out || cb < want)
        return want;
    for (DWORD i = 0; i < want; ++i)
        out[i] = dir[i];
    return want - 1;
}

__declspec(dllexport) DWORD GetCurrentDirectoryW(DWORD cb, wchar_t16* out)
{
    /* "X:\" matches the v0 sentinel returned by the kernel
     * thunk-table fallback for GetModuleFileNameW and is what
     * userland/apps/hello_winapi probes for. The drive letter is
     * deliberately not "C:" because DuetOS doesn't have a real
     * drive-letter namespace; "X:" makes it visually distinct
     * from a Windows-shaped path and signals "v0 placeholder". */
    static const char dir[] = "X:\\";
    DWORD want = (DWORD)sizeof(dir);
    if (!out || cb < want)
        return want;
    for (DWORD i = 0; i < want; ++i)
        out[i] = (wchar_t16)(unsigned char)dir[i];
    return want - 1;
}

__declspec(dllexport) BOOL SetCurrentDirectoryA(const char* path)
{
    (void)path;
    return 1;
}

__declspec(dllexport) BOOL SetCurrentDirectoryW(const wchar_t16* path)
{
    (void)path;
    return 1;
}

/* GetFullPathNameA — A variant of GetFullPathNameW. Same logic
 * (prepend "C:" to drive-less paths), one byte per char. */
__declspec(dllexport) DWORD GetFullPathNameA(const char* lpFileName, DWORD nBufferLength, char* lpBuffer,
                                             char** lpFilePart)
{
    (void)lpFilePart;
    if (lpFileName == (const char*)0 || lpBuffer == (char*)0)
        return 0;
    int srclen = 0;
    while (lpFileName[srclen] != 0)
        ++srclen;
    int add_drive = (srclen > 0 && (lpFileName[0] == '\\' || lpFileName[0] == '/')) ? 2 : 0;
    DWORD needed = (DWORD)(srclen + 1 + add_drive);
    if (needed > nBufferLength)
        return needed;
    int j = 0;
    if (add_drive)
    {
        lpBuffer[j++] = 'C';
        lpBuffer[j++] = ':';
    }
    for (int i = 0; i < srclen; ++i)
        lpBuffer[j++] = lpFileName[i];
    lpBuffer[j] = 0;
    return (DWORD)j;
}

/* GetDiskFreeSpaceA / GetDiskFreeSpaceW — pre-2GB style disk space
 * query. Returns canned ramfs-friendly geometry: 4-sector clusters,
 * 512-byte sectors, 256k free / 512k total clusters (= ~512 MiB
 * free / ~1 GiB total). Win32 callers comparing TotalNumberOfClusters
 * non-zero or doing their own multiplication land on a sane result. */
__declspec(dllexport) BOOL GetDiskFreeSpaceA(const char* lpRootPathName, DWORD* lpSectorsPerCluster,
                                             DWORD* lpBytesPerSector, DWORD* lpNumberOfFreeClusters,
                                             DWORD* lpTotalNumberOfClusters)
{
    (void)lpRootPathName;
    if (lpSectorsPerCluster)
        *lpSectorsPerCluster = 4;
    if (lpBytesPerSector)
        *lpBytesPerSector = 512;
    if (lpNumberOfFreeClusters)
        *lpNumberOfFreeClusters = 262144;
    if (lpTotalNumberOfClusters)
        *lpTotalNumberOfClusters = 524288;
    return 1;
}

__declspec(dllexport) BOOL GetDiskFreeSpaceW(const wchar_t16* lpRootPathName, DWORD* lpSectorsPerCluster,
                                             DWORD* lpBytesPerSector, DWORD* lpNumberOfFreeClusters,
                                             DWORD* lpTotalNumberOfClusters)
{
    (void)lpRootPathName;
    return GetDiskFreeSpaceA((const char*)0, lpSectorsPerCluster, lpBytesPerSector, lpNumberOfFreeClusters,
                             lpTotalNumberOfClusters);
}

/* GetVolumeInformationA/W — name "DuetOS", serial 0xDEADBEEF,
 * max component 255, FAT32-equivalent flags (CASE_PRESERVED |
 * UNICODE_ON_DISK), filesystem name "FAT32" (matches the underlying
 * `Fat32Format` primitive). All output pointers are optional in
 * Win32; respect that. */
#define FS_CASE_SENSITIVE_SEARCH 0x00000001
#define FS_CASE_IS_PRESERVED 0x00000002
#define FS_UNICODE_STORED_ON_DISK 0x00000004
#define FS_VOL_IS_COMPRESSED 0x00008000

__declspec(dllexport) BOOL GetVolumeInformationA(const char* lpRootPathName, char* lpVolumeNameBuffer,
                                                 DWORD nVolumeNameSize, DWORD* lpVolumeSerialNumber,
                                                 DWORD* lpMaximumComponentLength, DWORD* lpFileSystemFlags,
                                                 char* lpFileSystemNameBuffer, DWORD nFileSystemNameSize)
{
    (void)lpRootPathName;
    static const char vol_name[] = "DuetOS";
    static const char fs_name[] = "FAT32";
    if (lpVolumeNameBuffer && nVolumeNameSize > 0)
    {
        DWORD i = 0;
        for (; i < nVolumeNameSize - 1 && vol_name[i] != 0; ++i)
            lpVolumeNameBuffer[i] = vol_name[i];
        lpVolumeNameBuffer[i] = 0;
    }
    if (lpVolumeSerialNumber)
        *lpVolumeSerialNumber = 0xDEADBEEFu;
    if (lpMaximumComponentLength)
        *lpMaximumComponentLength = 255;
    if (lpFileSystemFlags)
        *lpFileSystemFlags = FS_CASE_IS_PRESERVED | FS_UNICODE_STORED_ON_DISK;
    if (lpFileSystemNameBuffer && nFileSystemNameSize > 0)
    {
        DWORD i = 0;
        for (; i < nFileSystemNameSize - 1 && fs_name[i] != 0; ++i)
            lpFileSystemNameBuffer[i] = fs_name[i];
        lpFileSystemNameBuffer[i] = 0;
    }
    return 1;
}

__declspec(dllexport) BOOL GetVolumeInformationW(const wchar_t16* lpRootPathName, wchar_t16* lpVolumeNameBuffer,
                                                 DWORD nVolumeNameSize, DWORD* lpVolumeSerialNumber,
                                                 DWORD* lpMaximumComponentLength, DWORD* lpFileSystemFlags,
                                                 wchar_t16* lpFileSystemNameBuffer, DWORD nFileSystemNameSize)
{
    (void)lpRootPathName;
    static const char vol_name[] = "DuetOS";
    static const char fs_name[] = "FAT32";
    if (lpVolumeNameBuffer && nVolumeNameSize > 0)
    {
        DWORD i = 0;
        for (; i < nVolumeNameSize - 1 && vol_name[i] != 0; ++i)
            lpVolumeNameBuffer[i] = (wchar_t16)(unsigned char)vol_name[i];
        lpVolumeNameBuffer[i] = 0;
    }
    if (lpVolumeSerialNumber)
        *lpVolumeSerialNumber = 0xDEADBEEFu;
    if (lpMaximumComponentLength)
        *lpMaximumComponentLength = 255;
    if (lpFileSystemFlags)
        *lpFileSystemFlags = FS_CASE_IS_PRESERVED | FS_UNICODE_STORED_ON_DISK;
    if (lpFileSystemNameBuffer && nFileSystemNameSize > 0)
    {
        DWORD i = 0;
        for (; i < nFileSystemNameSize - 1 && fs_name[i] != 0; ++i)
            lpFileSystemNameBuffer[i] = (wchar_t16)(unsigned char)fs_name[i];
        lpFileSystemNameBuffer[i] = 0;
    }
    return 1;
}

/* Process32First/Next — report empty process list. The
 * existing flat stubs are registered under ntdll's NOT_IMPL
 * tier; for completeness let's add these so PE startup
 * snapshots don't error. */
__declspec(dllexport) HANDLE CreateToolhelp32Snapshot(DWORD flags, DWORD pid)
{
    (void)flags;
    (void)pid;
    /* Return a non-INVALID sentinel so callers Close it later
     * (CloseHandle on an unknown handle is already a no-op). */
    return (HANDLE)0x1001;
}

__declspec(dllexport) BOOL Process32FirstW(HANDLE h, void* entry)
{
    (void)h;
    (void)entry;
    return 0; /* Empty snapshot */
}

__declspec(dllexport) BOOL Process32NextW(HANDLE h, void* entry)
{
    (void)h;
    (void)entry;
    return 0;
}

__declspec(dllexport) BOOL Process32First(HANDLE h, void* entry)
{
    return Process32FirstW(h, entry);
}

__declspec(dllexport) BOOL Process32Next(HANDLE h, void* entry)
{
    return Process32NextW(h, entry);
}

/* OpenProcess is implemented further up — old "access denied" stub
 * removed in v19 favour of the pseudo-handle return. */

__declspec(dllexport) BOOL GenerateConsoleCtrlEvent(DWORD event, DWORD group)
{
    (void)event;
    (void)group;
    return 0;
}

/* GlobalAlloc / LocalAlloc family. Deprecated Win32 heap APIs
 * still used by old clipboard / OLE code. v0 routes both through
 * SYS_HEAP_ALLOC (=11) and SYS_HEAP_FREE (=12). Flags ignored;
 * every block behaves like GMEM_FIXED so Lock/Unlock are
 * pass-through. GMEM_ZEROINIT (0x0040) is honoured — zeros the
 * buffer before returning. */
#define GMEM_ZEROINIT 0x0040u

__declspec(dllexport) HANDLE GlobalAlloc(UINT flags, SIZE_T cb)
{
    long long rv;
    __asm__ volatile("int $0x80" : "=a"(rv) : "a"((long long)11), "D"((long long)cb) : "memory");
    if (rv != 0 && (flags & GMEM_ZEROINIT))
    {
        unsigned char* p = (unsigned char*)rv;
        for (SIZE_T i = 0; i < cb; ++i)
            p[i] = 0;
    }
    return (HANDLE)rv;
}

__declspec(dllexport) HANDLE GlobalReAlloc(HANDLE h, SIZE_T cb, UINT flags)
{
    (void)flags;
    long long rv;
    __asm__ volatile("int $0x80"
                     : "=a"(rv)
                     : "a"((long long)15), /* SYS_HEAP_REALLOC */
                       "D"((long long)(unsigned long long)h), "S"((long long)cb)
                     : "memory");
    return (HANDLE)rv;
}

__declspec(dllexport) HANDLE GlobalFree(HANDLE h)
{
    if (h == (HANDLE)0)
        return (HANDLE)0;
    long long discard;
    __asm__ volatile("int $0x80"
                     : "=a"(discard)
                     : "a"((long long)12), "D"((long long)(unsigned long long)h)
                     : "memory");
    return (HANDLE)0; /* GlobalFree returns NULL on success. */
}

__declspec(dllexport) void* GlobalLock(HANDLE h)
{
    /* GMEM_FIXED → handle == pointer. */
    return (void*)h;
}

__declspec(dllexport) BOOL GlobalUnlock(HANDLE h)
{
    (void)h;
    return 1;
}

__declspec(dllexport) SIZE_T GlobalSize(HANDLE h)
{
    long long rv;
    __asm__ volatile("int $0x80"
                     : "=a"(rv)
                     : "a"((long long)14), /* SYS_HEAP_SIZE */
                       "D"((long long)(unsigned long long)h)
                     : "memory");
    return (SIZE_T)rv;
}

__declspec(dllexport) UINT GlobalFlags(HANDLE h)
{
    (void)h;
    return 0;
}

/* Local* — same shape as Global*. */
__declspec(dllexport) HANDLE LocalAlloc(UINT flags, SIZE_T cb)
{
    return GlobalAlloc(flags, cb);
}

__declspec(dllexport) HANDLE LocalReAlloc(HANDLE h, SIZE_T cb, UINT flags)
{
    return GlobalReAlloc(h, cb, flags);
}

__declspec(dllexport) HANDLE LocalFree(HANDLE h)
{
    return GlobalFree(h);
}

__declspec(dllexport) void* LocalLock(HANDLE h)
{
    return GlobalLock(h);
}

__declspec(dllexport) BOOL LocalUnlock(HANDLE h)
{
    return GlobalUnlock(h);
}

__declspec(dllexport) SIZE_T LocalSize(HANDLE h)
{
    return GlobalSize(h);
}

__declspec(dllexport) UINT LocalFlags(HANDLE h)
{
    return GlobalFlags(h);
}

/* Affinity / CPU info — single-CPU; both masks are 1. */
__declspec(dllexport) BOOL GetProcessAffinityMask(HANDLE proc, unsigned long long* proc_mask,
                                                  unsigned long long* sys_mask)
{
    (void)proc;
    if (proc_mask)
        *proc_mask = 1;
    if (sys_mask)
        *sys_mask = 1;
    return 1;
}

__declspec(dllexport) BOOL SetProcessAffinityMask(HANDLE proc, unsigned long long mask)
{
    (void)proc;
    (void)mask;
    return 1;
}

__declspec(dllexport) unsigned long long SetThreadAffinityMask(HANDLE thread, unsigned long long mask)
{
    (void)thread;
    (void)mask;
    return 1;
}

__declspec(dllexport) DWORD GetActiveProcessorCount(unsigned short group)
{
    (void)group;
    return 1;
}

__declspec(dllexport) unsigned short GetActiveProcessorGroupCount(void)
{
    return 1;
}

/* SetThreadDescription / GetThreadDescription — Windows 10
 * thread-naming surface. Many modern apps (Edge, Chrome, .NET
 * runtimes) call these at thread spawn for diagnostic naming.
 * v0 stores the name in a process-local 16-slot table keyed by
 * the supplied thread handle (the low 32 bits — usually a TID).
 * Cross-thread reads work; cross-process reads do not (the
 * table is per-process). Returns S_OK on success. */
typedef long HRESULT; /* signed 32-bit; 0 = S_OK; high bit = failure. */
#define WIN32_THREAD_NAME_SLOTS 16
#define WIN32_THREAD_NAME_LEN 64

typedef struct Win32ThreadNameSlot
{
    int in_use;
    unsigned long long handle_key;
    wchar_t16 name[WIN32_THREAD_NAME_LEN];
} Win32ThreadNameSlot;

static Win32ThreadNameSlot g_thread_names[WIN32_THREAD_NAME_SLOTS];

static void win32_wname_copy(const wchar_t16* src, wchar_t16* dst, int cap)
{
    int i = 0;
    if (src)
    {
        for (; src[i] && i < cap - 1; ++i)
            dst[i] = src[i];
    }
    dst[i] = 0;
}

__declspec(dllexport) HRESULT SetThreadDescription(HANDLE thread, const wchar_t16* name)
{
    unsigned long long key = (unsigned long long)thread;
    /* GetCurrentThread pseudo-handle (-2) → caller's TID. */
    if (thread == (HANDLE)(long long)-2 || thread == (HANDLE)0)
        key = (unsigned long long)syscall_get_tid();
    int free_idx = -1;
    for (int i = 0; i < WIN32_THREAD_NAME_SLOTS; ++i)
    {
        if (g_thread_names[i].in_use && g_thread_names[i].handle_key == key)
        {
            win32_wname_copy(name, g_thread_names[i].name, WIN32_THREAD_NAME_LEN);
            return 0; /* S_OK */
        }
        if (!g_thread_names[i].in_use && free_idx < 0)
            free_idx = i;
    }
    if (free_idx < 0)
        return 0; /* Table full — no harm; pretend success. */
    g_thread_names[free_idx].in_use = 1;
    g_thread_names[free_idx].handle_key = key;
    win32_wname_copy(name, g_thread_names[free_idx].name, WIN32_THREAD_NAME_LEN);
    return 0;
}

/* GetThreadDescription — caller owns the returned buffer; Win32
 * uses LocalAlloc internally and the caller LocalFrees. v0
 * routes through SYS_HEAP_ALLOC (=11) for the same lifetime. */
__declspec(dllexport) HRESULT GetThreadDescription(HANDLE thread, wchar_t16** out_name)
{
    if (out_name == (wchar_t16**)0)
        return 0x80070057UL; /* E_INVALIDARG */
    *out_name = (wchar_t16*)0;
    unsigned long long key = (unsigned long long)thread;
    if (thread == (HANDLE)(long long)-2 || thread == (HANDLE)0)
        key = (unsigned long long)syscall_get_tid();
    const wchar_t16* found = (const wchar_t16*)0;
    for (int i = 0; i < WIN32_THREAD_NAME_SLOTS; ++i)
    {
        if (g_thread_names[i].in_use && g_thread_names[i].handle_key == key)
        {
            found = g_thread_names[i].name;
            break;
        }
    }
    /* Name length + NUL. Allocate via SYS_HEAP_ALLOC. */
    int len = 0;
    if (found)
    {
        while (found[len])
            ++len;
    }
    long long rv;
    long long bytes = (long long)((len + 1) * (long long)sizeof(wchar_t16));
    __asm__ volatile("int $0x80" : "=a"(rv) : "a"((long long)11), "D"(bytes) : "memory");
    if (rv == 0)
        return 0x8007000EUL; /* E_OUTOFMEMORY */
    wchar_t16* buf = (wchar_t16*)rv;
    for (int i = 0; i < len; ++i)
        buf[i] = found[i];
    buf[len] = 0;
    *out_name = buf;
    return 0;
}

/* GetSystemInfo / GetNativeSystemInfo — populate SYSTEM_INFO
 * (48 bytes). Apps query this for page size + processor count. */
__declspec(dllexport) void GetSystemInfo(void* info)
{
    if (!info)
        return;
    unsigned char* p = (unsigned char*)info;
    for (int i = 0; i < 48; ++i)
        p[i] = 0;
    *((unsigned short*)&p[0]) = 9; /* PROCESSOR_ARCHITECTURE_AMD64 */
    *((DWORD*)&p[4]) = 4096;
    *((unsigned long long*)&p[8]) = 0x10000ULL;
    *((unsigned long long*)&p[16]) = 0x7FFFFFFEFFFFULL;
    *((unsigned long long*)&p[24]) = 1;
    *((DWORD*)&p[32]) = 1;
    *((DWORD*)&p[36]) = 8664; /* PROCESSOR_AMD_X8664 */
    *((DWORD*)&p[40]) = 65536;
}

__declspec(dllexport) void GetNativeSystemInfo(void* info)
{
    GetSystemInfo(info);
}

/* Windows version reporting — claim Windows 10 build 19041
 * (matches the registry stub in advapi32). */
__declspec(dllexport) DWORD GetVersion(void)
{
    /* Layout: low 8 bits major (10), bits 8..15 minor (0),
     * high 16 bits build (19041) — but the high bit is set on
     * NT-based versions, so flip bit 31. */
    return 0x4A6100AAu;
}

__declspec(dllexport) BOOL GetVersionExA(void* info)
{
    if (!info)
        return 0;
    DWORD* p = (DWORD*)info;
    if (p[0] < 148)
        return 0;
    p[1] = 10;
    p[2] = 0;
    p[3] = 19041;
    p[4] = 2; /* VER_PLATFORM_WIN32_NT */
    /* szCSDVersion left untouched — matches the kernel32 thunk
       fast-path. Caller is expected to zero-init the struct. */
    return 1;
}

__declspec(dllexport) BOOL GetVersionExW(void* info)
{
    if (!info)
        return 0;
    DWORD* p = (DWORD*)info;
    if (p[0] < 276)
        return 0;
    p[1] = 10;
    p[2] = 0;
    p[3] = 19041;
    p[4] = 2;
    /* szCSDVersion left untouched — matches the kernel32 thunk
       fast-path. Caller is expected to zero-init the struct. */
    return 1;
}

__declspec(dllexport) BOOL VerifyVersionInfoW(void* info, DWORD type_mask, unsigned long long cond_mask)
{
    (void)info;
    (void)type_mask;
    (void)cond_mask;
    return 1;
}

/* CheckRemoteDebuggerPresent — always FALSE. */
__declspec(dllexport) BOOL CheckRemoteDebuggerPresent(HANDLE p, BOOL* present)
{
    (void)p;
    if (present != (BOOL*)0)
        *present = 0;
    return 1;
}

/* GetProcessId / GetThreadId — return the current process / thread
 * id regardless of the input handle. v0 doesn't track foreign-
 * process or foreign-thread identities, so the contract is "for any
 * handle that names this process, return GetCurrentProcessId(); for
 * any handle that names a thread of this process, return
 * GetCurrentThreadId()." That's the case the smoke tests exercise
 * (GetCurrentProcess() pseudo-handle = -1, GetCurrentThread() = -2).
 *
 * Fix history: the previous impl wired these to the wrong syscall
 * numbers — 5 (SYS_READ, path-based file read) and 6 (SYS_DROPCAPS).
 * Both clobber-checked their caller's caps and returned -1 on every
 * v0 PE, breaking [debug_smoke] GetProcessId == self / GetThreadId
 * == self. The correct paths are SYS_GETPROCID (= 8) for the pid
 * and SYS_GETPID (= 1) for the scheduler task id, mirroring
 * GetCurrentProcessId / GetCurrentThreadId. */
__declspec(dllexport) DWORD GetProcessId(HANDLE p)
{
    (void)p;
    long long rv;
    __asm__ volatile("int $0x80" : "=a"(rv) : "a"((long long)8) : "memory");
    return (DWORD)rv;
}

__declspec(dllexport) DWORD GetThreadId(HANDLE t)
{
    (void)t;
    long long rv;
    __asm__ volatile("int $0x80" : "=a"(rv) : "a"((long long)1) : "memory");
    return (DWORD)rv;
}

/* AddVectoredExceptionHandler / RemoveVectoredExceptionHandler —
 * Windows keeps the VEH chain in ntdll; kernel32 is a forwarder.
 * We can't emit a PE forwarder, and kernel32 doesn't import ntdll,
 * so resolve ntdll's Rtl{Add,Remove}VectoredExceptionHandler at
 * call time via the loader syscalls (SYS_DLL_BASE_BY_NAME = 172,
 * SYS_DLL_PROC_ADDRESS = 57) and tail through. Resolution is
 * cached after the first successful lookup. */
static void* k32_resolve_ntdll(const char* name, unsigned long name_len)
{
    static const char k_ntdll[] = "ntdll";
    long long base;
    __asm__ volatile("int $0x80"
                     : "=a"(base)
                     : "a"((long long)172), "D"((long long)(unsigned long long)k_ntdll), "S"((long long)5)
                     : "memory");
    if (base == 0)
        return (void*)0;
    long long fn;
    __asm__ volatile("int $0x80"
                     : "=a"(fn)
                     : "a"((long long)57), "D"(base), "S"((long long)(unsigned long long)name)
                     : "memory");
    (void)name_len;
    return (void*)(unsigned long long)fn;
}

typedef void*(__attribute__((ms_abi)) * k32_add_veh_t)(unsigned long, void*);
typedef unsigned long(__attribute__((ms_abi)) * k32_rm_veh_t)(void*);

__declspec(dllexport) void* AddVectoredExceptionHandler(unsigned long first, void* h)
{
    static k32_add_veh_t fn;
    if (fn == (k32_add_veh_t)0)
        fn = (k32_add_veh_t)k32_resolve_ntdll("RtlAddVectoredExceptionHandler", 30);
    if (fn == (k32_add_veh_t)0)
        return (void*)0;
    return fn(first, h);
}

__declspec(dllexport) unsigned long RemoveVectoredExceptionHandler(void* h)
{
    static k32_rm_veh_t fn;
    if (fn == (k32_rm_veh_t)0)
        fn = (k32_rm_veh_t)k32_resolve_ntdll("RtlRemoveVectoredExceptionHandler", 33);
    if (fn == (k32_rm_veh_t)0)
        return 0;
    return fn(h);
}

/* GetThreadPriorityBoost — TRUE, no boost. */
__declspec(dllexport) BOOL GetThreadPriorityBoost(HANDLE t, BOOL* disabled)
{
    (void)t;
    if (disabled != (BOOL*)0)
        *disabled = 0;
    return 1;
}

/* GetConsoleProcessList — 1 entry. */
__declspec(dllexport) DWORD GetConsoleProcessList(DWORD* pids, DWORD count)
{
    if (pids != (DWORD*)0 && count >= 1)
        pids[0] = GetProcessId((HANDLE)(long long)-1);
    return 1;
}

/* PathCanonicalizeW — collapse "..". */
__declspec(dllexport) BOOL PathCanonicalizeW(wchar_t16* dst, const wchar_t16* src)
{
    if (dst == (wchar_t16*)0 || src == (const WCHAR_t*)0)
        return 0;
    /* Simple v0: copy everything, then collapse "\\..\\X" → "\\X". */
    int j = 0;
    int i = 0;
    while (src[i] != 0)
        dst[j++] = src[i++];
    dst[j] = 0;
    /* One pass: search for "\\..\\". When found, back up to the prior '\\'. */
    int k = 0;
    while (k + 3 < j)
    {
        if (dst[k] == '\\' && dst[k + 1] == '.' && dst[k + 2] == '.' && dst[k + 3] == '\\')
        {
            int back = k;
            while (back > 0 && dst[back - 1] != '\\')
                --back;
            if (back > 0)
                --back; /* Skip the leading '\\' too. */
            int shift = (k + 3) - back;
            for (int m = back; m + shift <= j; ++m)
                dst[m] = dst[m + shift];
            j -= shift;
            k = back > 0 ? back - 1 : 0;
        }
        else
            ++k;
    }
    dst[j] = 0;
    return 1;
}

/* PathRenameExtensionW — replace extension. */
__declspec(dllexport) BOOL PathRenameExtensionW(wchar_t16* path, const wchar_t16* new_ext)
{
    if (path == (wchar_t16*)0 || new_ext == (const WCHAR_t*)0)
        return 0;
    int n = 0;
    while (path[n] != 0)
        ++n;
    int dot = -1;
    for (int i = n - 1; i >= 0; --i)
    {
        if (path[i] == '.')
        {
            dot = i;
            break;
        }
        if (path[i] == '\\' || path[i] == '/')
            break;
    }
    int trim = (dot >= 0) ? dot : n;
    int j = 0;
    while (new_ext[j] != 0)
    {
        path[trim + j] = new_ext[j];
        ++j;
    }
    path[trim + j] = 0;
    return 1;
}

/* GetMaximumProcessorCount — was missing while GetActiveProcessorCount
 * + GetTempFileNameW already live earlier in the file. */
__declspec(dllexport) DWORD GetMaximumProcessorCount(unsigned short group)
{
    (void)group;
    return 1;
}
