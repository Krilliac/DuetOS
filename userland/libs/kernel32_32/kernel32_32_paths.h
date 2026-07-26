/*
 * userland/libs/kernel32_32/kernel32_32_paths.h
 *
 * Freestanding pure-logic core for the i386 kernel32 companion's file
 * surface: Win32 path narrowing and the SetFilePointer move-resolution
 * arithmetic. No syscalls, no globals, no allocation — so the hosted
 * unit test (tests/host/test_kernel32_32_paths.cpp) can include this
 * header directly and pin the behaviour without a kernel or a PE32
 * process, exactly as gdi32_region.h / kernel32_nls_format.h do for
 * their DLLs.
 *
 * Callers: kernel32_32_fs.c.
 */

#ifndef DUETOS_KERNEL32_32_PATHS_H
#define DUETOS_KERNEL32_32_PATHS_H

/* Win32 dwMoveMethod. */
#define DUET32_FILE_BEGIN 0u
#define DUET32_FILE_CURRENT 1u
#define DUET32_FILE_END 2u

/*
 * Narrow a Win32 path to the kernel's ASCII form.
 *
 * DuetOS has one logical volume, so the drive letter is vestigial:
 * "C:\Foo\bar" and "\Foo\bar" both resolve to "/Foo/bar". Same
 * transform the 64-bit CreateFileW does inline — factored out here
 * because four entry points need it.
 *
 * Returns the length written (excluding the NUL), or 0 for a null /
 * empty source or a capacity too small to hold anything.
 */
static inline int Duet32NormalizePathA(const char* src, char* dst, int dst_cap)
{
    int i = 0;
    int j = 0;
    if (src == 0 || dst == 0 || dst_cap < 1)
        return 0;
    /* Skip a leading drive-letter prefix if present. */
    if (src[0] != '\0' && src[1] == ':' && ((src[0] >= 'A' && src[0] <= 'Z') || (src[0] >= 'a' && src[0] <= 'z')))
        i = 2;
    while (j < dst_cap - 1 && src[i] != '\0')
    {
        const char c = src[i];
        dst[j++] = (c == '\\') ? '/' : c;
        ++i;
    }
    dst[j] = '\0';
    return j;
}

/*
 * UTF-16 → ASCII narrowing. Low byte only.
 *
 * GAP: no real UTF-16 → UTF-8 transcode — correct for ASCII /
 * Latin-1, lossy above U+00FF, so a PE32 opening a path with
 * non-Latin-1 characters gets a mangled name and an honest miss.
 * Revisit when the VFS grows a UTF-8 path contract.
 */
static inline int Duet32WideToAscii(const unsigned short* src, char* dst, int dst_cap)
{
    int i = 0;
    if (src == 0 || dst == 0 || dst_cap < 1)
        return 0;
    while (i < dst_cap - 1 && src[i] != 0)
    {
        dst[i] = (char)(src[i] & 0xFF);
        ++i;
    }
    dst[i] = '\0';
    return i;
}

/*
 * Resolve a Win32 SetFilePointer move into the (offset, whence) pair
 * to hand SYS_FILE_SEEK.
 *
 * This exists because the 32-bit syscall ABI ZERO-extends its
 * arguments (see kernel32_32_internal.h): a negative distance passed
 * straight through would arrive at the kernel as a huge positive u64
 * and land at EOF instead of before it. A backwards move is therefore
 * rewritten here into a forward FILE_BEGIN seek against an anchor the
 * caller has already queried — the current cursor for FILE_CURRENT,
 * the file size for FILE_END.
 *
 * Returns 1 and writes both out-params when the move resolves; returns
 * 0 when Win32 rejects it (a negative distance from FILE_BEGIN, or an
 * unknown whence). Every relative move is converted to FILE_BEGIN so
 * the returned cursor stays in the unambiguous signed-eax range. This
 * v0 therefore rejects targets above INT_MAX as well as targets before
 * byte zero.
 */
static inline int Duet32ResolveSeekTarget(long long anchor, int distance, unsigned whence,
                                          unsigned long long* out_offset, unsigned* out_whence)
{
    const unsigned long long max_seek_offset = 0x7FFFFFFFULL;
    long long target = (whence == DUET32_FILE_BEGIN ? 0 : anchor) + (long long)distance;
    if (out_offset == 0 || out_whence == 0)
        return 0;
    if (whence != DUET32_FILE_BEGIN && whence != DUET32_FILE_CURRENT && whence != DUET32_FILE_END)
        return 0;
    if (target < 0 || (unsigned long long)target > max_seek_offset)
        return 0;
    *out_offset = (unsigned long long)target;
    *out_whence = DUET32_FILE_BEGIN;
    return 1;
}

#endif /* DUETOS_KERNEL32_32_PATHS_H */
