/*
 * userland/libs/kernel32_32/kernel32_32_fs.c
 *
 * File I/O for the i386 (PE32) kernel32 companion DLL. Companion to
 * userland/libs/kernel32/kernel32_io.c (the PE32+ x86_64 variant),
 * which is the reference for every syscall number and argument shape
 * used here:
 *
 *   SYS_FILE_OPEN             = 20  — rdi=ASCII path, rsi=path len
 *   SYS_FILE_READ             = 21  — rdi=handle, rsi=buf, rdx=count
 *   SYS_FILE_CLOSE            = 22  — rdi=handle
 *   SYS_FILE_SEEK             = 23  — rdi=handle, rsi=offset, rdx=whence
 *   SYS_FILE_FSTAT            = 24  — rdi=handle, rsi=u64* out size
 *   SYS_FILE_WRITE            = 43  — rdi=handle, rsi=buf, rdx=count
 *   SYS_FILE_CREATE           = 44  — rdi=path, rsi=path cap,
 *                                     rdx=initial bytes, r10=count
 *   SYS_FILE_QUERY_ATTRIBUTES = 151 — rdi=path, rsi=len, rdx=out buf,
 *                                     r10=buf cap
 *
 * Every one of these is cap-gated kernel-side (kCapFsRead on the read
 * family, kCapFsWrite on create/write). Nothing here re-implements a
 * filesystem or caches kernel state: the DLL translates the Win32 call
 * shape and hands the result back verbatim, so a PE32 guest gets
 * exactly the access the kernel granted its process — no more.
 *
 * Before this TU the 32-bit surface had no file I/O at all: WriteFile
 * accepted std handles only and CreateFile* / ReadFile did not exist.
 * A static-CRT PE32 that cleared startup (see kernel32_32.c) hit that
 * wall the first time it touched its own data files.
 */

#include "kernel32_32_internal.h"
#include "kernel32_32_paths.h"

/* Win32 constants used below. Declared locally — the DLL is
 * freestanding and does not include windows.h. */
#define DUET32_INVALID_HANDLE_VALUE ((HANDLE)(unsigned long)0xFFFFFFFFu)
#define DUET32_INVALID_SET_FILE_POINTER 0xFFFFFFFFu
#define DUET32_INVALID_FILE_SIZE 0xFFFFFFFFu
#define DUET32_INVALID_FILE_ATTRIBUTES 0xFFFFFFFFu

/* dwCreationDisposition */
#define DUET32_CREATE_NEW 1u
#define DUET32_CREATE_ALWAYS 2u
#define DUET32_OPEN_EXISTING 3u
#define DUET32_OPEN_ALWAYS 4u
#define DUET32_TRUNCATE_EXISTING 5u

/* dwMoveMethod comes from kernel32_32_paths.h — the resolution
 * arithmetic and the constants belong together. */

/* GetLastError codes we actually set. */
#define DUET32_ERROR_INVALID_PARAMETER 87u
#define DUET32_ERROR_INVALID_HANDLE 6u

/* SetLastError is defined (and exported) by kernel32_32.c and linked
 * into this same DLL — a plain declaration, not a dllimport. Declared
 * here rather than pulled through a header so the internal header
 * stays plumbing-only. */
void __stdcall SetLastError(DWORD err);

/* ------------------------------------------------------------------
 * CreateFile
 * ------------------------------------------------------------------ */

/* Open the normalised path with SYS_FILE_OPEN. Returns an opaque,
 * generation-tagged Win32 file handle whose low tag is 0x100..0x10F
 * and whose non-zero generation occupies bits 12..30, or (HANDLE)-1.
 * The syscall's u64(-1) failure value arrives in eax as 0xFFFFFFFF,
 * which is already INVALID_HANDLE_VALUE, so failure is a pass-through. */
static HANDLE Duet32FileOpen(const char* path, int len)
{
    return (HANDLE)(unsigned long)(unsigned)duet_syscall2(20 /* SYS_FILE_OPEN */, (unsigned)(unsigned long)path,
                                                          (unsigned)len);
}

/* Create the file at `path` with zero initial bytes. `path_cap` is
 * the max string length the kernel will copy in (excluding the NUL),
 * i.e. the same strlen the open path passes. */
static HANDLE Duet32FileCreate(const char* path, int len)
{
    return (HANDLE)(unsigned long)(unsigned)duet_syscall4(44 /* SYS_FILE_CREATE */, (unsigned)(unsigned long)path,
                                                          (unsigned)len, 0u /* no initial bytes */, 0u);
}

/*
 * CreateFileA — the disposition is honoured against the two
 * primitives the kernel actually provides (SYS_FILE_OPEN and
 * SYS_FILE_CREATE):
 *
 *   CREATE_NEW        create; fails if the file exists (exact Win32).
 *   CREATE_ALWAYS     create; falls back to open when the name is
 *                     taken.
 *   OPEN_EXISTING     open (exact Win32).
 *   OPEN_ALWAYS       open, then create on miss (exact Win32).
 *   TRUNCATE_EXISTING open.
 *   anything else     open — Win32 rejects an out-of-range
 *                     disposition, but failing closed here would turn
 *                     a caller's sloppy constant into an unexplained
 *                     open failure.
 *
 * GAP: no truncation primitive — CREATE_ALWAYS and TRUNCATE_EXISTING
 * leave existing content in place instead of zeroing the file, so a
 * caller that rewrites a shorter payload sees the old tail. Revisit
 * when the kernel grows SYS_FILE_TRUNCATE / an O_TRUNC flag on
 * SYS_FILE_OPEN.
 *
 * dwDesiredAccess / dwShareMode / lpSecurityAttributes /
 * dwFlagsAndAttributes / hTemplateFile are not consulted: the kernel
 * decides access from the process's caps (kCapFsRead / kCapFsWrite)
 * at each read/write, which is the authority. Advisory share modes and
 * ACLs have no kernel-side backing to honour.
 */
__declspec(dllexport) HANDLE __stdcall CreateFileA(const char* lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode,
                                                   void* lpSecurityAttributes, DWORD dwCreationDisposition,
                                                   DWORD dwFlagsAndAttributes, HANDLE hTemplateFile)
{
    (void)dwDesiredAccess;
    (void)dwShareMode;
    (void)lpSecurityAttributes;
    (void)dwFlagsAndAttributes;
    (void)hTemplateFile;

    char path[256];
    const int len = Duet32NormalizePathA(lpFileName, path, (int)sizeof(path));
    if (len == 0)
    {
        SetLastError(DUET32_ERROR_INVALID_PARAMETER);
        return DUET32_INVALID_HANDLE_VALUE;
    }

    HANDLE h;
    switch (dwCreationDisposition)
    {
    case DUET32_CREATE_NEW:
        return Duet32FileCreate(path, len);

    case DUET32_CREATE_ALWAYS:
        h = Duet32FileCreate(path, len);
        if (Duet32IsFileHandle(h))
            return h;
        return Duet32FileOpen(path, len);

    case DUET32_OPEN_ALWAYS:
        h = Duet32FileOpen(path, len);
        if (Duet32IsFileHandle(h))
            return h;
        return Duet32FileCreate(path, len);

    case DUET32_OPEN_EXISTING:
    case DUET32_TRUNCATE_EXISTING:
        return Duet32FileOpen(path, len);

    default:
        SetLastError(DUET32_ERROR_INVALID_PARAMETER);
        return DUET32_INVALID_HANDLE_VALUE;
    }
}

__declspec(dllexport) HANDLE __stdcall CreateFileW(const wchar_t16* lpFileName, DWORD dwDesiredAccess,
                                                   DWORD dwShareMode, void* lpSecurityAttributes,
                                                   DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes,
                                                   HANDLE hTemplateFile)
{
    char ascii[256];
    if (Duet32WideToAscii(lpFileName, ascii, (int)sizeof(ascii)) == 0)
    {
        SetLastError(DUET32_ERROR_INVALID_PARAMETER);
        return DUET32_INVALID_HANDLE_VALUE;
    }
    return CreateFileA(ascii, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition,
                       dwFlagsAndAttributes, hTemplateFile);
}

/* ------------------------------------------------------------------
 * ReadFile
 * ------------------------------------------------------------------ */

/*
 * ReadFile — kernel file handles go to SYS_FILE_READ, which advances
 * the per-handle cursor and returns the byte count (0 at EOF).
 *
 * The std handles mirror the 64-bit contract: STDIN reports immediate
 * EOF (there is no keyboard-read syscall yet) and STDOUT / STDERR are
 * write-only, both reported as TRUE with *lpRead = 0 rather than a
 * failure — that is what a Win32 caller's EOF check expects.
 *
 * GAP: lpOverlapped is not honoured. The 64-bit path seeks to
 * OVERLAPPED.Offset and posts an IOCP completion; the 32-bit set has
 * no IOCP surface, so an overlapped read here would silently behave
 * synchronously at the current cursor. Rejecting it is the honest
 * answer until the PE32 IOCP slice lands.
 */
__declspec(dllexport) BOOL __stdcall ReadFile(HANDLE hFile, void* lpBuffer, DWORD nNumberOfBytesToRead, DWORD* lpRead,
                                              void* lpOverlapped)
{
    const unsigned h = (unsigned)(unsigned long)hFile;

    if (lpRead != (DWORD*)0)
        *lpRead = 0;

    /* Std handles — see contract note above. */
    if (h == 0xFFFFFFF6u || h == 0xFFFFFFF5u || h == 0xFFFFFFF4u)
        return 1;

    if (!Duet32IsFileHandle(hFile))
    {
        SetLastError(DUET32_ERROR_INVALID_HANDLE);
        return 0;
    }
    if (lpOverlapped != (void*)0)
    {
        SetLastError(DUET32_ERROR_INVALID_PARAMETER);
        return 0;
    }

    const int rv = duet_syscall3(21 /* SYS_FILE_READ */, h, (unsigned)(unsigned long)lpBuffer, nNumberOfBytesToRead);
    if (rv < 0)
        return 0;
    if (lpRead != (DWORD*)0)
        *lpRead = (DWORD)rv;
    return 1;
}

/* ------------------------------------------------------------------
 * Seek / size
 * ------------------------------------------------------------------ */

/* Raw seek. `offset` must be non-negative — see the ABI note in
 * kernel32_32_internal.h: a negative 32-bit argument reaches the
 * kernel zero-extended, not sign-extended. Returns the new cursor
 * position, or -1 on failure. */
static int Duet32FileSeek(unsigned h, unsigned offset, unsigned whence)
{
    return duet_syscall3(23 /* SYS_FILE_SEEK */, h, offset, whence);
}

/* Fetch the file size via SYS_FILE_FSTAT. The kernel writes a full
 * u64 into the caller's slot, so the high dword survives even though
 * the syscall's own arguments are 32-bit. Returns 1 on success. */
static int Duet32FileSize(unsigned h, unsigned long long* out)
{
    *out = 0;
    return duet_syscall2(24 /* SYS_FILE_FSTAT */, h, (unsigned)(unsigned long)out) == 0;
}

/*
 * SetFilePointer — resolves every move to a non-negative absolute
 * offset before issuing SYS_FILE_SEEK, because the 32-bit syscall ABI
 * zero-extends its arguments (kernel32_32_internal.h). Relative
 * FILE_CURRENT / FILE_END moves therefore query their live anchor,
 * apply the signed delta, reject a negative result, and seek FILE_BEGIN.
 *
 * GAP: offsets are limited to 0..INT_MAX. The i386 syscall wrapper
 * returns an `int`, so a successful cursor with bit 31 set is
 * indistinguishable from negative errno. lpDistanceToMoveHigh is
 * accepted only when it is NULL or points at 0 — a genuinely 64-bit
 * distance cannot be expressed through the i386 `int $0x80` argument
 * registers, so it fails with ERROR_INVALID_PARAMETER rather than
 * silently seeking somewhere else. The returned high dword is written
 * as 0 for the same reason: the kernel's new-cursor value comes back
 * in eax, truncated to 32 bits. Revisit alongside the multi-GB
 * bundled-data rung, which is what will first need it.
 */
__declspec(dllexport) DWORD __stdcall SetFilePointer(HANDLE hFile, int lDistanceToMove, int* lpDistanceToMoveHigh,
                                                     DWORD dwMoveMethod)
{
    if (!Duet32IsFileHandle(hFile))
    {
        SetLastError(DUET32_ERROR_INVALID_HANDLE);
        return DUET32_INVALID_SET_FILE_POINTER;
    }
    if (lpDistanceToMoveHigh != (int*)0 && *lpDistanceToMoveHigh != 0)
    {
        SetLastError(DUET32_ERROR_INVALID_PARAMETER);
        return DUET32_INVALID_SET_FILE_POINTER;
    }
    const unsigned h = (unsigned)(unsigned long)hFile;

    /* Every relative move needs a live anchor so it can be issued as
     * an absolute seek whose result is bounded below INT_MAX. */
    long long anchor = 0;
    if (dwMoveMethod == DUET32_FILE_CURRENT)
    {
        const int cur = Duet32FileSeek(h, 0u, DUET32_FILE_CURRENT);
        if (cur < 0)
            return DUET32_INVALID_SET_FILE_POINTER;
        anchor = (long long)(unsigned)cur;
    }
    else if (dwMoveMethod == DUET32_FILE_END)
    {
        unsigned long long size;
        if (!Duet32FileSize(h, &size))
            return DUET32_INVALID_SET_FILE_POINTER;
        if (size > 0xFFFFFFFFULL)
        {
            SetLastError(DUET32_ERROR_INVALID_PARAMETER);
            return DUET32_INVALID_SET_FILE_POINTER;
        }
        anchor = (long long)size;
    }

    unsigned long long target = 0;
    unsigned target_whence = 0;
    if (!Duet32ResolveSeekTarget(anchor, lDistanceToMove, dwMoveMethod, &target, &target_whence))
    {
        SetLastError(DUET32_ERROR_INVALID_PARAMETER);
        return DUET32_INVALID_SET_FILE_POINTER;
    }

    const int rv = Duet32FileSeek(h, (unsigned)target, target_whence);
    if (rv < 0)
        return DUET32_INVALID_SET_FILE_POINTER;
    if (lpDistanceToMoveHigh != (int*)0)
        *lpDistanceToMoveHigh = 0;
    return (DWORD)rv;
}

__declspec(dllexport) DWORD __stdcall GetFileSize(HANDLE hFile, DWORD* lpFileSizeHigh)
{
    unsigned long long size;
    if (!Duet32IsFileHandle(hFile) || !Duet32FileSize((unsigned)(unsigned long)hFile, &size))
    {
        SetLastError(DUET32_ERROR_INVALID_HANDLE);
        return DUET32_INVALID_FILE_SIZE;
    }
    if (lpFileSizeHigh != (DWORD*)0)
        *lpFileSizeHigh = (DWORD)(size >> 32);
    return (DWORD)(size & 0xFFFFFFFFu);
}

/* GetFileSizeEx — LARGE_INTEGER out-parameter, so the full 64-bit
 * size the kernel reports survives unchanged. */
__declspec(dllexport) BOOL __stdcall GetFileSizeEx(HANDLE hFile, long long* lpFileSize)
{
    unsigned long long size;
    if (lpFileSize == (long long*)0 || !Duet32IsFileHandle(hFile))
    {
        SetLastError(DUET32_ERROR_INVALID_HANDLE);
        return 0;
    }
    if (!Duet32FileSize((unsigned)(unsigned long)hFile, &size))
        return 0;
    *lpFileSize = (long long)size;
    return 1;
}

/* ------------------------------------------------------------------
 * Path-based attribute query
 * ------------------------------------------------------------------ */

/*
 * GetFileAttributesA — SYS_FILE_QUERY_ATTRIBUTES fills a 56-byte
 * FILE_NETWORK_OPEN_INFORMATION; the attributes DWORD sits at offset
 * 48 (0x10 directory / 0x80 normal). Same shape the 64-bit kernel32
 * uses.
 *
 * GAP: the kernel routes this through fs::routing::StatPathForProcess,
 * which is FAT32-only in v0 — a query against a ramfs path returns
 * INVALID_FILE_ATTRIBUTES even though SYS_FILE_OPEN would succeed on
 * it. Identical to the 64-bit behaviour; fixed kernel-side when
 * StatPathForProcess grows a ramfs backend.
 */
__declspec(dllexport) DWORD __stdcall GetFileAttributesA(const char* lpFileName)
{
    char path[256];
    const int len = Duet32NormalizePathA(lpFileName, path, (int)sizeof(path));
    if (len == 0)
        return DUET32_INVALID_FILE_ATTRIBUTES;

    unsigned char info[56];
    for (unsigned i = 0; i < sizeof(info); ++i)
        info[i] = 0;
    const int status = duet_syscall4(151 /* SYS_FILE_QUERY_ATTRIBUTES */, (unsigned)(unsigned long)path, (unsigned)len,
                                     (unsigned)(unsigned long)info, (unsigned)sizeof(info));
    if (status != 0)
        return DUET32_INVALID_FILE_ATTRIBUTES;
    return (DWORD)info[48] | ((DWORD)info[49] << 8) | ((DWORD)info[50] << 16) | ((DWORD)info[51] << 24);
}

__declspec(dllexport) DWORD __stdcall GetFileAttributesW(const wchar_t16* lpFileName)
{
    char ascii[256];
    if (Duet32WideToAscii(lpFileName, ascii, (int)sizeof(ascii)) == 0)
        return DUET32_INVALID_FILE_ATTRIBUTES;
    return GetFileAttributesA(ascii);
}
