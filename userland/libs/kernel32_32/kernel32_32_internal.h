/*
 * userland/libs/kernel32_32/kernel32_32_internal.h
 *
 * Shared plumbing for the i386 (PE32) kernel32 companion DLL — the
 * Win32 scalar typedefs plus the kernel file-handle band predicate.
 * Included by every kernel32_32 TU; nothing here is exported.
 *
 * The `int $0x80` trampolines every `_32` DLL issues syscalls through
 * live in userland/libs/common/duet32_syscall.h, including the ABI
 * note on how the kernel remaps the i386 argument registers and why
 * negative arguments are NOT sign-extended on the way in.
 *
 * Freestanding: no libc, no kernel headers. The only contract with
 * the kernel is the syscall number + argument shape documented in
 * kernel/syscall/syscall.h.
 */

#ifndef DUETOS_KERNEL32_32_INTERNAL_H
#define DUETOS_KERNEL32_32_INTERNAL_H

#include "../common/duet32_syscall.h"

typedef unsigned int DWORD;
typedef unsigned int UINT;
typedef int BOOL;
typedef void* HANDLE;
typedef unsigned short wchar_t16;

#define WIN32_NORETURN __attribute__((noreturn))

/* Opaque kernel file handles use bits 0..11 as a low tag and bits
 * 12..30 as a non-zero, non-wrapping slot generation. The file tag is
 * Process::kWin32HandleBase + slot_idx, i.e. [0x100, 0x10F]. Bit 31
 * stays clear so the value is positive and lossless in both PE32 and
 * PE32+. SYS_FILE_{OPEN,CREATE} plant the handle and the other file
 * syscalls consume it. */
#define DUET32_FILE_HANDLE_TAG_MASK 0xFFFu
#define DUET32_FILE_HANDLE_TAG_MIN 0x100u
#define DUET32_FILE_HANDLE_TAG_MAX 0x110u /* exclusive */
#define DUET32_FILE_HANDLE_GENERATION_SHIFT 12u
#define DUET32_FILE_HANDLE_MAX_VALUE 0x7FFFFFFFu

static inline int Duet32IsFileHandle(HANDLE h)
{
    const unsigned raw = (unsigned)(unsigned long)h;
    const unsigned tag = raw & DUET32_FILE_HANDLE_TAG_MASK;
    const unsigned generation = raw >> DUET32_FILE_HANDLE_GENERATION_SHIFT;
    return raw <= DUET32_FILE_HANDLE_MAX_VALUE && generation != 0u && tag >= DUET32_FILE_HANDLE_TAG_MIN &&
           tag < DUET32_FILE_HANDLE_TAG_MAX;
}

/* Cross-TU exports. These are defined in kernel32_32.c and reused by
 * the sibling TUs (kernel32_32_misc.c builds its W spellings on top of
 * the A ones so the sentinel strings and the syscall numbers are
 * spelled exactly once). Declared rather than re-derived — two copies
 * of a sentinel is how the "X:\ vs C:\" divergence class starts. */
__declspec(dllexport) HANDLE __stdcall GetModuleHandleA(const char* lpModuleName);
__declspec(dllexport) HANDLE __stdcall GetModuleHandleW(const wchar_t16* lpModuleName);
__declspec(dllexport) DWORD __stdcall GetModuleFileNameA(HANDLE hModule, char* lpFilename, DWORD nSize);
__declspec(dllexport) HANDLE __stdcall LoadLibraryA(const char* lpLibFileName);
__declspec(dllexport) HANDLE __stdcall LoadLibraryW(const wchar_t16* lpLibFileName);
__declspec(dllexport) void __stdcall OutputDebugStringA(const char* lpOutputString);

#endif /* DUETOS_KERNEL32_32_INTERNAL_H */
