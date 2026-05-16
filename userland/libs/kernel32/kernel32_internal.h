/*
 * userland/libs/kernel32/kernel32_internal.h
 *
 * Shared declarations for the split kernel32.dll translation
 * units. Each kernel32_*.c includes this so the per-domain
 * slices see the common Win32 scalar typedefs / macros and the
 * handful of helpers that legitimately cross a TU boundary.
 *
 * Layout rationale and the provably-clean cut points live in the
 * commit that introduced the split. The freestanding build
 * (clang --target=x86_64-pc-windows-msvc, -nostdlib) compiles
 * every TU listed in tools/build/build-kernel32-dll.sh and
 * lld-link's them into one DLL.
 *
 * Scalar typedefs and object-like macros below are *also* still
 * spelled inline in the slice that originally owned them; C
 * permits an identical typedef / macro redefinition, so the
 * duplicates are harmless and kept to minimise slice churn.
 */
#pragma once

typedef unsigned int DWORD;
typedef unsigned int UINT;
typedef int BOOL;
typedef void* HANDLE;
typedef unsigned long ULONG;
typedef unsigned long long UINT_PTR; /* 64-bit on x64 windows-msvc; DWORD is 32 */
typedef long long ll_;
typedef unsigned long long ULONGLONG;
typedef long LONG;
typedef long long LONG64;
typedef unsigned short WCHAR_t;
typedef unsigned long long SIZE_T;
typedef unsigned int PROT;
typedef unsigned short wchar_t16; /* Win32 wchar_t is UTF-16 */

#define WIN32_NORETURN __attribute__((noreturn))
#define DUET_USER_TRAP_UNREACHABLE()                                                                                   \
    do                                                                                                                 \
    {                                                                                                                  \
        __asm__ volatile("ud2" ::: "memory");                                                                          \
        __builtin_unreachable();                                                                                       \
    } while (0)

#define NO_BUILTIN_LSTR __attribute__((no_builtin("strlen", "strcmp", "strcpy")))

#define DUETOS_COMPAT_BIT_IGNORE_DEBUGGER (1ull << 0)
#define DUETOS_COMPAT_BIT_IGNORE_ETW (1ull << 1)
#define DUETOS_COMPAT_BIT_FAKE_OK_STACK_GUARANTEE (1ull << 2)
#define DUETOS_COMPAT_BIT_APPLIED (1ull << 3)
/* Top bit marks the cache primed. Reserved high so the kernel
 * never sets it on its own. Multiple threads can race the syscall
 * — every call returns the same answer, so the worst case is two
 * trips on first use. */
#define DUETOS_COMPAT_CACHE_PRIMED (1ull << 63)

/* Config macros consumed across a slice boundary (also still
 * spelled in their owning slice; identical redefinition is legal). */
#define DUETOS_ENV_MAX 16
#define DUETOS_ENV_NAME 32
#define DUETOS_ENV_VAL 96
#define STARTF_USESTDHANDLES 0x00000100

typedef DWORD (*ThreadStartFn)(void*);

/* Helpers that cross a slice boundary. Defined non-static in
 * kernel32.c (the common TU). */
unsigned long long duet_compat_query(void);
long long syscall_get_tid(void);
void syscall_yield(void);

/* Exported entry points called from a different slice than the one
 * that defines them — declared here so the caller's TU sees a
 * prototype (the definition stays in its domain slice). */
__declspec(dllexport) DWORD GetCurrentProcessId(void);
__declspec(dllexport) DWORD GetCurrentThreadId(void);
__declspec(dllexport) HANDLE GetCurrentProcess(void);
__declspec(dllexport) HANDLE GetCurrentThread(void);
__declspec(dllexport) void SetLastError(DWORD err);
__declspec(dllexport) void Sleep(DWORD ms);
__declspec(dllexport) ULONGLONG GetTickCount64(void);
__declspec(dllexport) DWORD ExpandEnvironmentStringsW(const wchar_t16* src, wchar_t16* dst, DWORD size);
__declspec(dllexport) HANDLE CreateThread(void* lpThreadAttributes, SIZE_T dwStackSize, ThreadStartFn lpStartAddress,
                                          void* lpParameter, DWORD dwCreationFlags, DWORD* lpThreadId);
