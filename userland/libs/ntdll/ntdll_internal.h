/*
 * userland/libs/ntdll/ntdll_internal.h
 *
 * Shared declarations for the split ntdll.dll translation units.
 * Each ntdll_*.c includes this so the per-domain slices see the
 * common NT scalar typedefs / status macros. The split boundaries
 * were chosen so that no file-scope static's [def, last-use] span
 * is bisected — every helper / table stays in the slice that owns
 * it. Only the universal preamble (and any cross-TU exported
 * prototype appended below) needs to live here.
 *
 * The freestanding build (clang --target=x86_64-pc-windows-msvc,
 * -nostdlib) compiles every TU listed in
 * tools/build/build-ntdll-dll.sh and lld-link's them into one DLL.
 *
 * The scalar typedefs / status macros are *also* still spelled in
 * the common slice (ntdll.c); C permits an identical typedef /
 * object-like-macro redefinition, so the duplicates are harmless
 * and kept to minimise slice churn.
 */
#pragma once

typedef unsigned int DWORD;
typedef unsigned int UINT;
typedef int BOOL;
typedef void* HANDLE;
typedef unsigned long ULONG;
typedef unsigned long long SIZE_T;
typedef unsigned long NTSTATUS; /* 32-bit on MSVC LLP64 */
typedef unsigned short wchar_t16;

#define NTSTATUS_SUCCESS 0x00000000UL
#define NTSTATUS_NOT_IMPLEMENTED 0xC00000BBUL
#define NTSTATUS_NO_MEMORY 0xC0000017UL
#define NTSTATUS_INVALID_PARAMETER 0xC000000DUL

/* Core NT string struct shared by the rtl / reg / token slices. */
typedef struct
{
    unsigned short Length;
    unsigned short MaximumLength;
    wchar_t16* Buffer;
} UNICODE_STRING;

#define NTDLL_NORETURN __attribute__((noreturn))
#define DUET_USER_TRAP_UNREACHABLE()                                                                                   \
    do                                                                                                                 \
    {                                                                                                                  \
        __asm__ volatile("ud2" ::: "memory");                                                                          \
        __builtin_unreachable();                                                                                       \
    } while (0)

/* Exported entry points called from a different slice than the one
 * that defines them (all defined in the common TU, ntdll.c) —
 * declared here so the caller's TU sees a prototype. The
 * __declspec(dllexport) matches the definition's attribute. */
__declspec(dllexport) NTSTATUS NtQueryPerformanceCounter(long long* counter, long long* freq);
__declspec(dllexport) NTSTATUS NtQuerySystemTime(long long* SystemTime);
__declspec(dllexport) NTSTATUS NtWaitForSingleObject(HANDLE h, BOOL bAlertable, const long long* timeout100ns);

/* T6-02 SEH engine (defined in ntdll_dispatch.c). RtlRestoreContext
 * loads a Microsoft CONTEXT and resumes at its Rip — used by
 * NtContinue and the unwinder. */
__declspec(dllexport) void RtlRestoreContext(void* ContextRecord, void* ExceptionRecord);
