#include "ntdll_internal.h"

/* ------------------------------------------------------------------
 * NT misc sync + APC + event extras + token write surface
 * ------------------------------------------------------------------ */
__declspec(dllexport) NTSTATUS NtPulseEvent(HANDLE EventHandle, long* PreviousState)
{
    long long rv1, rv2;
    __asm__ volatile("int $0x80" : "=a"(rv1) : "a"((long long)31), "D"((long long)EventHandle) : "memory");
    __asm__ volatile("int $0x80" : "=a"(rv2) : "a"((long long)32), "D"((long long)EventHandle) : "memory");
    if (PreviousState != (long*)0)
        *PreviousState = 0;
    if (rv1 != 0 || rv2 != 0)
        return (NTSTATUS)0xC0000008;
    return NTSTATUS_SUCCESS;
}

__declspec(dllexport) NTSTATUS NtClearEvent(HANDLE EventHandle)
{
    long long rv;
    __asm__ volatile("int $0x80" : "=a"(rv) : "a"((long long)32), "D"((long long)EventHandle) : "memory");
    return rv == 0 ? NTSTATUS_SUCCESS : (NTSTATUS)0xC0000008;
}

__declspec(dllexport) NTSTATUS NtQueryEvent(HANDLE EventHandle, ULONG EventInformationClass, void* EventInformation,
                                            ULONG EventInformationLength, ULONG* ReturnLength)
{
    (void)EventHandle;
    (void)EventInformationClass;
    if (EventInformation == (void*)0 || EventInformationLength < 8)
        return NTSTATUS_INVALID_PARAMETER;
    unsigned char* out = (unsigned char*)EventInformation;
    for (unsigned i = 0; i < 8; ++i)
        out[i] = 0;
    if (ReturnLength != (ULONG*)0)
        *ReturnLength = 8;
    return NTSTATUS_SUCCESS;
}

__declspec(dllexport) NTSTATUS NtSignalAndWaitForSingleObject(HANDLE ObjectToSignal, HANDLE WaitableObject,
                                                              BOOL Alertable, void* Time)
{
    /* Best-effort: signal first object, then wait on second.
     * Atomicity not preserved (sub-GAP). */
    unsigned long long sig_handle = (unsigned long long)ObjectToSignal;
    long long sig_status = 0;
    if (sig_handle >= 0x200 && sig_handle < 0x208)
        __asm__ volatile("int $0x80"
                         : "=a"(sig_status)
                         : "a"((long long)27), "D"((long long)ObjectToSignal)
                         : "memory");
    else if (sig_handle >= 0x300 && sig_handle < 0x308)
        __asm__ volatile("int $0x80"
                         : "=a"(sig_status)
                         : "a"((long long)31), "D"((long long)ObjectToSignal)
                         : "memory");
    if (sig_status != 0)
        return (NTSTATUS)0xC0000008;
    return NtWaitForSingleObject(WaitableObject, Alertable, (const long long*)Time);
}

/* NtQueueApcThread / NtQueueApcThreadEx — route user-mode APCs
 * through the kernel-resident queue (SYS_QUEUE_USER_APC = 187).
 * The native Win32 contract: ApcRoutine is invoked as
 *   ApcRoutine(NormalContext, SystemArgument1, SystemArgument2)
 * when the target enters an alertable wait. The kernel queue
 * stores all three values verbatim (see Process::ApcSlot) so a
 * future drain path can replay the full three-arg call; today's
 * kernel32!win32_drain_apc_queue still calls the pfn with the
 * single-arg PAPCFUNC convention (NormalContext only) but that
 * is a userland-shim concern, not a kernel ABI gap.
 *
 * Returns STATUS_SUCCESS on success, STATUS_NOT_IMPLEMENTED
 * on cross-process / unknown-tid (kernel returns -1). The
 * thread handle is opaque; v0 takes the low 32 bits as the
 * target tid, the same convention kernel32!QueueUserAPC uses.
 */
__declspec(dllexport) NTSTATUS NtQueueApcThread(HANDLE ThreadHandle, void* ApcRoutine, void* NormalContext,
                                                void* SystemArgument1, void* SystemArgument2)
{
    if (ApcRoutine == (void*)0)
        return (NTSTATUS)0xC000000DL; /* STATUS_INVALID_PARAMETER */
    long long target_tid = (long long)(unsigned long long)ThreadHandle;
    register long long r10 __asm__("r10") = (long long)SystemArgument1;
    register long long r8 __asm__("r8") = (long long)SystemArgument2;
    long long rv;
    __asm__ volatile("int $0x80"
                     : "=a"(rv)
                     : "a"((long long)187), /* SYS_QUEUE_USER_APC */
                       "D"(target_tid), "S"((long long)ApcRoutine), "d"((long long)NormalContext), "r"(r10), "r"(r8)
                     : "memory");
    if (rv != 0)
        return (NTSTATUS)0xC0000002L; /* STATUS_NOT_IMPLEMENTED — caller falls back */
    return (NTSTATUS)0;
}

__declspec(dllexport) NTSTATUS NtQueueApcThreadEx(HANDLE ThreadHandle, HANDLE ReserveHandle, void* ApcRoutine,
                                                  void* NormalContext, void* SystemArgument1, void* SystemArgument2)
{
    (void)ReserveHandle;
    return NtQueueApcThread(ThreadHandle, ApcRoutine, NormalContext, SystemArgument1, SystemArgument2);
}

__declspec(dllexport) NTSTATUS NtAlertThread(HANDLE ThreadHandle)
{
    (void)ThreadHandle;
    return (NTSTATUS)0xC0000002;
}

__declspec(dllexport) NTSTATUS NtCallbackReturn(void* OutputBuffer, ULONG OutputLength, NTSTATUS Status)
{
    (void)OutputBuffer;
    (void)OutputLength;
    return Status;
}

__declspec(dllexport) NTSTATUS NtAdjustGroupsToken(HANDLE TokenHandle, BOOL ResetToDefault, void* NewState,
                                                   ULONG BufferLength, void* PreviousState, ULONG* ReturnLength)
{
    (void)TokenHandle;
    (void)ResetToDefault;
    (void)NewState;
    (void)BufferLength;
    (void)PreviousState;
    if (ReturnLength != (ULONG*)0)
        *ReturnLength = 0;
    return NTSTATUS_SUCCESS;
}

__declspec(dllexport) NTSTATUS NtSetInformationToken(HANDLE TokenHandle, ULONG TokenInformationClass,
                                                     void* TokenInformation, ULONG TokenInformationLength)
{
    (void)TokenHandle;
    (void)TokenInformationClass;
    (void)TokenInformation;
    (void)TokenInformationLength;
    return NTSTATUS_SUCCESS;
}

__declspec(dllexport) NTSTATUS NtCheckTokenMembership(HANDLE TokenHandle, void* SidToCheck, BOOL* IsMember)
{
    (void)TokenHandle;
    (void)SidToCheck;
    if (IsMember != (BOOL*)0)
        *IsMember = 1;
    return NTSTATUS_SUCCESS;
}

__declspec(dllexport) NTSTATUS NtPrivilegeObjectAuditAlarm(void* SubsystemName, void* HandleId, HANDLE ClientToken,
                                                           ULONG DesiredAccess, void* Privileges, BOOL AccessGranted)
{
    (void)SubsystemName;
    (void)HandleId;
    (void)ClientToken;
    (void)DesiredAccess;
    (void)Privileges;
    (void)AccessGranted;
    return NTSTATUS_SUCCESS;
}

/* ------------------------------------------------------------------
 * NT timer family — explicit NotImpl facades.
 *
 * Win32 NT timers are kernel-coordinated dispatcher objects.
 * v0 has no APC dispatch + no kernel timer queue exposed via
 * the timer-handle ABI. Callers wanting time-based wakes use
 * Sleep / NtDelayExecution (already implemented).
 * ------------------------------------------------------------------ */
__declspec(dllexport) NTSTATUS NtCreateTimer(HANDLE* TimerHandle, ULONG DesiredAccess, void* ObjectAttributes,
                                             ULONG TimerType)
{
    (void)TimerHandle;
    (void)DesiredAccess;
    (void)ObjectAttributes;
    (void)TimerType;
    return (NTSTATUS)0xC0000002;
}

__declspec(dllexport) NTSTATUS NtSetTimer(HANDLE TimerHandle, void* DueTime, void* TimerApcRoutine, void* TimerContext,
                                          BOOL ResumeTimer, ULONG Period, BOOL* PreviousState)
{
    (void)TimerHandle;
    (void)DueTime;
    (void)TimerApcRoutine;
    (void)TimerContext;
    (void)ResumeTimer;
    (void)Period;
    (void)PreviousState;
    return (NTSTATUS)0xC0000002;
}

__declspec(dllexport) NTSTATUS NtCancelTimer(HANDLE TimerHandle, BOOL* CurrentState)
{
    (void)TimerHandle;
    if (CurrentState != (BOOL*)0)
        *CurrentState = 0;
    return (NTSTATUS)0xC0000002;
}

__declspec(dllexport) NTSTATUS NtOpenTimer(HANDLE* TimerHandle, ULONG DesiredAccess, void* ObjectAttributes)
{
    (void)TimerHandle;
    (void)DesiredAccess;
    (void)ObjectAttributes;
    return (NTSTATUS)0xC0000034;
}

/* ------------------------------------------------------------------
 * NT IO-completion family — explicit NotImpl facades.
 * Used by Win32 IOCP server frameworks. v0 has no async-I/O
 * completion queue.
 * ------------------------------------------------------------------ */
__declspec(dllexport) NTSTATUS NtCreateIoCompletion(HANDLE* IoCompletionHandle, ULONG DesiredAccess,
                                                    void* ObjectAttributes, ULONG NumberOfConcurrentThreads)
{
    (void)DesiredAccess;
    (void)ObjectAttributes;
    (void)NumberOfConcurrentThreads;
    if (IoCompletionHandle == (HANDLE*)0)
        return NTSTATUS_INVALID_PARAMETER;
    long long rv;
    __asm__ volatile("int $0x80" : "=a"(rv) : "a"((long long)159) : "memory"); /* SYS_IOCP_CREATE */
    if (rv < 0)
        return (NTSTATUS)0xC0000002;
    *IoCompletionHandle = (HANDLE)rv;
    return NTSTATUS_SUCCESS;
}

__declspec(dllexport) NTSTATUS NtOpenIoCompletion(HANDLE* IoCompletionHandle, ULONG DesiredAccess,
                                                  void* ObjectAttributes)
{
    (void)IoCompletionHandle;
    (void)DesiredAccess;
    (void)ObjectAttributes;
    /* No named-object table — open-by-name returns NAME_NOT_FOUND. */
    return (NTSTATUS)0xC0000034;
}

__declspec(dllexport) NTSTATUS NtSetIoCompletion(HANDLE IoCompletionHandle, void* CompletionKey, void* CompletionValue,
                                                 NTSTATUS CompletionStatus, ULONG NumberOfBytesTransferred)
{
    long long rv;
    __asm__ volatile("mov %4, %%r10\n\t"
                     "mov %5, %%r8\n\t"
                     "int $0x80"
                     : "=a"(rv)
                     : "a"((long long)160), /* SYS_IOCP_SET */
                       "D"((long long)IoCompletionHandle), "S"((long long)CompletionKey),
                       "d"((long long)CompletionValue), "r"((long long)CompletionStatus),
                       "r"((long long)NumberOfBytesTransferred)
                     : "r10", "r8", "memory");
    if (rv < 0)
        return (NTSTATUS)0xC0000008; /* INVALID_HANDLE */
    return NTSTATUS_SUCCESS;
}

__declspec(dllexport) NTSTATUS NtRemoveIoCompletion(HANDLE IoCompletionHandle, void* CompletionKey,
                                                    void* CompletionValue, void* IoStatusBlock, void* Timeout)
{
    /* Timeout is a pointer to a LARGE_INTEGER (NT 100ns ticks).
     * v0 collapses to "infinite if non-null, immediate if null".
     * Sub-GAP: real timeout integration not wired. */
    const unsigned long long timeout_ms = (Timeout != (void*)0) ? (unsigned long long)-1 : 0;
    long long rv;
    __asm__ volatile("mov %4, %%r10\n\t"
                     "mov %5, %%r8\n\t"
                     "int $0x80"
                     : "=a"(rv)
                     : "a"((long long)161), /* SYS_IOCP_REMOVE */
                       "D"((long long)IoCompletionHandle), "S"((long long)CompletionKey),
                       "d"((long long)CompletionValue), "r"((long long)IoStatusBlock), "r"(timeout_ms)
                     : "r10", "r8", "memory");
    if (rv < 0)
        return (NTSTATUS)0xC0000008;
    if (rv == 0)
        return (NTSTATUS)0x00000102; /* STATUS_TIMEOUT */
    return NTSTATUS_SUCCESS;
}

__declspec(dllexport) NTSTATUS NtRemoveIoCompletionEx(HANDLE IoCompletionHandle, void* IoCompletionInformation,
                                                      ULONG Count, ULONG* NumEntriesRemoved, void* Timeout,
                                                      BOOL Alertable)
{
    (void)Alertable;
    if (NumEntriesRemoved != (ULONG*)0)
        *NumEntriesRemoved = 0;
    if (Count == 0 || IoCompletionInformation == (void*)0)
        return NTSTATUS_INVALID_PARAMETER;
    /* Loop NtRemoveIoCompletion to fill the caller's array. Each
     * record is 32 bytes (key + apcctx + IO_STATUS_BLOCK). The
     * shape matches OVERLAPPED_ENTRY {lpCompletionKey, lpOverlapped,
     * Internal, dwNumberOfBytesTransferred}. */
    unsigned char* out = (unsigned char*)IoCompletionInformation;
    unsigned filled = 0;
    for (unsigned i = 0; i < Count; ++i)
    {
        unsigned long long iosb[2];
        unsigned long long key = 0;
        unsigned long long apc = 0;
        const unsigned long long timeout_ms = (i == 0 && Timeout != (void*)0) ? (unsigned long long)-1 : 0;
        long long rv;
        __asm__ volatile("mov %4, %%r10\n\t"
                         "mov %5, %%r8\n\t"
                         "int $0x80"
                         : "=a"(rv)
                         : "a"((long long)161), "D"((long long)IoCompletionHandle), "S"((long long)&key),
                           "d"((long long)&apc), "r"((long long)iosb), "r"(timeout_ms)
                         : "r10", "r8", "memory");
        if (rv != 1)
            break;
        unsigned base = i * 32;
        for (unsigned j = 0; j < 8; ++j)
        {
            out[base + j] = (unsigned char)((key >> (j * 8)) & 0xFF);
            out[base + 8 + j] = (unsigned char)((apc >> (j * 8)) & 0xFF);
            out[base + 16 + j] = (unsigned char)((iosb[0] >> (j * 8)) & 0xFF);
            out[base + 24 + j] = (unsigned char)((iosb[1] >> (j * 8)) & 0xFF);
        }
        ++filled;
    }
    if (NumEntriesRemoved != (ULONG*)0)
        *NumEntriesRemoved = filled;
    return filled > 0 ? NTSTATUS_SUCCESS : (NTSTATUS)0x00000102;
}

/* ------------------------------------------------------------------
 * NT transaction (KTM) family — explicit NotImpl facades.
 * Kernel Transaction Manager surface. v0 has no KTM.
 * ------------------------------------------------------------------ */
__declspec(dllexport) NTSTATUS NtCreateTransaction(HANDLE* TransactionHandle, ULONG DesiredAccess,
                                                   void* ObjectAttributes, void* Uow, HANDLE TmHandle,
                                                   ULONG CreateOptions, ULONG IsolationLevel, ULONG IsolationFlags,
                                                   void* Timeout, void* Description)
{
    (void)TransactionHandle;
    (void)DesiredAccess;
    (void)ObjectAttributes;
    (void)Uow;
    (void)TmHandle;
    (void)CreateOptions;
    (void)IsolationLevel;
    (void)IsolationFlags;
    (void)Timeout;
    (void)Description;
    return (NTSTATUS)0xC0000002;
}

__declspec(dllexport) NTSTATUS NtCommitTransaction(HANDLE TransactionHandle, BOOL Wait)
{
    (void)TransactionHandle;
    (void)Wait;
    return (NTSTATUS)0xC0000002;
}

__declspec(dllexport) NTSTATUS NtRollbackTransaction(HANDLE TransactionHandle, BOOL Wait)
{
    (void)TransactionHandle;
    (void)Wait;
    return (NTSTATUS)0xC0000002;
}

__declspec(dllexport) NTSTATUS NtOpenTransaction(HANDLE* TransactionHandle, ULONG DesiredAccess, void* ObjectAttributes,
                                                 void* Uow, HANDLE TmHandle)
{
    (void)TransactionHandle;
    (void)DesiredAccess;
    (void)ObjectAttributes;
    (void)Uow;
    (void)TmHandle;
    return (NTSTATUS)0xC0000034;
}

/* ------------------------------------------------------------------
 * NT misc — NtRaiseException, NtContinue (already exists),
 * NtYieldExecution, NtFlushInstructionCache, NtTestAlert.
 * Most are tractable as success no-ops or simple forwards.
 * ------------------------------------------------------------------ */
/* NtYieldExecution lives at line ~99 (forwards to SYS_YIELD). */

__declspec(dllexport) NTSTATUS NtFlushInstructionCache(HANDLE ProcessHandle, void* BaseAddress, SIZE_T Length)
{
    (void)ProcessHandle;
    (void)BaseAddress;
    (void)Length;
    /* x86_64 has coherent I-cache vs D-cache; flush is a no-op. */
    return NTSTATUS_SUCCESS;
}

__declspec(dllexport) NTSTATUS NtTestAlert(void)
{
    /* No APC / alert engine — always returns NO_ALERT (a success
     * status meaning "nothing pending"). */
    return NTSTATUS_SUCCESS;
}

/* NtRaiseException now lives in ntdll_dispatch.c (real first-chance
 * user SEH dispatch, T6-02 slice 3). */

/* ------------------------------------------------------------------
 * NT process-creation thunks — explicit NotImpl facades.
 *
 * v0 has no Win32 PE process spawn pipeline. Process creation
 * happens at boot via the loader; runtime PE spawn via Win32 API
 * needs a section-from-file path that doesn't exist yet (sub-GAP
 * in §11.8). NtCreateUserProcess (the modern Vista+ API) gets
 * the same treatment.
 *
 * NtSuspendProcess / NtResumeProcess work at the per-process
 * granularity by walking every thread; v0 returns NotImpl
 * because that walk needs the §11.7-style suspend infrastructure
 * extended to whole-process scope. Per-thread NtSuspendThread is
 * the working alternative.
 * ------------------------------------------------------------------ */
__declspec(dllexport) NTSTATUS NtCreateProcess(HANDLE* ProcessHandle, ULONG DesiredAccess, void* ObjectAttributes,
                                               HANDLE ParentProcess, BOOL InheritObjectTable, HANDLE SectionHandle,
                                               HANDLE DebugPort, HANDLE ExceptionPort)
{
    (void)ProcessHandle;
    (void)DesiredAccess;
    (void)ObjectAttributes;
    (void)ParentProcess;
    (void)InheritObjectTable;
    (void)SectionHandle;
    (void)DebugPort;
    (void)ExceptionPort;
    return (NTSTATUS)0xC0000002;
}

__declspec(dllexport) NTSTATUS ZwCreateProcess(HANDLE* ProcessHandle, ULONG DesiredAccess, void* ObjectAttributes,
                                               HANDLE ParentProcess, BOOL InheritObjectTable, HANDLE SectionHandle,
                                               HANDLE DebugPort, HANDLE ExceptionPort)
{
    return NtCreateProcess(ProcessHandle, DesiredAccess, ObjectAttributes, ParentProcess, InheritObjectTable,
                           SectionHandle, DebugPort, ExceptionPort);
}

__declspec(dllexport) NTSTATUS NtCreateProcessEx(HANDLE* ProcessHandle, ULONG DesiredAccess, void* ObjectAttributes,
                                                 HANDLE ParentProcess, ULONG Flags, HANDLE SectionHandle,
                                                 HANDLE DebugPort, HANDLE ExceptionPort, ULONG JobMemberLevel)
{
    (void)ProcessHandle;
    (void)DesiredAccess;
    (void)ObjectAttributes;
    (void)ParentProcess;
    (void)Flags;
    (void)SectionHandle;
    (void)DebugPort;
    (void)ExceptionPort;
    (void)JobMemberLevel;
    return (NTSTATUS)0xC0000002;
}

__declspec(dllexport) NTSTATUS ZwCreateProcessEx(HANDLE* ProcessHandle, ULONG DesiredAccess, void* ObjectAttributes,
                                                 HANDLE ParentProcess, ULONG Flags, HANDLE SectionHandle,
                                                 HANDLE DebugPort, HANDLE ExceptionPort, ULONG JobMemberLevel)
{
    return NtCreateProcessEx(ProcessHandle, DesiredAccess, ObjectAttributes, ParentProcess, Flags, SectionHandle,
                             DebugPort, ExceptionPort, JobMemberLevel);
}

/* RTL_USER_PROCESS_PARAMETERS — Windows process-parameters block.
 * Only the fields v0 actually consumes are named; the rest is
 * skipped via byte-offset reads so we don't need the full layout
 * here. ImagePathName is the path to the .exe we're spawning;
 * everything else (CommandLine, environment, current directory,
 * console handles) is accepted but unused — sub-GAP.
 *
 * UNICODE_STRING layout on x64:
 *   +0x00  Length        (USHORT, byte count, NOT including NUL)
 *   +0x02  MaximumLength (USHORT)
 *   +0x04  Padding
 *   +0x08  Buffer        (PWSTR — 8 bytes)
 *
 * Inside RTL_USER_PROCESS_PARAMETERS, ImagePathName lives at +0x60.
 * Independently verified against ntdll.dll on Windows 10 / 11 25H2.
 */
#define NTDLL_PP_OFFSET_IMAGE_PATH 0x60

/* Translate a Windows-shaped image path (UNICODE_STRING.Buffer +
 * Length-in-bytes) into the kernel's "/disk/N/..." form. Mirrors
 * the kernel32 NormalizePathW translator inline so ntdll stays
 * freestanding (kernel32 isn't guaranteed loaded yet at the time
 * a PE may issue NtCreateUserProcess).
 *
 * Strips up to one "\??\" or "\\?\" extended-length prefix, maps
 * a drive letter ("C:") to "/disk/N" (C → /disk/0, D → /disk/1,
 * ...), and converts "\" to "/" for the rest. Non-ASCII codepoints
 * become '?'. Returns 1 on success, 0 on capacity overrun / no
 * recognisable shape. */
static int ntdll_translate_image_path(const wchar_t16* buf, unsigned chars, char* out, unsigned cap)
{
    if (out == (char*)0 || cap == 0)
        return 0;
    out[0] = '\0';
    if (buf == (wchar_t16*)0 || chars == 0)
        return 0;

    unsigned ci = 0;
    /* "\??\" or "\\?\" extended-length prefix — strip once. */
    if (chars >= 4)
    {
        unsigned short a = buf[0];
        unsigned short b = buf[1];
        unsigned short c = buf[2];
        unsigned short d = buf[3];
        if ((a == L'\\' || a == L'/') && (b == L'\\' || b == L'?' || b == L'/') && (c == L'?' || c == L'\\') &&
            (d == L'\\' || d == L'/'))
        {
            ci = 4;
        }
    }

    unsigned oi = 0;
    /* Drive-letter prefix? */
    if (ci + 1 < chars)
    {
        unsigned short letter = buf[ci];
        unsigned short colon = buf[ci + 1];
        if (((letter >= L'A' && letter <= L'Z') || (letter >= L'a' && letter <= L'z')) && colon == L':')
        {
            char upper = (letter >= L'a' && letter <= L'z') ? (char)(letter - L'a' + L'A') : (char)letter;
            int idx = (upper < 'C') ? 0 : (upper - 'C');
            const char* prefix = "/disk/";
            for (unsigned p = 0; prefix[p] != '\0'; ++p)
            {
                if (oi + 1 >= cap)
                    return 0;
                out[oi++] = prefix[p];
            }
            if (idx >= 10)
            {
                if (oi + 1 >= cap)
                    return 0;
                out[oi++] = (char)('0' + (idx / 10));
            }
            if (oi + 1 >= cap)
                return 0;
            out[oi++] = (char)('0' + (idx % 10));
            ci += 2;
        }
    }

    while (ci < chars)
    {
        unsigned short w = buf[ci++];
        char c;
        if (w == L'\\')
            c = '/';
        else if (w <= 0x7F)
            c = (char)w;
        else
            c = '?';
        if (oi + 1 >= cap)
            return 0;
        out[oi++] = c;
    }
    out[oi] = '\0';
    return 1;
}

/* NtCreateUserProcess — backed by SYS_PROCESS_SPAWN = 158.
 *
 * Pulls ImagePathName out of RTL_USER_PROCESS_PARAMETERS, translates
 * the Windows-shaped path to the kernel's "/disk/N/..." form, and
 * issues SYS_PROCESS_SPAWN. Writes the new pid (cast to HANDLE) to
 * *ProcessHandle. ThreadHandle is set to -1 — the new thread's tid
 * is the same as its pid in v0 (single-thread-per-process at spawn),
 * so callers wanting a real thread handle can NtOpenThread the pid.
 *
 * Sub-GAPs (accepted but unused): CommandLine (kernel doesn't pass
 * arguments yet); ProcessFlags / ThreadFlags (no PROCESS_CREATE_*
 * semantics); CreateInfo / AttributeList (PS_ATTRIBUTE list is
 * Windows-internal); object attributes (no NT object-namespace yet).
 */
__declspec(dllexport) NTSTATUS NtCreateUserProcess(HANDLE* ProcessHandle, HANDLE* ThreadHandle,
                                                   ULONG ProcessDesiredAccess, ULONG ThreadDesiredAccess,
                                                   void* ProcessObjectAttributes, void* ThreadObjectAttributes,
                                                   ULONG ProcessFlags, ULONG ThreadFlags, void* ProcessParameters,
                                                   void* CreateInfo, void* AttributeList)
{
    (void)ProcessDesiredAccess;
    (void)ThreadDesiredAccess;
    (void)ProcessObjectAttributes;
    (void)ThreadObjectAttributes;
    (void)ProcessFlags;
    (void)ThreadFlags;
    (void)CreateInfo;
    (void)AttributeList;
    if (ProcessHandle == (HANDLE*)0 || ThreadHandle == (HANDLE*)0 || ProcessParameters == (void*)0)
        return NTSTATUS_INVALID_PARAMETER;

    const unsigned char* pp = (const unsigned char*)ProcessParameters;
    const unsigned char* image = pp + NTDLL_PP_OFFSET_IMAGE_PATH;
    const unsigned short length_bytes = *(const unsigned short*)(image + 0);
    const wchar_t16* buffer = *(const wchar_t16* const*)(image + 8);
    if (buffer == (wchar_t16*)0 || length_bytes == 0)
        return NTSTATUS_INVALID_PARAMETER;

    char path[128];
    const unsigned chars = (unsigned)(length_bytes / 2);
    if (!ntdll_translate_image_path(buffer, chars, path, sizeof(path)))
        return NTSTATUS_INVALID_PARAMETER;

    long long pid;
    /* SYS_PROCESS_SPAWN = 158: rdi = const char* path, rsi = u64 flags. */
    __asm__ volatile("int $0x80" : "=a"(pid) : "a"((long long)158), "D"((long long)path), "S"((long long)0) : "memory");
    if (pid < 0)
        return (NTSTATUS)0xC0000022; /* STATUS_ACCESS_DENIED — most likely cap miss */

    *ProcessHandle = (HANDLE)pid;
    *ThreadHandle = (HANDLE)-1; /* sub-GAP: caller can NtOpenThread(pid) for a real handle */
    return NTSTATUS_SUCCESS;
}

__declspec(dllexport) NTSTATUS ZwCreateUserProcess(HANDLE* ProcessHandle, HANDLE* ThreadHandle,
                                                   ULONG ProcessDesiredAccess, ULONG ThreadDesiredAccess,
                                                   void* ProcessObjectAttributes, void* ThreadObjectAttributes,
                                                   ULONG ProcessFlags, ULONG ThreadFlags, void* ProcessParameters,
                                                   void* CreateInfo, void* AttributeList)
{
    return NtCreateUserProcess(ProcessHandle, ThreadHandle, ProcessDesiredAccess, ThreadDesiredAccess,
                               ProcessObjectAttributes, ThreadObjectAttributes, ProcessFlags, ThreadFlags,
                               ProcessParameters, CreateInfo, AttributeList);
}

__declspec(dllexport) NTSTATUS NtSuspendProcess(HANDLE ProcessHandle)
{
    (void)ProcessHandle;
    return (NTSTATUS)0xC0000002;
}

__declspec(dllexport) NTSTATUS NtResumeProcess(HANDLE ProcessHandle)
{
    (void)ProcessHandle;
    return (NTSTATUS)0xC0000002;
}

/* ------------------------------------------------------------------
 * NT access-check / privilege / impersonation — explicit
 * NotImpl / accept-pass facades. v0 cap-gates on kCapDebug etc.
 * at the kernel; the Win32 access-check surface is a façade.
 * NtAccessCheck returns granted=true so callers don't loop on
 * a stuck "permission denied"; the real gating is kernel-side.
 * NtRevertToSelf is success-no-op (no impersonation token to
 * revert from).
 * ------------------------------------------------------------------ */
__declspec(dllexport) NTSTATUS NtAccessCheck(void* SecurityDescriptor, HANDLE ClientToken, ULONG DesiredAccess,
                                             void* GenericMapping, void* PrivilegeSet, ULONG* PrivilegeSetLength,
                                             ULONG* GrantedAccess, BOOL* AccessStatus)
{
    (void)SecurityDescriptor;
    (void)ClientToken;
    (void)GenericMapping;
    (void)PrivilegeSet;
    (void)PrivilegeSetLength;
    if (GrantedAccess != (ULONG*)0)
        *GrantedAccess = DesiredAccess;
    if (AccessStatus != (BOOL*)0)
        *AccessStatus = 1;
    return NTSTATUS_SUCCESS;
}

__declspec(dllexport) NTSTATUS NtPrivilegeCheck(HANDLE ClientToken, void* RequiredPrivileges, BOOL* Result)
{
    (void)ClientToken;
    (void)RequiredPrivileges;
    if (Result != (BOOL*)0)
        *Result = 1;
    return NTSTATUS_SUCCESS;
}

__declspec(dllexport) NTSTATUS NtImpersonateThread(HANDLE ServerThreadHandle, HANDLE ClientThreadHandle,
                                                   void* SecurityQos)
{
    (void)ServerThreadHandle;
    (void)ClientThreadHandle;
    (void)SecurityQos;
    /* No impersonation engine in v0. Returning success keeps
     * RPC-shaped probes happy; the actual identity of every
     * task is the same single-user model. */
    return NTSTATUS_SUCCESS;
}

__declspec(dllexport) NTSTATUS NtImpersonateAnonymousToken(HANDLE ThreadHandle)
{
    (void)ThreadHandle;
    return NTSTATUS_SUCCESS;
}

/* RtlSetImpersonationToken — referenced by some Win32 callers
 * for thread-token swap; same single-user façade. */
__declspec(dllexport) NTSTATUS NtSetInformationThread(HANDLE ThreadHandle, ULONG ThreadInformationClass,
                                                      void* ThreadInformation, ULONG ThreadInformationLength)
{
    (void)ThreadHandle;
    (void)ThreadInformationClass;
    (void)ThreadInformation;
    (void)ThreadInformationLength;
    /* Most callers set ThreadHideFromDebugger or ThreadAffinity-
     * Mask. v0 has no debugger and a single CPU; both are no-op
     * success. */
    return NTSTATUS_SUCCESS;
}

__declspec(dllexport) NTSTATUS NtQueryInformationThread(HANDLE ThreadHandle, ULONG ThreadInformationClass,
                                                        void* ThreadInformation, ULONG ThreadInformationLength,
                                                        ULONG* ReturnLength)
{
    (void)ThreadHandle;
    (void)ThreadInformation;
    (void)ThreadInformationLength;
    if (ReturnLength != (ULONG*)0)
        *ReturnLength = 0;
    /* ThreadBasicInformation (0): the canonical first probe.
     * Returns a 48-byte struct; v0 emits zeros. Callers that
     * need real values land in §11.7's Get/SetContext path
     * instead, which IS implemented. */
    if (ThreadInformationClass == 0 && ThreadInformation != (void*)0 && ThreadInformationLength >= 48)
    {
        unsigned char* out = (unsigned char*)ThreadInformation;
        for (unsigned i = 0; i < 48; ++i)
            out[i] = 0;
        if (ReturnLength != (ULONG*)0)
            *ReturnLength = 48;
        return NTSTATUS_SUCCESS;
    }
    return (NTSTATUS)0xC0000002;
}

__declspec(dllexport) NTSTATUS ZwSetInformationThread(HANDLE ThreadHandle, ULONG ThreadInformationClass,
                                                      void* ThreadInformation, ULONG ThreadInformationLength)
{
    return NtSetInformationThread(ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength);
}

__declspec(dllexport) NTSTATUS ZwQueryInformationThread(HANDLE ThreadHandle, ULONG ThreadInformationClass,
                                                        void* ThreadInformation, ULONG ThreadInformationLength,
                                                        ULONG* ReturnLength)
{
    return NtQueryInformationThread(ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength,
                                    ReturnLength);
}

/* NtSetInformationProcess — write counterpart to NtQueryInformationProcess.
 * Most callers set ProcessBasicInformation (write-back of PEB)
 * or ProcessIoCounters; both are no-op success. v0 doesn't gate
 * on any of these for actual behaviour. */
__declspec(dllexport) NTSTATUS NtSetInformationProcess(HANDLE ProcessHandle, ULONG ProcessInformationClass,
                                                       void* ProcessInformation, ULONG ProcessInformationLength)
{
    (void)ProcessHandle;
    (void)ProcessInformationClass;
    (void)ProcessInformation;
    (void)ProcessInformationLength;
    return NTSTATUS_SUCCESS;
}

__declspec(dllexport) NTSTATUS ZwSetInformationProcess(HANDLE ProcessHandle, ULONG ProcessInformationClass,
                                                       void* ProcessInformation, ULONG ProcessInformationLength)
{
    return NtSetInformationProcess(ProcessHandle, ProcessInformationClass, ProcessInformation,
                                   ProcessInformationLength);
}

/* ------------------------------------------------------------------
 * NT keyed-event surface — explicit NotImpl. KEs are a
 * Vista-era kernel-coordinated wait primitive used internally by
 * RtlAcquireSRWLockShared etc. v0's mutex/event surface covers
 * the same use cases through SYS_MUTEX_* / SYS_EVENT_*.
 * ------------------------------------------------------------------ */
__declspec(dllexport) NTSTATUS NtCreateKeyedEvent(HANDLE* KeyedEventHandle, ULONG DesiredAccess, void* ObjectAttributes,
                                                  ULONG Flags)
{
    (void)KeyedEventHandle;
    (void)DesiredAccess;
    (void)ObjectAttributes;
    (void)Flags;
    return (NTSTATUS)0xC0000002;
}

__declspec(dllexport) NTSTATUS NtOpenKeyedEvent(HANDLE* KeyedEventHandle, ULONG DesiredAccess, void* ObjectAttributes)
{
    (void)KeyedEventHandle;
    (void)DesiredAccess;
    (void)ObjectAttributes;
    return (NTSTATUS)0xC0000002;
}

__declspec(dllexport) NTSTATUS NtWaitForKeyedEvent(HANDLE KeyedEventHandle, void* Key, BOOL Alertable, void* Timeout)
{
    (void)KeyedEventHandle;
    (void)Key;
    (void)Alertable;
    (void)Timeout;
    return (NTSTATUS)0xC0000002;
}

__declspec(dllexport) NTSTATUS NtReleaseKeyedEvent(HANDLE KeyedEventHandle, void* Key, BOOL Alertable, void* Timeout)
{
    (void)KeyedEventHandle;
    (void)Key;
    (void)Alertable;
    (void)Timeout;
    return (NTSTATUS)0xC0000002;
}

/* ------------------------------------------------------------------
 * NT debug surface — userland-only NotImpl stubs.
 *
 * v0 has no debug-event engine (no DBG_PRINTEXCEPTION_C dispatch,
 * no debug-port queue, no Wait-for-debug-event blocking). The
 * Win32 cap-gating model — kCapDebug — is what gates cross-
 * process inspection (via NtOpenProcess / NtOpenThread / VM read
 * + write / Get/SetContext). The classic NtDebug* family that
 * a Windows debugger uses is a separate rope; v0 doesn't pull
 * it. These stubs return STATUS_NOT_IMPLEMENTED explicitly so
 * callers see a clean "no debugger here" instead of generic
 * kSysNtNotImpl noise.
 *
 * NB: this is a FACADE per the subsystem-isolation rule. The
 * Win32 NtDebug* surface does not gate DuetOS-level debug
 * authority — that's still kCapDebug, enforced kernel-side on
 * SYS_PROCESS_VM_READ / SYS_THREAD_GET_CONTEXT / etc.
 * ------------------------------------------------------------------ */
__declspec(dllexport) NTSTATUS NtCreateDebugObject(HANDLE* DebugObjectHandle, ULONG DesiredAccess,
                                                   void* ObjectAttributes, ULONG Flags)
{
    (void)DebugObjectHandle;
    (void)DesiredAccess;
    (void)ObjectAttributes;
    (void)Flags;
    return (NTSTATUS)0xC0000002;
}

__declspec(dllexport) NTSTATUS ZwCreateDebugObject(HANDLE* DebugObjectHandle, ULONG DesiredAccess,
                                                   void* ObjectAttributes, ULONG Flags)
{
    return NtCreateDebugObject(DebugObjectHandle, DesiredAccess, ObjectAttributes, Flags);
}

__declspec(dllexport) NTSTATUS NtDebugActiveProcess(HANDLE ProcessHandle, HANDLE DebugObjectHandle)
{
    (void)ProcessHandle;
    (void)DebugObjectHandle;
    return (NTSTATUS)0xC0000002;
}

__declspec(dllexport) NTSTATUS ZwDebugActiveProcess(HANDLE ProcessHandle, HANDLE DebugObjectHandle)
{
    return NtDebugActiveProcess(ProcessHandle, DebugObjectHandle);
}

__declspec(dllexport) NTSTATUS NtDebugContinue(HANDLE DebugObjectHandle, void* ClientId, ULONG ContinueStatus)
{
    (void)DebugObjectHandle;
    (void)ClientId;
    (void)ContinueStatus;
    return (NTSTATUS)0xC0000002;
}

__declspec(dllexport) NTSTATUS ZwDebugContinue(HANDLE DebugObjectHandle, void* ClientId, ULONG ContinueStatus)
{
    return NtDebugContinue(DebugObjectHandle, ClientId, ContinueStatus);
}

__declspec(dllexport) NTSTATUS NtWaitForDebugEvent(HANDLE DebugObjectHandle, BOOL Alertable, void* Timeout,
                                                   void* WaitStateChange)
{
    (void)DebugObjectHandle;
    (void)Alertable;
    (void)Timeout;
    (void)WaitStateChange;
    return (NTSTATUS)0xC0000002;
}

__declspec(dllexport) NTSTATUS ZwWaitForDebugEvent(HANDLE DebugObjectHandle, BOOL Alertable, void* Timeout,
                                                   void* WaitStateChange)
{
    return NtWaitForDebugEvent(DebugObjectHandle, Alertable, Timeout, WaitStateChange);
}

__declspec(dllexport) NTSTATUS NtRemoveProcessDebug(HANDLE ProcessHandle, HANDLE DebugObjectHandle)
{
    (void)ProcessHandle;
    (void)DebugObjectHandle;
    return (NTSTATUS)0xC0000002;
}

__declspec(dllexport) NTSTATUS ZwRemoveProcessDebug(HANDLE ProcessHandle, HANDLE DebugObjectHandle)
{
    return NtRemoveProcessDebug(ProcessHandle, DebugObjectHandle);
}

__declspec(dllexport) NTSTATUS NtSetInformationDebugObject(HANDLE DebugObjectHandle, ULONG DebugObjectInformationClass,
                                                           void* DebugInformation, ULONG DebugInformationLength,
                                                           ULONG* ReturnLength)
{
    (void)DebugObjectHandle;
    (void)DebugObjectInformationClass;
    (void)DebugInformation;
    (void)DebugInformationLength;
    (void)ReturnLength;
    return (NTSTATUS)0xC0000002;
}

__declspec(dllexport) NTSTATUS ZwSetInformationDebugObject(HANDLE DebugObjectHandle, ULONG DebugObjectInformationClass,
                                                           void* DebugInformation, ULONG DebugInformationLength,
                                                           ULONG* ReturnLength)
{
    return NtSetInformationDebugObject(DebugObjectHandle, DebugObjectInformationClass, DebugInformation,
                                       DebugInformationLength, ReturnLength);
}

__declspec(dllexport) NTSTATUS NtQueryDebugFilterState(ULONG ComponentId, ULONG Level)
{
    (void)ComponentId;
    (void)Level;
    /* TRUE = component logging enabled. v0 returns FALSE
     * uniformly — no debug logging filter. */
    return 0;
}
