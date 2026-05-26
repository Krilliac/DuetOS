#include "ntdll_internal.h"

/* ------------------------------------------------------------------
 * NtQueryObject — derive object metadata from a kernel handle.
 *
 * Win32 NT signature:
 *   NTSTATUS NtQueryObject(
 *     HANDLE Handle,
 *     OBJECT_INFORMATION_CLASS ObjectInformationClass,
 *     PVOID ObjectInformation,
 *     ULONG ObjectInformationLength,
 *     PULONG ReturnLength);
 *
 * v0 honours ObjectTypeInformation (class 2) only — that's the
 * class every malware-shape PE uses to confirm a handle's
 * underlying type. The implementation lives entirely in userland:
 * the kernel's handle bases are stable u64 ranges
 * (0x200..0x208 = Mutant, 0x300..0x308 = Event,
 *  0x400..0x408 = Thread, 0x600..0x608 = Key,
 *  0x700..0x708 = Process, 0x800..0x808 = Thread (foreign),
 *  0x900..0x908 = Section), so range-matching produces the
 *  right type name without a syscall.
 *
 *  Output layout for ObjectTypeInformation: a UNICODE_STRING
 *  header (16 bytes on x64) followed by the UTF-16 type name
 *  + trailing NUL, with Buffer pointing into the same buffer.
 *  This matches the "alloc one block, header self-references"
 *  shape every Windows caller assumes.
 * ------------------------------------------------------------------ */
static const wchar_t16* HandleRangeToTypeName(unsigned long long handle)
{
    static const wchar_t16 mutant[] = {'M', 'u', 't', 'a', 'n', 't', 0};
    static const wchar_t16 event[] = {'E', 'v', 'e', 'n', 't', 0};
    static const wchar_t16 thread[] = {'T', 'h', 'r', 'e', 'a', 'd', 0};
    static const wchar_t16 key[] = {'K', 'e', 'y', 0};
    static const wchar_t16 process[] = {'P', 'r', 'o', 'c', 'e', 's', 's', 0};
    static const wchar_t16 section[] = {'S', 'e', 'c', 't', 'i', 'o', 'n', 0};
    if (handle >= 0x200 && handle < 0x208)
        return mutant;
    if (handle >= 0x300 && handle < 0x308)
        return event;
    if (handle >= 0x400 && handle < 0x408)
        return thread;
    if (handle >= 0x600 && handle < 0x608)
        return key;
    if (handle >= 0x700 && handle < 0x708)
        return process;
    if (handle >= 0x800 && handle < 0x808)
        return thread; /* foreign-thread handles are still threads */
    if (handle >= 0x900 && handle < 0x908)
        return section;
    return (const wchar_t16*)0;
}

static unsigned WStr16Len(const wchar_t16* s)
{
    unsigned n = 0;
    while (s[n] != 0)
        ++n;
    return n;
}

__declspec(dllexport) NTSTATUS NtQueryObject(HANDLE Handle, ULONG ObjectInformationClass, void* ObjectInformation,
                                             ULONG ObjectInformationLength, ULONG* ReturnLength)
{
    /* ObjectTypeInformation = 2. Other classes (Basic, Name,
     * AllInformation, DataInformation, …) return NOT_IMPLEMENTED
     * so callers fall back rather than misinterpret zeros. */
    if (ObjectInformationClass != 2)
        return (NTSTATUS)0xC0000002; /* STATUS_NOT_IMPLEMENTED */

    const wchar_t16* type_name = HandleRangeToTypeName((unsigned long long)Handle);
    if (type_name == (const wchar_t16*)0)
        return (NTSTATUS)0xC0000008; /* STATUS_INVALID_HANDLE */

    const unsigned name_chars = WStr16Len(type_name);
    const unsigned name_bytes = name_chars * 2;
    /* OBJECT_TYPE_INFORMATION starts with a 16-byte UNICODE_STRING
     * (Length:2, MaximumLength:2, _pad:4, Buffer:8) on x64. The
     * UTF-16 string body follows immediately after, with a
     * trailing NUL. */
    const unsigned header = 16;
    const unsigned total = header + name_bytes + 2;
    if (ReturnLength != (ULONG*)0)
        *ReturnLength = total;
    if (ObjectInformationLength < total)
        return (NTSTATUS)0xC0000023; /* STATUS_BUFFER_TOO_SMALL */
    if (ObjectInformation == (void*)0)
        return NTSTATUS_INVALID_PARAMETER;

    unsigned char* out = (unsigned char*)ObjectInformation;
    /* UNICODE_STRING.Length (bytes used, excluding NUL). */
    out[0] = (unsigned char)(name_bytes & 0xFF);
    out[1] = (unsigned char)((name_bytes >> 8) & 0xFF);
    /* UNICODE_STRING.MaximumLength (bytes including NUL). */
    out[2] = (unsigned char)((name_bytes + 2) & 0xFF);
    out[3] = (unsigned char)(((name_bytes + 2) >> 8) & 0xFF);
    /* 4-byte padding zeroed. */
    out[4] = 0;
    out[5] = 0;
    out[6] = 0;
    out[7] = 0;
    /* UNICODE_STRING.Buffer — pointer to the body inside this
     * same allocation. */
    void** buf_slot = (void**)(out + 8);
    *buf_slot = (void*)(out + header);

    /* Copy the UTF-16 type name body + trailing NUL. */
    wchar_t16* body = (wchar_t16*)(out + header);
    for (unsigned i = 0; i < name_chars; ++i)
        body[i] = type_name[i];
    body[name_chars] = 0;
    return NTSTATUS_SUCCESS;
}

__declspec(dllexport) NTSTATUS ZwQueryObject(HANDLE Handle, ULONG ObjectInformationClass, void* ObjectInformation,
                                             ULONG ObjectInformationLength, ULONG* ReturnLength)
{
    return NtQueryObject(Handle, ObjectInformationClass, ObjectInformation, ObjectInformationLength, ReturnLength);
}

/* NtQuerySystemTime + NtQueryPerformanceCounter live earlier in
 * this file (around line 127). Zw* aliases below for export
 * completeness. */
__declspec(dllexport) NTSTATUS ZwQuerySystemTime(long long* SystemTime)
{
    return NtQuerySystemTime(SystemTime);
}

__declspec(dllexport) NTSTATUS ZwQueryPerformanceCounter(long long* counter, long long* freq)
{
    return NtQueryPerformanceCounter(counter, freq);
}

/* ------------------------------------------------------------------
 * NtQuerySystemInformation — multiplexed system info read.
 * Honours SystemBasicInformation (0) + SystemTimeOfDayInformation (3);
 * other classes return NotImpl. The real hardware/topology data
 * lives in the kernel — this thunk only adapts the ABI shape.
 * ------------------------------------------------------------------ */
__declspec(dllexport) NTSTATUS NtQuerySystemInformation(ULONG SystemInformationClass, void* SystemInformation,
                                                        ULONG SystemInformationLength, ULONG* ReturnLength)
{
    if (SystemInformation == (void*)0)
        return NTSTATUS_INVALID_PARAMETER;
    if (SystemInformationClass == 0 /* SystemBasicInformation */)
    {
        const unsigned total = 56;
        if (ReturnLength != (ULONG*)0)
            *ReturnLength = total;
        if (SystemInformationLength < total)
            return (NTSTATUS)0xC0000004;
        unsigned char* out = (unsigned char*)SystemInformation;
        for (unsigned i = 0; i < total; ++i)
            out[i] = 0;
        out[4] = 0x10;
        out[5] = 0x27; /* TimerResolution */
        out[8] = 0x00;
        out[9] = 0x10; /* PageSize = 4096 */
        out[24] = 0x00;
        out[25] = 0x00;
        out[26] = 0x01;
        out[27] = 0x00; /* AllocationGranularity = 65536 */
        out[52] = 1;    /* NumberOfProcessors = 1 */
        return NTSTATUS_SUCCESS;
    }
    if (SystemInformationClass == 3 /* SystemTimeOfDayInformation */)
    {
        const unsigned total = 32;
        if (ReturnLength != (ULONG*)0)
            *ReturnLength = total;
        if (SystemInformationLength < total)
            return (NTSTATUS)0xC0000004;
        unsigned char* out = (unsigned char*)SystemInformation;
        for (unsigned i = 0; i < total; ++i)
            out[i] = 0;
        long long ft, ns;
        __asm__ volatile("int $0x80" : "=a"(ft) : "a"((long long)17) : "memory");
        __asm__ volatile("int $0x80" : "=a"(ns) : "a"((long long)18) : "memory");
        long long boot = ft - (ns / 100);
        for (unsigned i = 0; i < 8; ++i)
            out[i] = (unsigned char)((boot >> (i * 8)) & 0xFF);
        for (unsigned i = 0; i < 8; ++i)
            out[8 + i] = (unsigned char)((ft >> (i * 8)) & 0xFF);
        return NTSTATUS_SUCCESS;
    }
    return (NTSTATUS)0xC0000002;
}

__declspec(dllexport) NTSTATUS ZwQuerySystemInformation(ULONG SystemInformationClass, void* SystemInformation,
                                                        ULONG SystemInformationLength, ULONG* ReturnLength)
{
    return NtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
}

__declspec(dllexport) NTSTATUS NtSetSystemInformation(ULONG SystemInformationClass, void* SystemInformation,
                                                      ULONG SystemInformationLength)
{
    (void)SystemInformationClass;
    (void)SystemInformation;
    (void)SystemInformationLength;
    return (NTSTATUS)0xC0000002;
}

__declspec(dllexport) NTSTATUS ZwSetSystemInformation(ULONG SystemInformationClass, void* SystemInformation,
                                                      ULONG SystemInformationLength)
{
    return NtSetSystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength);
}

/* ------------------------------------------------------------------
 * NT LPC / ALPC — explicit NotImpl facades.
 *
 * v0 has no LPC/ALPC inter-process port engine. Every Win32 RPC
 * lands kernel-side via SYS_* directly, not via Win32 ports.
 * These thunks return NotImpl so any RPC-shaped probe gets a
 * clean answer. Architectural note: cross-process IPC in DuetOS
 * goes through kernel-mediated, cap-gated SYS_* — the LPC port
 * surface is a façade, not a parallel IPC path.
 * ------------------------------------------------------------------ */
__declspec(dllexport) NTSTATUS NtCreatePort(HANDLE* PortHandle, void* ObjectAttributes, ULONG MaxConnectionInfoLength,
                                            ULONG MaxMessageLength, ULONG MaxPoolUsage)
{
    (void)PortHandle;
    (void)ObjectAttributes;
    (void)MaxConnectionInfoLength;
    (void)MaxMessageLength;
    (void)MaxPoolUsage;
    return (NTSTATUS)0xC0000002;
}

__declspec(dllexport) NTSTATUS NtConnectPort(HANDLE* ClientPortHandle, void* PortName, void* SecurityQos,
                                             void* ClientView, void* ServerView, void* MaxMessageLength,
                                             void* ConnectionInformation, void* ConnectionInformationLength)
{
    (void)ClientPortHandle;
    (void)PortName;
    (void)SecurityQos;
    (void)ClientView;
    (void)ServerView;
    (void)MaxMessageLength;
    (void)ConnectionInformation;
    (void)ConnectionInformationLength;
    return (NTSTATUS)0xC0000002;
}

__declspec(dllexport) NTSTATUS NtListenPort(HANDLE PortHandle, void* ConnectionRequest)
{
    (void)PortHandle;
    (void)ConnectionRequest;
    return (NTSTATUS)0xC0000002;
}

__declspec(dllexport) NTSTATUS NtAcceptConnectPort(HANDLE* ServerPortHandle, void* PortContext, void* ConnectionRequest,
                                                   BOOL AcceptConnection, void* ServerView, void* ClientView)
{
    (void)ServerPortHandle;
    (void)PortContext;
    (void)ConnectionRequest;
    (void)AcceptConnection;
    (void)ServerView;
    (void)ClientView;
    return (NTSTATUS)0xC0000002;
}

__declspec(dllexport) NTSTATUS NtCompleteConnectPort(HANDLE PortHandle)
{
    (void)PortHandle;
    return (NTSTATUS)0xC0000002;
}

__declspec(dllexport) NTSTATUS NtRequestPort(HANDLE PortHandle, void* RequestMessage)
{
    (void)PortHandle;
    (void)RequestMessage;
    return (NTSTATUS)0xC0000002;
}

__declspec(dllexport) NTSTATUS NtRequestWaitReplyPort(HANDLE PortHandle, void* RequestMessage, void* ReplyMessage)
{
    (void)PortHandle;
    (void)RequestMessage;
    (void)ReplyMessage;
    return (NTSTATUS)0xC0000002;
}

__declspec(dllexport) NTSTATUS NtReplyPort(HANDLE PortHandle, void* ReplyMessage)
{
    (void)PortHandle;
    (void)ReplyMessage;
    return (NTSTATUS)0xC0000002;
}

__declspec(dllexport) NTSTATUS NtReplyWaitReceivePort(HANDLE PortHandle, void** PortContext, void* ReplyMessage,
                                                      void* ReceiveMessage)
{
    (void)PortHandle;
    (void)PortContext;
    (void)ReplyMessage;
    (void)ReceiveMessage;
    return (NTSTATUS)0xC0000002;
}

__declspec(dllexport) NTSTATUS NtAlpcCreatePort(HANDLE* PortHandle, void* ObjectAttributes, void* PortAttributes)
{
    (void)PortHandle;
    (void)ObjectAttributes;
    (void)PortAttributes;
    return (NTSTATUS)0xC0000002;
}

__declspec(dllexport) NTSTATUS NtAlpcConnectPort(HANDLE* PortHandle, void* PortName, void* ObjectAttributes,
                                                 void* PortAttributes, ULONG Flags, void* RequiredServerSid,
                                                 void* ConnectionMessage, void* BufferLength,
                                                 void* OutMessageAttributes, void* InMessageAttributes, void* Timeout)
{
    (void)PortHandle;
    (void)PortName;
    (void)ObjectAttributes;
    (void)PortAttributes;
    (void)Flags;
    (void)RequiredServerSid;
    (void)ConnectionMessage;
    (void)BufferLength;
    (void)OutMessageAttributes;
    (void)InMessageAttributes;
    (void)Timeout;
    return (NTSTATUS)0xC0000002;
}

__declspec(dllexport) NTSTATUS NtAlpcSendWaitReceivePort(HANDLE PortHandle, ULONG Flags, void* SendMessage,
                                                         void* SendMessageAttributes, void* ReceiveMessage,
                                                         void* BufferLength, void* ReceiveMessageAttributes,
                                                         void* Timeout)
{
    (void)PortHandle;
    (void)Flags;
    (void)SendMessage;
    (void)SendMessageAttributes;
    (void)ReceiveMessage;
    (void)BufferLength;
    (void)ReceiveMessageAttributes;
    (void)Timeout;
    return (NTSTATUS)0xC0000002;
}

/* ------------------------------------------------------------------
 * NT atom / symbolic-link / directory-object — explicit NotImpl
 * facades. All four are name-table primitives that v0 doesn't
 * have a backing store for. Architectural note: the kernel owns
 * naming; these thunks don't synthesize a parallel namespace.
 * ------------------------------------------------------------------ */
__declspec(dllexport) NTSTATUS NtAddAtom(void* AtomName, ULONG Length, void* Atom)
{
    (void)AtomName;
    (void)Length;
    (void)Atom;
    return (NTSTATUS)0xC0000002;
}

__declspec(dllexport) NTSTATUS NtFindAtom(void* AtomName, ULONG Length, void* Atom)
{
    (void)AtomName;
    (void)Length;
    (void)Atom;
    return (NTSTATUS)0xC0000002;
}

__declspec(dllexport) NTSTATUS NtDeleteAtom(unsigned short Atom)
{
    (void)Atom;
    return (NTSTATUS)0xC0000002;
}

__declspec(dllexport) NTSTATUS NtCreateSymbolicLinkObject(HANDLE* LinkHandle, ULONG DesiredAccess,
                                                          void* ObjectAttributes, void* LinkTarget)
{
    (void)LinkHandle;
    (void)DesiredAccess;
    (void)ObjectAttributes;
    (void)LinkTarget;
    return (NTSTATUS)0xC0000002;
}

__declspec(dllexport) NTSTATUS NtOpenSymbolicLinkObject(HANDLE* LinkHandle, ULONG DesiredAccess, void* ObjectAttributes)
{
    (void)LinkHandle;
    (void)DesiredAccess;
    (void)ObjectAttributes;
    return (NTSTATUS)0xC0000002;
}

__declspec(dllexport) NTSTATUS NtQuerySymbolicLinkObject(HANDLE LinkHandle, void* LinkTarget, void* ReturnedLength)
{
    (void)LinkHandle;
    (void)LinkTarget;
    (void)ReturnedLength;
    return (NTSTATUS)0xC0000002;
}

__declspec(dllexport) NTSTATUS NtCreateDirectoryObject(HANDLE* DirectoryHandle, ULONG DesiredAccess,
                                                       void* ObjectAttributes)
{
    (void)DirectoryHandle;
    (void)DesiredAccess;
    (void)ObjectAttributes;
    return (NTSTATUS)0xC0000002;
}

__declspec(dllexport) NTSTATUS NtOpenDirectoryObject(HANDLE* DirectoryHandle, ULONG DesiredAccess,
                                                     void* ObjectAttributes)
{
    (void)DirectoryHandle;
    (void)DesiredAccess;
    (void)ObjectAttributes;
    return (NTSTATUS)0xC0000002;
}

__declspec(dllexport) NTSTATUS NtQueryDirectoryObject(HANDLE DirectoryHandle, void* Buffer, ULONG Length,
                                                      BOOL ReturnSingleEntry, BOOL RestartScan, void* Context,
                                                      void* ReturnLength)
{
    (void)DirectoryHandle;
    (void)Buffer;
    (void)Length;
    (void)ReturnSingleEntry;
    (void)RestartScan;
    (void)Context;
    (void)ReturnLength;
    return (NTSTATUS)0xC0000002;
}

/* ------------------------------------------------------------------
 * NT extended-file ops — explicit NotImpl facades.
 * Lock / EA / NotifyChange families. v0 has no byte-range lock
 * table, no extended-attribute store, and no inotify-style watch
 * dispatch. Returning NotImpl is the right answer; callers fall
 * back rather than spin.
 * ------------------------------------------------------------------ */
__declspec(dllexport) NTSTATUS NtLockFile(HANDLE FileHandle, HANDLE Event, void* ApcRoutine, void* ApcContext,
                                          void* IoStatusBlock, void* ByteOffset, void* Length, ULONG Key,
                                          BOOL FailImmediately, BOOL ExclusiveLock)
{
    (void)FileHandle;
    (void)Event;
    (void)ApcRoutine;
    (void)ApcContext;
    (void)IoStatusBlock;
    (void)ByteOffset;
    (void)Length;
    (void)Key;
    (void)FailImmediately;
    (void)ExclusiveLock;
    return (NTSTATUS)0xC0000002;
}

__declspec(dllexport) NTSTATUS NtUnlockFile(HANDLE FileHandle, void* IoStatusBlock, void* ByteOffset, void* Length,
                                            ULONG Key)
{
    (void)FileHandle;
    (void)IoStatusBlock;
    (void)ByteOffset;
    (void)Length;
    (void)Key;
    return (NTSTATUS)0xC0000002;
}

__declspec(dllexport) NTSTATUS NtQueryEaFile(HANDLE FileHandle, void* IoStatusBlock, void* Buffer, ULONG Length,
                                             BOOL ReturnSingleEntry, void* EaList, ULONG EaListLength, void* EaIndex,
                                             BOOL RestartScan)
{
    (void)FileHandle;
    (void)IoStatusBlock;
    (void)Buffer;
    (void)Length;
    (void)ReturnSingleEntry;
    (void)EaList;
    (void)EaListLength;
    (void)EaIndex;
    (void)RestartScan;
    return (NTSTATUS)0xC0000002;
}

__declspec(dllexport) NTSTATUS NtSetEaFile(HANDLE FileHandle, void* IoStatusBlock, void* Buffer, ULONG Length)
{
    (void)FileHandle;
    (void)IoStatusBlock;
    (void)Buffer;
    (void)Length;
    return (NTSTATUS)0xC0000002;
}

/* NtNotifyChangeDirectoryFile — backed by SYS_DIR_NOTIFY (= 157).
 * Synchronous: blocks until the watched directory has at least
 * one change matching CompletionFilter, then writes a single
 * FILE_NOTIFY_INFORMATION record and returns. Real Windows packs
 * many records and supports async via Event / APC; v0 caller
 * loops to drain. Event / ApcRoutine / ApcContext accepted but
 * ignored — sub-GAP. */
__declspec(dllexport) NTSTATUS NtNotifyChangeDirectoryFile(HANDLE FileHandle, HANDLE Event, void* ApcRoutine,
                                                           void* ApcContext, void* IoStatusBlock, void* Buffer,
                                                           ULONG Length, ULONG CompletionFilter, BOOL WatchTree)
{
    (void)Event;
    (void)ApcRoutine;
    (void)ApcContext;
    if (Buffer == (void*)0 || Length == 0)
        return NTSTATUS_INVALID_PARAMETER;
    long long rv;
    __asm__ volatile("mov %4, %%r10\n\t"
                     "mov %5, %%r8\n\t"
                     "int $0x80"
                     : "=a"(rv)
                     : "a"((long long)157), /* SYS_DIR_NOTIFY */
                       "D"((long long)FileHandle), "S"((long long)CompletionFilter), "d"((long long)WatchTree),
                       "r"((long long)Buffer), "r"((long long)Length)
                     : "r10", "r8", "memory");
    if (rv < 0)
        return (NTSTATUS)0xC0000008ULL; /* STATUS_INVALID_HANDLE */
    if (IoStatusBlock != (void*)0)
    {
        unsigned long long* iosb = (unsigned long long*)IoStatusBlock;
        iosb[0] = 0;                      /* NTSTATUS_SUCCESS */
        iosb[1] = (unsigned long long)rv; /* bytes written */
    }
    return NTSTATUS_SUCCESS;
}

__declspec(dllexport) NTSTATUS NtCancelIoFile(HANDLE FileHandle, void* IoStatusBlock)
{
    (void)FileHandle;
    if (IoStatusBlock != (void*)0)
    {
        unsigned long long* iosb = (unsigned long long*)IoStatusBlock;
        iosb[0] = 0;
        iosb[1] = 0;
    }
    /* No async I/O to cancel; success no-op. */
    return NTSTATUS_SUCCESS;
}

/* ------------------------------------------------------------------
 * NT extended-IO + tracing + locale + final misc facades.
 * ------------------------------------------------------------------ */
__declspec(dllexport) NTSTATUS NtCancelIoFileEx(HANDLE FileHandle, void* IoRequestToCancel, void* IoStatusBlock)
{
    (void)FileHandle;
    (void)IoRequestToCancel;
    if (IoStatusBlock != (void*)0)
    {
        unsigned long long* iosb = (unsigned long long*)IoStatusBlock;
        iosb[0] = 0;
        iosb[1] = 0;
    }
    /* No async I/O to cancel. */
    return NTSTATUS_SUCCESS;
}

__declspec(dllexport) NTSTATUS NtCancelSynchronousIoFile(HANDLE ThreadHandle, void* IoRequestToCancel,
                                                         void* IoStatusBlock)
{
    (void)ThreadHandle;
    (void)IoRequestToCancel;
    if (IoStatusBlock != (void*)0)
    {
        unsigned long long* iosb = (unsigned long long*)IoStatusBlock;
        iosb[0] = 0;
        iosb[1] = 0;
    }
    return NTSTATUS_SUCCESS;
}

__declspec(dllexport) NTSTATUS NtReadFileScatter(HANDLE FileHandle, HANDLE Event, void* ApcRoutine, void* ApcContext,
                                                 void* IoStatusBlock, void* SegmentArray, ULONG Length,
                                                 void* ByteOffset, void* Key)
{
    (void)FileHandle;
    (void)Event;
    (void)ApcRoutine;
    (void)ApcContext;
    (void)SegmentArray;
    (void)Length;
    (void)ByteOffset;
    (void)Key;
    if (IoStatusBlock != (void*)0)
    {
        unsigned long long* iosb = (unsigned long long*)IoStatusBlock;
        iosb[0] = 0xC0000002;
        iosb[1] = 0;
    }
    return (NTSTATUS)0xC0000002;
}

__declspec(dllexport) NTSTATUS NtWriteFileGather(HANDLE FileHandle, HANDLE Event, void* ApcRoutine, void* ApcContext,
                                                 void* IoStatusBlock, void* SegmentArray, ULONG Length,
                                                 void* ByteOffset, void* Key)
{
    (void)FileHandle;
    (void)Event;
    (void)ApcRoutine;
    (void)ApcContext;
    (void)SegmentArray;
    (void)Length;
    (void)ByteOffset;
    (void)Key;
    if (IoStatusBlock != (void*)0)
    {
        unsigned long long* iosb = (unsigned long long*)IoStatusBlock;
        iosb[0] = 0xC0000002;
        iosb[1] = 0;
    }
    return (NTSTATUS)0xC0000002;
}

__declspec(dllexport) NTSTATUS NtTraceEvent(HANDLE TraceHandle, ULONG Flags, ULONG FieldSize, void* Fields)
{
    (void)TraceHandle;
    (void)Flags;
    (void)FieldSize;
    (void)Fields;
    /* No ETW; success no-op so tracing shapes don't error. */
    return NTSTATUS_SUCCESS;
}

__declspec(dllexport) NTSTATUS NtTraceControl(ULONG TraceCode, void* InputBuffer, ULONG InputBufferLength,
                                              void* OutputBuffer, ULONG OutputBufferLength, ULONG* ReturnLength)
{
    (void)TraceCode;
    (void)InputBuffer;
    (void)InputBufferLength;
    (void)OutputBuffer;
    (void)OutputBufferLength;
    if (ReturnLength != (ULONG*)0)
        *ReturnLength = 0;
    return (NTSTATUS)0xC0000002;
}

__declspec(dllexport) NTSTATUS NtGetMUIRegistryInfo(ULONG Flags, ULONG* OutputResourceCount, void* OutputBuffer)
{
    (void)Flags;
    if (OutputResourceCount != (ULONG*)0)
        *OutputResourceCount = 0;
    (void)OutputBuffer;
    return (NTSTATUS)0xC0000002;
}

/* Process-local default LCID + UI LangID. Real Windows persists
 * these to HKLM\SYSTEM\CurrentControlSet\Control\Nls\Language and
 * shares them across the system; v0 keeps them per-process in
 * userland (no cross-process registry yet). Initialised to en-US
 * (0x0409). A subsequent NtSetDefault* call updates the value so a
 * follow-up NtQueryDefault* reads back what was written. Plain
 * statics are safe in v0 — DuetOS PEs are single-process callers of
 * these and the locale knobs are not on a hot path. */
static unsigned long g_default_lcid = 0x0409UL;
static unsigned short g_default_langid = 0x0409;

__declspec(dllexport) NTSTATUS NtQueryDefaultLocale(BOOL UserProfile, ULONG* DefaultLocaleId)
{
    (void)UserProfile;
    if (DefaultLocaleId != (ULONG*)0)
        *DefaultLocaleId = g_default_lcid;
    return NTSTATUS_SUCCESS;
}

__declspec(dllexport) NTSTATUS NtSetDefaultLocale(BOOL UserProfile, ULONG DefaultLocaleId)
{
    (void)UserProfile;
    if (DefaultLocaleId == 0)
        return NTSTATUS_INVALID_PARAMETER;
    g_default_lcid = DefaultLocaleId;
    return NTSTATUS_SUCCESS;
}

__declspec(dllexport) NTSTATUS NtQueryDefaultUILanguage(unsigned short* DefaultUILanguageId)
{
    if (DefaultUILanguageId != (unsigned short*)0)
        *DefaultUILanguageId = g_default_langid;
    return NTSTATUS_SUCCESS;
}

__declspec(dllexport) NTSTATUS NtSetDefaultUILanguage(unsigned short DefaultUILanguageId)
{
    if (DefaultUILanguageId == 0)
        return NTSTATUS_INVALID_PARAMETER;
    g_default_langid = DefaultUILanguageId;
    return NTSTATUS_SUCCESS;
}

__declspec(dllexport) NTSTATUS NtQueryInstallUILanguage(unsigned short* InstallUILanguageId)
{
    if (InstallUILanguageId != (unsigned short*)0)
        *InstallUILanguageId = 0x0409;
    return NTSTATUS_SUCCESS;
}

__declspec(dllexport) NTSTATUS NtSetUuidSeed(void* Seed)
{
    (void)Seed;
    return NTSTATUS_SUCCESS;
}

__declspec(dllexport) NTSTATUS NtAllocateUuids(void* Time, ULONG* Range, ULONG* Sequence, void* Seed)
{
    (void)Time;
    (void)Seed;
    if (Range != (ULONG*)0)
        *Range = 0;
    if (Sequence != (ULONG*)0)
        *Sequence = 0;
    return (NTSTATUS)0xC0000002;
}

/* NtSecureConnectPort — LPC variant. NotImpl. */
__declspec(dllexport) NTSTATUS NtSecureConnectPort(HANDLE* ClientPortHandle, void* PortName, void* SecurityQos,
                                                   void* ClientView, void* ServerSid, void* ServerView,
                                                   void* MaxMessageLength, void* ConnectionInformation,
                                                   void* ConnectionInformationLength)
{
    (void)ClientPortHandle;
    (void)PortName;
    (void)SecurityQos;
    (void)ClientView;
    (void)ServerSid;
    (void)ServerView;
    (void)MaxMessageLength;
    (void)ConnectionInformation;
    (void)ConnectionInformationLength;
    return (NTSTATUS)0xC0000002;
}

/* NtDuplicateToken — duplicates a token for impersonation. v0
 * has one static token; duplication just hands back the same
 * sentinel handle (0xA00 — see DUETOS_TOKEN_HANDLE further
 * down). */
__declspec(dllexport) NTSTATUS NtDuplicateToken(HANDLE ExistingTokenHandle, ULONG DesiredAccess, void* ObjectAttributes,
                                                BOOL EffectiveOnly, ULONG TokenType, HANDLE* NewTokenHandle)
{
    (void)ExistingTokenHandle;
    (void)DesiredAccess;
    (void)ObjectAttributes;
    (void)EffectiveOnly;
    (void)TokenType;
    if (NewTokenHandle == (HANDLE*)0)
        return NTSTATUS_INVALID_PARAMETER;
    *NewTokenHandle = (HANDLE)0xA00;
    return NTSTATUS_SUCCESS;
}

__declspec(dllexport) NTSTATUS NtFilterToken(HANDLE ExistingTokenHandle, ULONG Flags, void* SidsToDisable,
                                             void* PrivilegesToDelete, void* RestrictedSids, HANDLE* NewTokenHandle)
{
    (void)ExistingTokenHandle;
    (void)Flags;
    (void)SidsToDisable;
    (void)PrivilegesToDelete;
    (void)RestrictedSids;
    if (NewTokenHandle == (HANDLE*)0)
        return NTSTATUS_INVALID_PARAMETER;
    *NewTokenHandle = (HANDLE)0xA00;
    return NTSTATUS_SUCCESS;
}

/* ------------------------------------------------------------------
 * NT mailslot + named-pipe + power-info + write-watch + profile
 * + PnP + VDM facades.
 * ------------------------------------------------------------------ */
__declspec(dllexport) NTSTATUS NtCreateMailslotFile(HANDLE* FileHandle, ULONG DesiredAccess, void* ObjectAttributes,
                                                    void* IoStatusBlock, ULONG CreateOptions, ULONG MailslotQuota,
                                                    ULONG MaximumMessageSize, void* ReadTimeout)
{
    (void)FileHandle;
    (void)DesiredAccess;
    (void)ObjectAttributes;
    (void)IoStatusBlock;
    (void)CreateOptions;
    (void)MailslotQuota;
    (void)MaximumMessageSize;
    (void)ReadTimeout;
    return (NTSTATUS)0xC0000002;
}

__declspec(dllexport) NTSTATUS NtCreateNamedPipeFile(HANDLE* FileHandle, ULONG DesiredAccess, void* ObjectAttributes,
                                                     void* IoStatusBlock, ULONG ShareAccess, ULONG CreateDisposition,
                                                     ULONG CreateOptions, BOOL NamedPipeType, BOOL ReadMode,
                                                     BOOL CompletionMode, ULONG MaximumInstances, ULONG InboundQuota,
                                                     ULONG OutboundQuota, void* DefaultTimeout)
{
    (void)FileHandle;
    (void)DesiredAccess;
    (void)ObjectAttributes;
    (void)IoStatusBlock;
    (void)ShareAccess;
    (void)CreateDisposition;
    (void)CreateOptions;
    (void)NamedPipeType;
    (void)ReadMode;
    (void)CompletionMode;
    (void)MaximumInstances;
    (void)InboundQuota;
    (void)OutboundQuota;
    (void)DefaultTimeout;
    return (NTSTATUS)0xC0000002;
}

__declspec(dllexport) NTSTATUS NtImpersonateClientOfPort(HANDLE PortHandle, void* Message)
{
    (void)PortHandle;
    (void)Message;
    return (NTSTATUS)0xC0000002;
}

__declspec(dllexport) NTSTATUS NtPowerInformation(ULONG InformationLevel, void* InputBuffer, ULONG InputBufferLength,
                                                  void* OutputBuffer, ULONG OutputBufferLength)
{
    (void)InformationLevel;
    (void)InputBuffer;
    (void)InputBufferLength;
    if (OutputBuffer != (void*)0 && OutputBufferLength > 0)
    {
        unsigned char* out = (unsigned char*)OutputBuffer;
        for (ULONG i = 0; i < OutputBufferLength; ++i)
            out[i] = 0;
    }
    return NTSTATUS_SUCCESS;
}

__declspec(dllexport) NTSTATUS NtGetWriteWatch(HANDLE ProcessHandle, ULONG Flags, void* BaseAddress, SIZE_T RegionSize,
                                               void** UserAddressArray, SIZE_T* EntriesInUserAddressArray,
                                               ULONG* Granularity)
{
    (void)ProcessHandle;
    (void)Flags;
    (void)BaseAddress;
    (void)RegionSize;
    (void)UserAddressArray;
    if (EntriesInUserAddressArray != (SIZE_T*)0)
        *EntriesInUserAddressArray = 0;
    if (Granularity != (ULONG*)0)
        *Granularity = 4096;
    return NTSTATUS_SUCCESS;
}

__declspec(dllexport) NTSTATUS NtResetWriteWatch(HANDLE ProcessHandle, void* BaseAddress, SIZE_T RegionSize)
{
    (void)ProcessHandle;
    (void)BaseAddress;
    (void)RegionSize;
    return NTSTATUS_SUCCESS;
}

__declspec(dllexport) NTSTATUS NtCreateProfile(HANDLE* ProfileHandle, HANDLE ProcessHandle, void* RangeBase,
                                               SIZE_T RangeSize, ULONG BucketSize, void* Buffer, ULONG BufferSize,
                                               ULONG ProfileSource, ULONG Affinity)
{
    (void)ProfileHandle;
    (void)ProcessHandle;
    (void)RangeBase;
    (void)RangeSize;
    (void)BucketSize;
    (void)Buffer;
    (void)BufferSize;
    (void)ProfileSource;
    (void)Affinity;
    return (NTSTATUS)0xC0000002;
}

__declspec(dllexport) NTSTATUS NtStartProfile(HANDLE ProfileHandle)
{
    (void)ProfileHandle;
    return (NTSTATUS)0xC0000002;
}

__declspec(dllexport) NTSTATUS NtStopProfile(HANDLE ProfileHandle)
{
    (void)ProfileHandle;
    return (NTSTATUS)0xC0000002;
}

__declspec(dllexport) NTSTATUS NtSetIntervalProfile(ULONG Interval, ULONG Source)
{
    (void)Interval;
    (void)Source;
    return NTSTATUS_SUCCESS;
}

__declspec(dllexport) NTSTATUS NtQueryIntervalProfile(ULONG ProfileSource, ULONG* Interval)
{
    (void)ProfileSource;
    if (Interval != (ULONG*)0)
        *Interval = 0;
    return NTSTATUS_SUCCESS;
}

__declspec(dllexport) NTSTATUS NtPlugPlayControl(ULONG PnPControlClass, void* PnPControlData,
                                                 ULONG PnPControlDataLength)
{
    (void)PnPControlClass;
    (void)PnPControlData;
    (void)PnPControlDataLength;
    return (NTSTATUS)0xC0000002;
}

__declspec(dllexport) NTSTATUS NtVdmControl(ULONG Service, void* ServiceData)
{
    (void)Service;
    (void)ServiceData;
    return (NTSTATUS)0xC0000002;
}

/* ------------------------------------------------------------------
 * NT additional VM + driver-load + system-power thunks.
 * ------------------------------------------------------------------ */
__declspec(dllexport) NTSTATUS NtFlushVirtualMemory(HANDLE ProcessHandle, void** BaseAddress, SIZE_T* RegionSize,
                                                    void* IoStatus)
{
    (void)ProcessHandle;
    (void)BaseAddress;
    (void)RegionSize;
    if (IoStatus != (void*)0)
    {
        unsigned long long* iosb = (unsigned long long*)IoStatus;
        iosb[0] = 0;
        iosb[1] = 0;
    }
    return NTSTATUS_SUCCESS;
}

__declspec(dllexport) NTSTATUS NtLockVirtualMemory(HANDLE ProcessHandle, void** BaseAddress, SIZE_T* RegionSize,
                                                   ULONG MapType)
{
    (void)ProcessHandle;
    (void)BaseAddress;
    (void)RegionSize;
    (void)MapType;
    return NTSTATUS_SUCCESS;
}

__declspec(dllexport) NTSTATUS NtUnlockVirtualMemory(HANDLE ProcessHandle, void** BaseAddress, SIZE_T* RegionSize,
                                                     ULONG MapType)
{
    (void)ProcessHandle;
    (void)BaseAddress;
    (void)RegionSize;
    (void)MapType;
    return NTSTATUS_SUCCESS;
}

__declspec(dllexport) NTSTATUS NtAreMappedFilesTheSame(void* File1MappedAsAnImage, void* File2MappedAsFile)
{
    (void)File1MappedAsAnImage;
    (void)File2MappedAsFile;
    return (NTSTATUS)0xC0000055; /* STATUS_NOT_SAME_DEVICE */
}

__declspec(dllexport) NTSTATUS NtLoadDriver(void* DriverServiceName)
{
    (void)DriverServiceName;
    /* Architectural note: drivers are kernel-internal, not
     * subsystem-internal. Userland never gets to load drivers.
     * STATUS_PRIVILEGE_NOT_HELD = 0xC0000061. */
    return (NTSTATUS)0xC0000061;
}

__declspec(dllexport) NTSTATUS NtUnloadDriver(void* DriverServiceName)
{
    (void)DriverServiceName;
    return (NTSTATUS)0xC0000061;
}

__declspec(dllexport) NTSTATUS NtShutdownSystem(ULONG Action)
{
    (void)Action;
    /* Power management is kernel-owned. */
    return (NTSTATUS)0xC0000061;
}

__declspec(dllexport) NTSTATUS NtRaiseHardError(NTSTATUS ErrorStatus, ULONG NumberOfParameters,
                                                ULONG UnicodeStringParameterMask, void* Parameters,
                                                ULONG ValidResponseOptions, ULONG* Response)
{
    (void)ErrorStatus;
    (void)NumberOfParameters;
    (void)UnicodeStringParameterMask;
    (void)Parameters;
    (void)ValidResponseOptions;
    if (Response != (ULONG*)0)
        *Response = 0;
    return NTSTATUS_SUCCESS;
}

__declspec(dllexport) NTSTATUS NtSetTimerResolution(ULONG DesiredResolution, BOOL SetResolution,
                                                    ULONG* CurrentResolution)
{
    (void)SetResolution;
    if (CurrentResolution != (ULONG*)0)
        *CurrentResolution = DesiredResolution;
    return NTSTATUS_SUCCESS;
}

__declspec(dllexport) NTSTATUS NtQueryTimerResolution(ULONG* MaximumTime, ULONG* MinimumTime, ULONG* CurrentTime)
{
    if (MaximumTime != (ULONG*)0)
        *MaximumTime = 156250;
    if (MinimumTime != (ULONG*)0)
        *MinimumTime = 5000;
    if (CurrentTime != (ULONG*)0)
        *CurrentTime = 100000;
    return NTSTATUS_SUCCESS;
}

__declspec(dllexport) ULONG NtGetCurrentProcessorNumber(void)
{
    return 0;
}
