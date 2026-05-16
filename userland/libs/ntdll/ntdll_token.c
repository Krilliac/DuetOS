#include "ntdll_internal.h"

/* ------------------------------------------------------------------
 * NT job-object surface — userland-only NotImpl stubs.
 *
 * Job objects are a Win32 mechanism for grouping processes for
 * resource limits + bulk termination. v0 has no job engine; the
 * kernel cap-set already handles the per-process limit cases we
 * care about. These stubs return STATUS_NOT_IMPLEMENTED so a
 * sandboxed PE checking for a job assignment gets a clean
 * answer.
 * ------------------------------------------------------------------ */
__declspec(dllexport) NTSTATUS NtCreateJobObject(HANDLE* JobHandle, ULONG DesiredAccess, void* ObjectAttributes)
{
    (void)DesiredAccess;
    (void)ObjectAttributes;
    if (JobHandle == (HANDLE*)0)
        return NTSTATUS_INVALID_PARAMETER;
    long long rv;
    __asm__ volatile("int $0x80" : "=a"(rv) : "a"((long long)163) : "memory"); /* SYS_JOB_CREATE */
    if (rv < 0)
        return (NTSTATUS)0xC0000002;
    *JobHandle = (HANDLE)rv;
    return NTSTATUS_SUCCESS;
}

__declspec(dllexport) NTSTATUS ZwCreateJobObject(HANDLE* JobHandle, ULONG DesiredAccess, void* ObjectAttributes)
{
    return NtCreateJobObject(JobHandle, DesiredAccess, ObjectAttributes);
}

__declspec(dllexport) NTSTATUS NtAssignProcessToJobObject(HANDLE JobHandle, HANDLE ProcessHandle)
{
    long long rv;
    __asm__ volatile("int $0x80"
                     : "=a"(rv)
                     : "a"((long long)164), /* SYS_JOB_ASSIGN */
                       "D"((long long)JobHandle), "S"((long long)ProcessHandle)
                     : "memory");
    if (rv < 0)
        return (NTSTATUS)0xC0000022; /* STATUS_ACCESS_DENIED */
    return NTSTATUS_SUCCESS;
}

__declspec(dllexport) NTSTATUS ZwAssignProcessToJobObject(HANDLE JobHandle, HANDLE ProcessHandle)
{
    return NtAssignProcessToJobObject(JobHandle, ProcessHandle);
}

__declspec(dllexport) NTSTATUS NtIsProcessInJob(HANDLE ProcessHandle, HANDLE JobHandle)
{
    /* Returns STATUS_PROCESS_IN_JOB (1) or STATUS_PROCESS_NOT_IN_JOB (0). */
    unsigned int out = 0;
    long long rv;
    __asm__ volatile("int $0x80"
                     : "=a"(rv)
                     : "a"((long long)165), /* SYS_JOB_IS_IN */
                       "D"((long long)JobHandle), "S"((long long)ProcessHandle), "d"((long long)&out)
                     : "memory");
    if (rv < 0)
        return (NTSTATUS)0xC0000008;
    return (NTSTATUS)(out ? 0x00000001 : 0x00000000);
}

__declspec(dllexport) NTSTATUS NtTerminateJobObject(HANDLE JobHandle, NTSTATUS ExitStatus)
{
    long long rv;
    __asm__ volatile("int $0x80"
                     : "=a"(rv)
                     : "a"((long long)166), /* SYS_JOB_TERMINATE */
                       "D"((long long)JobHandle), "S"((long long)ExitStatus)
                     : "memory");
    if (rv < 0)
        return (NTSTATUS)0xC0000008;
    return NTSTATUS_SUCCESS;
}

__declspec(dllexport) NTSTATUS ZwTerminateJobObject(HANDLE JobHandle, NTSTATUS ExitStatus)
{
    return NtTerminateJobObject(JobHandle, ExitStatus);
}

__declspec(dllexport) NTSTATUS NtQueryInformationJobObject(HANDLE JobHandle, ULONG JobObjectInformationClass,
                                                           void* JobObjectInformation, ULONG JobObjectInformationLength,
                                                           ULONG* ReturnLength)
{
    long long rv;
    __asm__ volatile("mov %4, %%r10\n\t"
                     "int $0x80"
                     : "=a"(rv)
                     : "a"((long long)167), /* SYS_JOB_QUERY */
                       "D"((long long)JobHandle), "S"((long long)JobObjectInformationClass),
                       "d"((long long)JobObjectInformation), "r"((long long)JobObjectInformationLength)
                     : "r10", "memory");
    if (rv < 0)
        return (NTSTATUS)0xC0000004; /* STATUS_INFO_LENGTH_MISMATCH */
    if (ReturnLength != (ULONG*)0)
        *ReturnLength = (ULONG)rv;
    return NTSTATUS_SUCCESS;
}

__declspec(dllexport) NTSTATUS ZwQueryInformationJobObject(HANDLE JobHandle, ULONG JobObjectInformationClass,
                                                           void* JobObjectInformation, ULONG JobObjectInformationLength,
                                                           ULONG* ReturnLength)
{
    return NtQueryInformationJobObject(JobHandle, JobObjectInformationClass, JobObjectInformation,
                                       JobObjectInformationLength, ReturnLength);
}

__declspec(dllexport) NTSTATUS NtSetInformationJobObject(HANDLE JobHandle, ULONG JobObjectInformationClass,
                                                         void* JobObjectInformation, ULONG JobObjectInformationLength)
{
    (void)JobHandle;
    (void)JobObjectInformationClass;
    (void)JobObjectInformation;
    (void)JobObjectInformationLength;
    return (NTSTATUS)0xC0000002;
}

__declspec(dllexport) NTSTATUS ZwSetInformationJobObject(HANDLE JobHandle, ULONG JobObjectInformationClass,
                                                         void* JobObjectInformation, ULONG JobObjectInformationLength)
{
    return NtSetInformationJobObject(JobHandle, JobObjectInformationClass, JobObjectInformation,
                                     JobObjectInformationLength);
}

/* NtTerminateJobObject / ZwTerminateJobObject / NtIsProcessInJob /
 * ZwIsProcessInJob now have real implementations earlier in this
 * file (backed by SYS_JOB_TERMINATE / SYS_JOB_IS_IN). The old
 * NotImpl stubs were removed; this comment is here so a grep for
 * the legacy stub returns the new spot. */

__declspec(dllexport) NTSTATUS ZwIsProcessInJob(HANDLE ProcessHandle, HANDLE JobHandle)
{
    return NtIsProcessInJob(ProcessHandle, JobHandle);
}

/* ------------------------------------------------------------------
 * Win32 token surface — userland-only static "system token".
 *
 * v0 has no auth model; every process runs with the same
 * effective identity. We expose a single-token handle range
 * (0xA00..0xA07 reserved; v0 returns 0xA00 unconditionally)
 * and answer NtQueryInformationToken with constant data
 * sufficient to keep malware-shape PEs probing the surface
 * happy:
 *
 *   - TokenUser (1)               -> S-1-5-21-1-1-1-1000
 *   - TokenIntegrityLevel (25)    -> S-1-16-12288 (High)
 *   - everything else             -> STATUS_NOT_IMPLEMENTED
 *
 * NtAdjustPrivilegesToken returns success no-op so callers
 * that try to enable SeDebugPrivilege get an "OK" — we have
 * no privilege model to actually grant or refuse.
 *
 * NtOpenProcessToken / NtOpenThreadToken always succeed and
 * hand back the same constant token handle. NtClose on this
 * handle range is a userland-only no-op (the static token is
 * never destroyed).
 * ------------------------------------------------------------------ */
#define DUETOS_TOKEN_HANDLE ((HANDLE)0xA00)

__declspec(dllexport) NTSTATUS NtOpenProcessToken(HANDLE ProcessHandle, ULONG DesiredAccess, HANDLE* TokenHandle)
{
    (void)ProcessHandle;
    (void)DesiredAccess;
    if (TokenHandle == (HANDLE*)0)
        return NTSTATUS_INVALID_PARAMETER;
    *TokenHandle = DUETOS_TOKEN_HANDLE;
    return NTSTATUS_SUCCESS;
}

__declspec(dllexport) NTSTATUS ZwOpenProcessToken(HANDLE ProcessHandle, ULONG DesiredAccess, HANDLE* TokenHandle)
{
    return NtOpenProcessToken(ProcessHandle, DesiredAccess, TokenHandle);
}

__declspec(dllexport) NTSTATUS NtOpenProcessTokenEx(HANDLE ProcessHandle, ULONG DesiredAccess, ULONG HandleAttributes,
                                                    HANDLE* TokenHandle)
{
    (void)HandleAttributes;
    return NtOpenProcessToken(ProcessHandle, DesiredAccess, TokenHandle);
}

__declspec(dllexport) NTSTATUS NtOpenThreadToken(HANDLE ThreadHandle, ULONG DesiredAccess, BOOL OpenAsSelf,
                                                 HANDLE* TokenHandle)
{
    (void)ThreadHandle;
    (void)DesiredAccess;
    (void)OpenAsSelf;
    if (TokenHandle == (HANDLE*)0)
        return NTSTATUS_INVALID_PARAMETER;
    /* No per-thread token impersonation in v0 — return the
     * same process-wide static token. */
    *TokenHandle = DUETOS_TOKEN_HANDLE;
    return NTSTATUS_SUCCESS;
}

__declspec(dllexport) NTSTATUS ZwOpenThreadToken(HANDLE ThreadHandle, ULONG DesiredAccess, BOOL OpenAsSelf,
                                                 HANDLE* TokenHandle)
{
    return NtOpenThreadToken(ThreadHandle, DesiredAccess, OpenAsSelf, TokenHandle);
}

__declspec(dllexport) NTSTATUS NtOpenThreadTokenEx(HANDLE ThreadHandle, ULONG DesiredAccess, BOOL OpenAsSelf,
                                                   ULONG HandleAttributes, HANDLE* TokenHandle)
{
    (void)HandleAttributes;
    return NtOpenThreadToken(ThreadHandle, DesiredAccess, OpenAsSelf, TokenHandle);
}

/* Static SID encoding: rev=1, sub_count, identifier_authority=6 bytes
 * BIG-ENDIAN (Windows quirk), then sub_count u32 sub-authorities LE. */
static const unsigned char k_user_sid[28] = {
    1,    5,             /* rev, sub_count */
    0,    0, 0, 0, 0, 5, /* IdentifierAuthority = 5 (NT_AUTHORITY) */
    21,   0, 0, 0,       /* sub-auth 0: 21 */
    1,    0, 0, 0,       /* sub-auth 1: 1 */
    1,    0, 0, 0,       /* sub-auth 2: 1 */
    1,    0, 0, 0,       /* sub-auth 3: 1 */
    0xE8, 3, 0, 0        /* sub-auth 4: 1000 */
};

static const unsigned char k_integrity_high_sid[12] = {
    1, 1,                 /* rev, sub_count */
    0, 0,    0, 0, 0, 16, /* IdentifierAuthority = 16 (MANDATORY_LABEL_AUTHORITY) */
    0, 0x30, 0, 0         /* SECURITY_MANDATORY_HIGH_RID = 0x3000 */
};

__declspec(dllexport) NTSTATUS NtQueryInformationToken(HANDLE TokenHandle, ULONG TokenInformationClass,
                                                       void* TokenInformation, ULONG TokenInformationLength,
                                                       ULONG* ReturnLength)
{
    (void)TokenHandle; /* v0 has only one token; ignore */
    /* TOKEN_INFORMATION_CLASS values: */
    enum
    {
        TokenUser = 1,
        TokenIntegrityLevel = 25
    };
    if (TokenInformationClass == TokenUser)
    {
        /* TOKEN_USER { SID_AND_ATTRIBUTES User; } where
         * SID_AND_ATTRIBUTES = { PSID Sid; DWORD Attributes; }.
         * On x64: 16-byte struct (8-byte ptr + 4-byte attr +
         * 4-byte padding), followed by the SID body. Layout:
         *   [0..16) SID_AND_ATTRIBUTES (Sid ptr -> body, attrs=0)
         *   [16..16+sizeof(sid)) SID body
         */
        const unsigned hdr = 16;
        const unsigned total = hdr + (unsigned)sizeof(k_user_sid);
        if (ReturnLength != (ULONG*)0)
            *ReturnLength = total;
        if (TokenInformationLength < total)
            return (NTSTATUS)0xC0000023; /* BUFFER_TOO_SMALL */
        unsigned char* out = (unsigned char*)TokenInformation;
        void** sid_slot = (void**)(out + 0);
        *sid_slot = (void*)(out + hdr);
        out[8] = 0;
        out[9] = 0;
        out[10] = 0;
        out[11] = 0;                     /* Attributes = 0 */
        for (unsigned i = 0; i < 4; ++i) /* trailing pad */
            out[12 + i] = 0;
        for (unsigned i = 0; i < sizeof(k_user_sid); ++i)
            out[hdr + i] = k_user_sid[i];
        return NTSTATUS_SUCCESS;
    }
    if (TokenInformationClass == TokenIntegrityLevel)
    {
        /* TOKEN_MANDATORY_LABEL { SID_AND_ATTRIBUTES Label; }
         * Same shape as TokenUser; SID body is shorter. */
        const unsigned hdr = 16;
        const unsigned total = hdr + (unsigned)sizeof(k_integrity_high_sid);
        if (ReturnLength != (ULONG*)0)
            *ReturnLength = total;
        if (TokenInformationLength < total)
            return (NTSTATUS)0xC0000023;
        unsigned char* out = (unsigned char*)TokenInformation;
        void** sid_slot = (void**)(out + 0);
        *sid_slot = (void*)(out + hdr);
        out[8] = 0;
        out[9] = 0;
        out[10] = 0;
        out[11] = 0x20; /* SE_GROUP_INTEGRITY = 0x20 */
        for (unsigned i = 0; i < 4; ++i)
            out[12 + i] = 0;
        for (unsigned i = 0; i < sizeof(k_integrity_high_sid); ++i)
            out[hdr + i] = k_integrity_high_sid[i];
        return NTSTATUS_SUCCESS;
    }
    return (NTSTATUS)0xC0000002; /* NOT_IMPLEMENTED */
}

__declspec(dllexport) NTSTATUS ZwQueryInformationToken(HANDLE TokenHandle, ULONG TokenInformationClass,
                                                       void* TokenInformation, ULONG TokenInformationLength,
                                                       ULONG* ReturnLength)
{
    return NtQueryInformationToken(TokenHandle, TokenInformationClass, TokenInformation, TokenInformationLength,
                                   ReturnLength);
}

/* NtAdjustPrivilegesToken — backed by SYS_TOKEN_ADJUST = 169.
 *
 * Translates the requested privilege adjustments into kernel
 * CapSet operations. Mappings (kernel/subsystems/win32/token_syscall.h):
 *   SeIncreaseBasePriorityPrivilege (LUID 14) → kCapSpawnThread
 *   SeBackupPrivilege               (LUID 17) → kCapFsRead
 *   SeRestorePrivilege              (LUID 18) → kCapFsWrite
 *   SeDebugPrivilege                (LUID 20) → kCapDebug
 *
 * Enabling a privilege whose mapped cap isn't held returns
 * STATUS_NOT_ALL_ASSIGNED (0x00000106) — NOT a failure, just an
 * "info" status. The kernel never adds caps from user space.
 * Disable / SE_PRIVILEGE_REMOVED / DisableAllPrivileges all drop
 * the mapped cap. Privileges with no mapping (SeShutdown, etc.)
 * are silently accepted.
 *
 * Returns: STATUS_SUCCESS (0), STATUS_NOT_ALL_ASSIGNED (0x106), or
 * STATUS_INVALID_PARAMETER on a malformed blob.
 */
__declspec(dllexport) NTSTATUS NtAdjustPrivilegesToken(HANDLE TokenHandle, BOOL DisableAllPrivileges, void* NewState,
                                                       ULONG BufferLength, void* PreviousState, ULONG* ReturnLength)
{
    (void)TokenHandle;
    long long rv;
    __asm__ volatile("mov %5, %%r10\n\t"
                     "mov %6, %%r8\n\t"
                     "int $0x80"
                     : "=a"(rv)
                     : "a"((long long)169), /* SYS_TOKEN_ADJUST */
                       "D"((long long)(DisableAllPrivileges ? 1 : 0)), "S"((long long)NewState),
                       "d"((long long)BufferLength), "r"((long long)PreviousState), "r"((long long)BufferLength)
                     : "r10", "r8", "memory");
    if (rv < 0)
        return NTSTATUS_INVALID_PARAMETER;
    if (ReturnLength != (ULONG*)0)
        *ReturnLength = BufferLength;
    if (rv == 1)
        return (NTSTATUS)0x00000106UL; /* STATUS_NOT_ALL_ASSIGNED — info, not failure */
    return NTSTATUS_SUCCESS;
}

__declspec(dllexport) NTSTATUS ZwAdjustPrivilegesToken(HANDLE TokenHandle, BOOL DisableAllPrivileges, void* NewState,
                                                       ULONG BufferLength, void* PreviousState, ULONG* ReturnLength)
{
    return NtAdjustPrivilegesToken(TokenHandle, DisableAllPrivileges, NewState, BufferLength, PreviousState,
                                   ReturnLength);
}

__declspec(dllexport) NTSTATUS NtFlushKey(HANDLE KeyHandle)
{
    long long status;
    /* SYS_REGISTRY = 130, op = 6 (kOpFlushKey). */
    __asm__ volatile("int $0x80"
                     : "=a"(status)
                     : "a"((long long)130), "D"((long long)6), "S"((long long)KeyHandle)
                     : "memory");
    return (NTSTATUS)status;
}

/* ------------------------------------------------------------------
 * NtEnumerateValueKey — walk values of an open key. v0 honours
 * KeyValueBasicInformation (class 0); other classes return
 * NotImpl. STATUS_NO_MORE_ENTRIES (0x8000001A) past end so for-
 * loops terminate cleanly.
 * ------------------------------------------------------------------ */
__declspec(dllexport) NTSTATUS NtEnumerateValueKey(HANDLE KeyHandle, ULONG Index, ULONG KeyValueInformationClass,
                                                   void* KeyValueInformation, ULONG Length, ULONG* ResultLength)
{
    if (KeyValueInformationClass != 0)
        return (NTSTATUS)0xC0000002;
    if (KeyValueInformation == (void*)0)
        return NTSTATUS_INVALID_PARAMETER;
    unsigned char stage[96];
    long long status;
    __asm__ volatile("mov %4, %%r10\n\t"
                     "mov %5, %%r8\n\t"
                     "int $0x80"
                     : "=a"(status)
                     : "a"((long long)130), "D"((long long)7), "S"((long long)KeyHandle), "d"((long long)Index),
                       "r"((long long)stage), "r"((long long)sizeof(stage))
                     : "r10", "r8", "memory");
    if (status != 0)
        return (NTSTATUS)status;
    const unsigned title_index = (unsigned)*(unsigned*)(stage + 0);
    const unsigned type = (unsigned)*(unsigned*)(stage + 4);
    const unsigned name_chars = (unsigned)*(unsigned*)(stage + 12);
    const ULONG name_bytes = (ULONG)(name_chars * 2);
    const ULONG total = 12 + name_bytes;
    if (ResultLength != (ULONG*)0)
        *ResultLength = total;
    if (Length < total)
        return (NTSTATUS)0xC0000023;
    unsigned char* out = (unsigned char*)KeyValueInformation;
    *(unsigned*)(out + 0) = title_index;
    *(unsigned*)(out + 4) = type;
    *(unsigned*)(out + 8) = name_bytes;
    const char* src = (const char*)(stage + 32);
    wchar_t16* dst = (wchar_t16*)(out + 12);
    for (unsigned i = 0; i < name_chars; ++i)
        dst[i] = (unsigned char)src[i];
    return NTSTATUS_SUCCESS;
}

__declspec(dllexport) NTSTATUS ZwEnumerateValueKey(HANDLE KeyHandle, ULONG Index, ULONG KeyValueInformationClass,
                                                   void* KeyValueInformation, ULONG Length, ULONG* ResultLength)
{
    return NtEnumerateValueKey(KeyHandle, Index, KeyValueInformationClass, KeyValueInformation, Length, ResultLength);
}

/* NtQueryKey — KeyFullInformation only. Kernel-side SYS_REGISTRY
 * op=8 returns 5 u64 fields: SubKeys / Values / MaxNameLen /
 * MaxValueNameLen / MaxValueDataLen (40 bytes total). The thunk
 * maps these onto KEY_FULL_INFORMATION's offsets. ClassOffset /
 * ClassLength / MaxClassLen stay zero — v0 has no class strings. */
__declspec(dllexport) NTSTATUS NtQueryKey(HANDLE KeyHandle, ULONG KeyInformationClass, void* KeyInformation,
                                          ULONG Length, ULONG* ResultLength)
{
    if (KeyInformationClass != 2)
        return (NTSTATUS)0xC0000002;
    if (KeyInformation == (void*)0)
        return NTSTATUS_INVALID_PARAMETER;
    const ULONG total = 44;
    if (ResultLength != (ULONG*)0)
        *ResultLength = total;
    if (Length < total)
        return (NTSTATUS)0xC0000023;
    unsigned long long fields[5] = {0, 0, 0, 0, 0};
    long long status;
    __asm__ volatile("mov %3, %%r10\n\t"
                     "int $0x80"
                     : "=a"(status)
                     : "a"((long long)130), "D"((long long)8), "S"((long long)KeyHandle), "r"((long long)40),
                       "d"((long long)fields)
                     : "r10", "memory");
    if (status != 0)
        return (NTSTATUS)status;
    unsigned char* out = (unsigned char*)KeyInformation;
    for (unsigned i = 0; i < total; ++i)
        out[i] = 0;
    /* KEY_FULL_INFORMATION fields:
     *   [20..24) SubKeys
     *   [24..28) MaxNameLen      (chars)
     *   [28..32) MaxClassLen     (chars, always 0 in v0)
     *   [32..36) Values
     *   [36..40) MaxValueNameLen (chars)
     *   [40..44) MaxValueDataLen (bytes)
     */
    *(unsigned*)(out + 20) = (unsigned)fields[0];
    *(unsigned*)(out + 24) = (unsigned)fields[2];
    *(unsigned*)(out + 32) = (unsigned)fields[1];
    *(unsigned*)(out + 36) = (unsigned)fields[3];
    *(unsigned*)(out + 40) = (unsigned)fields[4];
    return NTSTATUS_SUCCESS;
}

__declspec(dllexport) NTSTATUS ZwQueryKey(HANDLE KeyHandle, ULONG KeyInformationClass, void* KeyInformation,
                                          ULONG Length, ULONG* ResultLength)
{
    return NtQueryKey(KeyHandle, KeyInformationClass, KeyInformation, Length, ResultLength);
}

/* NtCreateKey / NtDeleteKey — NotImpl facades. v0 has no
 * mutable key tree; only mutable VALUES on existing static keys
 * (via NtSetValueKey). */
__declspec(dllexport) NTSTATUS NtCreateKey(HANDLE* KeyHandle, ULONG DesiredAccess, void* ObjectAttributes,
                                           ULONG TitleIndex, void* Class, ULONG CreateOptions, ULONG* Disposition)
{
    (void)KeyHandle;
    (void)DesiredAccess;
    (void)ObjectAttributes;
    (void)TitleIndex;
    (void)Class;
    (void)CreateOptions;
    (void)Disposition;
    return (NTSTATUS)0xC0000002;
}

__declspec(dllexport) NTSTATUS NtDeleteKey(HANDLE KeyHandle)
{
    (void)KeyHandle;
    return (NTSTATUS)0xC0000002;
}

/* NtEnumerateKey — list direct children of an open key. v0 honours
 * KeyBasicInformation (class 0); other classes return NotImpl.
 * STATUS_NO_MORE_ENTRIES (0x8000001A) past end so for-loops
 * terminate cleanly. The kernel side (SYS_REGISTRY op=9) walks the
 * static tree's prefix + terminal entries to derive direct
 * children. */
__declspec(dllexport) NTSTATUS NtEnumerateKey(HANDLE KeyHandle, ULONG Index, ULONG KeyInformationClass,
                                              void* KeyInformation, ULONG Length, ULONG* ResultLength)
{
    if (KeyInformationClass != 0)
        return (NTSTATUS)0xC0000002;
    if (KeyInformation == (void*)0)
        return NTSTATUS_INVALID_PARAMETER;
    unsigned char stage[96];
    long long status;
    __asm__ volatile("mov %4, %%r10\n\t"
                     "mov %5, %%r8\n\t"
                     "int $0x80"
                     : "=a"(status)
                     : "a"((long long)130), "D"((long long)9), "S"((long long)KeyHandle), "d"((long long)Index),
                       "r"((long long)stage), "r"((long long)sizeof(stage))
                     : "r10", "r8", "memory");
    if (status != 0)
    {
        if (ResultLength != (ULONG*)0)
            *ResultLength = 0;
        return (NTSTATUS)status;
    }
    /* KEY_BASIC_INFORMATION layout:
     *   LARGE_INTEGER LastWriteTime;  (8 bytes)
     *   ULONG TitleIndex;             (4 bytes)
     *   ULONG NameLength;             (4 bytes, byte count of UTF-16)
     *   WCHAR Name[1];                (UTF-16 LE name body, no NUL)
     */
    const unsigned name_chars = (unsigned)*(unsigned*)(stage + 16);
    const ULONG name_bytes = (ULONG)(name_chars * 2);
    const ULONG total = 16 + name_bytes;
    if (ResultLength != (ULONG*)0)
        *ResultLength = total;
    if (Length < total)
        return (NTSTATUS)0xC0000023;
    unsigned char* out = (unsigned char*)KeyInformation;
    /* LastWriteTime — zero in v0 (no mtime tracking). */
    *(unsigned long long*)(out + 0) = 0;
    *(unsigned*)(out + 8) = (unsigned)Index;
    *(unsigned*)(out + 12) = name_bytes;
    const char* src = (const char*)(stage + 32);
    wchar_t16* dst = (wchar_t16*)(out + 16);
    for (unsigned i = 0; i < name_chars; ++i)
        dst[i] = (unsigned char)src[i];
    return NTSTATUS_SUCCESS;
}

__declspec(dllexport) NTSTATUS ZwEnumerateKey(HANDLE KeyHandle, ULONG Index, ULONG KeyInformationClass,
                                              void* KeyInformation, ULONG Length, ULONG* ResultLength)
{
    return NtEnumerateKey(KeyHandle, Index, KeyInformationClass, KeyInformation, Length, ResultLength);
}

/* ------------------------------------------------------------------
 * NtCreateFile / NtOpenFile / NtReadFile / NtWriteFile — Win32 PE
 * file I/O via the NT-namespace API.
 *
 * These thunks are pure ABI adapters: they translate Win32-shaped
 * arguments (OBJECT_ATTRIBUTES, IO_STATUS_BLOCK, CreateDisposition)
 * into the kernel's native SYS_FILE_OPEN / SYS_FILE_CREATE /
 * SYS_FILE_READ / SYS_FILE_WRITE syscalls. The kernel is the
 * authority on what's allowed (kCapFsRead / kCapFsWrite gates
 * apply) — the NT layer cannot bypass them.
 *
 * Architectural rule: Win32 subsystem is for executing PE
 * binaries, not for driving DuetOS. Every effect a PE has on the
 * filesystem goes through the same kernel mediation a native
 * DuetOS program does.
 *
 * v0 honours CreateDisposition = FILE_OPEN, FILE_CREATE, and
 * FILE_OPEN_IF. SUPERSEDE / OVERWRITE / OVERWRITE_IF return
 * STATUS_NOT_IMPLEMENTED.
 * ------------------------------------------------------------------ */
/* Forward declaration — definition lives further down with the
 * NtQueryAttributesFile thunks. The helper is shared between the
 * path-based file-stat surface and the NtCreateFile / NtOpenFile
 * adapter family. */
static int ExtractAsciiPathFromObjectAttributes(void* ObjectAttributes, char* out, unsigned cap, unsigned* out_len);

__declspec(dllexport) NTSTATUS NtCreateFile(HANDLE* FileHandle, ULONG DesiredAccess, void* ObjectAttributes,
                                            void* IoStatusBlock, void* AllocationSize, ULONG FileAttributes,
                                            ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions,
                                            void* EaBuffer, ULONG EaLength)
{
    (void)DesiredAccess;
    (void)AllocationSize;
    (void)FileAttributes;
    (void)ShareAccess;
    (void)EaBuffer;
    (void)EaLength;
    if (FileHandle == (HANDLE*)0)
        return NTSTATUS_INVALID_PARAMETER;
    char path[256];
    unsigned path_len = 0;
    if (!ExtractAsciiPathFromObjectAttributes(ObjectAttributes, path, sizeof(path), &path_len))
        return NTSTATUS_INVALID_PARAMETER;
    /* CreateOptions:
     *   FILE_DIRECTORY_FILE     = 0x00000001 — caller wants a dir
     *                             handle for NtQueryDirectoryFile
     *   FILE_NON_DIRECTORY_FILE = 0x00000040 — must NOT be a dir
     * If FILE_DIRECTORY_FILE is set, route to SYS_DIR_OPEN and
     * return the resulting kWin32DirBase handle. NtQueryDirectoryFile
     * recognises this handle range. */
    long long handle = -1;
    long long status = 0;
    if ((CreateOptions & 0x00000001) != 0)
    {
        if (CreateDisposition != 1 /* OPEN */ && CreateDisposition != 3 /* OPEN_IF */)
            return NTSTATUS_INVALID_PARAMETER;
        /* SYS_DIR_OPEN = 154. */
        __asm__ volatile("int $0x80" : "=a"(handle) : "a"((long long)154), "D"((long long)path) : "memory");
        if (handle < 0)
            return (NTSTATUS)0xC0000034ULL; /* OBJECT_NAME_NOT_FOUND */
        *FileHandle = (HANDLE)handle;
        if (IoStatusBlock != (void*)0)
        {
            unsigned long long* iosb = (unsigned long long*)IoStatusBlock;
            iosb[0] = 0;
            iosb[1] = 1; /* FILE_OPENED */
        }
        return NTSTATUS_SUCCESS;
    }
    /* CreateDisposition codes:
     *   0 = SUPERSEDE       (NotImpl in v0)
     *   1 = FILE_OPEN
     *   2 = FILE_CREATE
     *   3 = FILE_OPEN_IF
     *   4 = FILE_OVERWRITE  (NotImpl)
     *   5 = FILE_OVERWRITE_IF (NotImpl) */
    if (CreateDisposition == 1 /* OPEN */ || CreateDisposition == 3 /* OPEN_IF */)
    {
        /* SYS_FILE_OPEN = 20. */
        __asm__ volatile("int $0x80"
                         : "=a"(handle)
                         : "a"((long long)20), "D"((long long)path), "S"((long long)(path_len + 1))
                         : "memory");
        if (handle < 0 && CreateDisposition == 3)
        {
            /* OPEN_IF: open failed -> create. */
            __asm__ volatile("mov %4, %%r10\n\t"
                             "int $0x80"
                             : "=a"(handle)
                             : "a"((long long)44), "D"((long long)path), "S"((long long)(path_len + 1)),
                               "d"((long long)0), "r"((long long)0)
                             : "r10", "memory");
        }
        if (handle < 0)
            status = (long long)0xC0000034ULL; /* OBJECT_NAME_NOT_FOUND */
    }
    else if (CreateDisposition == 2 /* CREATE */)
    {
        /* SYS_FILE_CREATE = 44. */
        __asm__ volatile("mov %4, %%r10\n\t"
                         "int $0x80"
                         : "=a"(handle)
                         : "a"((long long)44), "D"((long long)path), "S"((long long)(path_len + 1)), "d"((long long)0),
                           "r"((long long)0)
                         : "r10", "memory");
        if (handle < 0)
            status = (long long)0xC0000035ULL; /* OBJECT_NAME_COLLISION */
    }
    else
    {
        return (NTSTATUS)0xC0000002; /* NOT_IMPLEMENTED */
    }
    if (handle < 0)
        return (NTSTATUS)status;
    *FileHandle = (HANDLE)handle;
    /* IO_STATUS_BLOCK is { Status; Information } — write success
     * + a per-disposition Information value:
     *   FILE_OPEN     -> FILE_OPENED        (1)
     *   FILE_CREATE   -> FILE_CREATED       (2)
     *   FILE_OPEN_IF  -> caller-discovered  (1 or 2; we report 1) */
    if (IoStatusBlock != (void*)0)
    {
        unsigned long long* iosb = (unsigned long long*)IoStatusBlock;
        iosb[0] = 0; /* NTSTATUS_SUCCESS */
        iosb[1] = (CreateDisposition == 2) ? 2 : 1;
    }
    return NTSTATUS_SUCCESS;
}

__declspec(dllexport) NTSTATUS ZwCreateFile(HANDLE* FileHandle, ULONG DesiredAccess, void* ObjectAttributes,
                                            void* IoStatusBlock, void* AllocationSize, ULONG FileAttributes,
                                            ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions,
                                            void* EaBuffer, ULONG EaLength)
{
    return NtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes,
                        ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);
}

__declspec(dllexport) NTSTATUS NtOpenFile(HANDLE* FileHandle, ULONG DesiredAccess, void* ObjectAttributes,
                                          void* IoStatusBlock, ULONG ShareAccess, ULONG OpenOptions)
{
    (void)DesiredAccess;
    (void)ShareAccess;
    (void)OpenOptions;
    if (FileHandle == (HANDLE*)0)
        return NTSTATUS_INVALID_PARAMETER;
    char path[256];
    unsigned path_len = 0;
    if (!ExtractAsciiPathFromObjectAttributes(ObjectAttributes, path, sizeof(path), &path_len))
        return NTSTATUS_INVALID_PARAMETER;
    long long handle;
    /* SYS_FILE_OPEN = 20. */
    __asm__ volatile("int $0x80"
                     : "=a"(handle)
                     : "a"((long long)20), "D"((long long)path), "S"((long long)(path_len + 1))
                     : "memory");
    if (handle < 0)
        return (NTSTATUS)0xC0000034;
    *FileHandle = (HANDLE)handle;
    if (IoStatusBlock != (void*)0)
    {
        unsigned long long* iosb = (unsigned long long*)IoStatusBlock;
        iosb[0] = 0;
        iosb[1] = 1; /* FILE_OPENED */
    }
    return NTSTATUS_SUCCESS;
}

__declspec(dllexport) NTSTATUS ZwOpenFile(HANDLE* FileHandle, ULONG DesiredAccess, void* ObjectAttributes,
                                          void* IoStatusBlock, ULONG ShareAccess, ULONG OpenOptions)
{
    return NtOpenFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, ShareAccess, OpenOptions);
}

__declspec(dllexport) NTSTATUS NtReadFile(HANDLE FileHandle, HANDLE Event, void* ApcRoutine, void* ApcContext,
                                          void* IoStatusBlock, void* Buffer, ULONG Length, void* ByteOffset, void* Key)
{
    (void)Event;
    (void)ApcRoutine;
    (void)ApcContext;
    (void)Key;
    /* ByteOffset is honoured only for the special "no-cursor-update"
     * marker (-1, -1) which means "read at current cursor". v0
     * always uses the per-handle cursor — explicit-offset reads
     * would need a SYS_FILE_PREAD which doesn't exist yet. Sub-
     * GAP. */
    (void)ByteOffset;
    long long n;
    /* SYS_FILE_READ = 21. */
    __asm__ volatile("int $0x80"
                     : "=a"(n)
                     : "a"((long long)21), "D"((long long)FileHandle), "S"((long long)Buffer), "d"((long long)Length)
                     : "memory");
    if (n < 0)
    {
        if (IoStatusBlock != (void*)0)
        {
            unsigned long long* iosb = (unsigned long long*)IoStatusBlock;
            iosb[0] = 0xC0000008; /* INVALID_HANDLE */
            iosb[1] = 0;
        }
        return (NTSTATUS)0xC0000008;
    }
    if (IoStatusBlock != (void*)0)
    {
        unsigned long long* iosb = (unsigned long long*)IoStatusBlock;
        iosb[0] = 0;
        iosb[1] = (unsigned long long)n;
    }
    if (n == 0)
        return (NTSTATUS)0xC0000011; /* END_OF_FILE */
    return NTSTATUS_SUCCESS;
}

__declspec(dllexport) NTSTATUS ZwReadFile(HANDLE FileHandle, HANDLE Event, void* ApcRoutine, void* ApcContext,
                                          void* IoStatusBlock, void* Buffer, ULONG Length, void* ByteOffset, void* Key)
{
    return NtReadFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, Buffer, Length, ByteOffset, Key);
}

__declspec(dllexport) NTSTATUS NtWriteFile(HANDLE FileHandle, HANDLE Event, void* ApcRoutine, void* ApcContext,
                                           void* IoStatusBlock, void* Buffer, ULONG Length, void* ByteOffset, void* Key)
{
    (void)Event;
    (void)ApcRoutine;
    (void)ApcContext;
    (void)Key;
    (void)ByteOffset;
    long long n;
    /* SYS_FILE_WRITE = 43. */
    __asm__ volatile("int $0x80"
                     : "=a"(n)
                     : "a"((long long)43), "D"((long long)FileHandle), "S"((long long)Buffer), "d"((long long)Length)
                     : "memory");
    if (n < 0)
    {
        if (IoStatusBlock != (void*)0)
        {
            unsigned long long* iosb = (unsigned long long*)IoStatusBlock;
            iosb[0] = 0xC0000008;
            iosb[1] = 0;
        }
        return (NTSTATUS)0xC0000008;
    }
    if (IoStatusBlock != (void*)0)
    {
        unsigned long long* iosb = (unsigned long long*)IoStatusBlock;
        iosb[0] = 0;
        iosb[1] = (unsigned long long)n;
    }
    return NTSTATUS_SUCCESS;
}

__declspec(dllexport) NTSTATUS ZwWriteFile(HANDLE FileHandle, HANDLE Event, void* ApcRoutine, void* ApcContext,
                                           void* IoStatusBlock, void* Buffer, ULONG Length, void* ByteOffset, void* Key)
{
    return NtWriteFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, Buffer, Length, ByteOffset, Key);
}

/* ------------------------------------------------------------------
 * NtQueryInformationFile / NtSetInformationFile —
 * handle-based file metadata read + write.
 *
 * The Win32 NT API multiplexes many information classes through
 * one syscall. v0 covers the two everyone touches:
 *   - FileStandardInformation   (5)  -> file size + dir flag
 *   - FilePositionInformation   (14) -> read/write cursor
 * Setters honour FilePositionInformation via SYS_FILE_SEEK.
 * Other classes return STATUS_NOT_IMPLEMENTED so callers fall
 * back rather than misinterpret zero-filled output.
 *
 * Architectural rule: the kernel is the authority on file state;
 * these thunks only translate the Win32 ABI shape.
 * ------------------------------------------------------------------ */
__declspec(dllexport) NTSTATUS NtQueryInformationFile(HANDLE FileHandle, void* IoStatusBlock, void* FileInformation,
                                                      ULONG Length, ULONG FileInformationClass)
{
    if (FileInformation == (void*)0)
        return NTSTATUS_INVALID_PARAMETER;
    if (FileInformationClass == 5 /* FileStandardInformation */)
    {
        if (Length < 24)
            return (NTSTATUS)0xC0000004;
        long long size_out = 0;
        long long status;
        __asm__ volatile("int $0x80"
                         : "=a"(status)
                         : "a"((long long)24), "D"((long long)FileHandle), "S"((long long)&size_out)
                         : "memory");
        if (status != 0)
            return (NTSTATUS)0xC0000008;
        unsigned char* out = (unsigned char*)FileInformation;
        const unsigned long long aligned = ((unsigned long long)size_out + 4095ULL) & ~4095ULL;
        for (unsigned i = 0; i < 8; ++i)
            out[i] = (unsigned char)((aligned >> (i * 8)) & 0xFF);
        for (unsigned i = 0; i < 8; ++i)
            out[8 + i] = (unsigned char)(((unsigned long long)size_out >> (i * 8)) & 0xFF);
        out[16] = 1;
        out[17] = 0;
        out[18] = 0;
        out[19] = 0;
        out[20] = 0;
        out[21] = 0;
        out[22] = 0;
        out[23] = 0;
        if (IoStatusBlock != (void*)0)
        {
            unsigned long long* iosb = (unsigned long long*)IoStatusBlock;
            iosb[0] = 0;
            iosb[1] = 24;
        }
        return NTSTATUS_SUCCESS;
    }
    if (FileInformationClass == 14 /* FilePositionInformation */)
    {
        if (Length < 8)
            return (NTSTATUS)0xC0000004;
        long long cur;
        __asm__ volatile("int $0x80"
                         : "=a"(cur)
                         : "a"((long long)23), "D"((long long)FileHandle), "S"((long long)0), "d"((long long)1)
                         : "memory");
        if (cur < 0)
            return (NTSTATUS)0xC0000008;
        unsigned char* out = (unsigned char*)FileInformation;
        unsigned long long ucur = (unsigned long long)cur;
        for (unsigned i = 0; i < 8; ++i)
            out[i] = (unsigned char)((ucur >> (i * 8)) & 0xFF);
        if (IoStatusBlock != (void*)0)
        {
            unsigned long long* iosb = (unsigned long long*)IoStatusBlock;
            iosb[0] = 0;
            iosb[1] = 8;
        }
        return NTSTATUS_SUCCESS;
    }
    return (NTSTATUS)0xC0000002;
}

__declspec(dllexport) NTSTATUS ZwQueryInformationFile(HANDLE FileHandle, void* IoStatusBlock, void* FileInformation,
                                                      ULONG Length, ULONG FileInformationClass)
{
    return NtQueryInformationFile(FileHandle, IoStatusBlock, FileInformation, Length, FileInformationClass);
}

__declspec(dllexport) NTSTATUS NtSetInformationFile(HANDLE FileHandle, void* IoStatusBlock, void* FileInformation,
                                                    ULONG Length, ULONG FileInformationClass)
{
    if (FileInformation == (void*)0)
        return NTSTATUS_INVALID_PARAMETER;
    if (FileInformationClass == 14 /* FilePositionInformation */)
    {
        if (Length < 8)
            return (NTSTATUS)0xC0000004;
        unsigned char* in = (unsigned char*)FileInformation;
        unsigned long long pos = 0;
        for (unsigned i = 0; i < 8; ++i)
            pos |= ((unsigned long long)in[i]) << (i * 8);
        long long rv;
        __asm__ volatile("int $0x80"
                         : "=a"(rv)
                         : "a"((long long)23), "D"((long long)FileHandle), "S"((long long)pos), "d"((long long)0)
                         : "memory");
        if (rv < 0)
            return (NTSTATUS)0xC0000008;
        if (IoStatusBlock != (void*)0)
        {
            unsigned long long* iosb = (unsigned long long*)IoStatusBlock;
            iosb[0] = 0;
            iosb[1] = 0;
        }
        return NTSTATUS_SUCCESS;
    }
    if (FileInformationClass == 4 /* FileBasicInformation */)
    {
        /* FILE_BASIC_INFORMATION: 4 LARGE_INTEGER timestamps +
         * u32 attributes + u32 pad. v0 doesn't track times on
         * disk (FAT32 cluster-time updates aren't wired through
         * the SYS_FILE_WRITE path), so the safe shape is
         * accept-as-success — the caller's expectation is "the
         * timestamps are now what I set" but most callers only
         * use this to bump LastAccess / LastWrite which we'd
         * silently lose anyway. Length must cover at least the
         * 4 timestamps (32 bytes). Sub-GAP: timestamps unobserved. */
        if (Length < 32)
            return (NTSTATUS)0xC0000004;
        if (IoStatusBlock != (void*)0)
        {
            unsigned long long* iosb = (unsigned long long*)IoStatusBlock;
            iosb[0] = 0;
            iosb[1] = Length;
        }
        return NTSTATUS_SUCCESS;
    }
    /* FileEndOfFileInformation (20) — truncate-by-handle.
     * FileRenameInformation (10) — rename-by-handle.
     * FileDispositionInformation (13) — delete-on-close.
     * Each needs a new kernel syscall (SYS_FILE_TRUNCATE,
     * handle->path resolution, per-handle flags) — separate slices. */
    return (NTSTATUS)0xC0000002;
}

__declspec(dllexport) NTSTATUS ZwSetInformationFile(HANDLE FileHandle, void* IoStatusBlock, void* FileInformation,
                                                    ULONG Length, ULONG FileInformationClass)
{
    return NtSetInformationFile(FileHandle, IoStatusBlock, FileInformation, Length, FileInformationClass);
}

__declspec(dllexport) NTSTATUS NtFlushBuffersFile(HANDLE FileHandle, void* IoStatusBlock)
{
    (void)FileHandle;
    if (IoStatusBlock != (void*)0)
    {
        unsigned long long* iosb = (unsigned long long*)IoStatusBlock;
        iosb[0] = 0;
        iosb[1] = 0;
    }
    return NTSTATUS_SUCCESS;
}

__declspec(dllexport) NTSTATUS ZwFlushBuffersFile(HANDLE FileHandle, void* IoStatusBlock)
{
    return NtFlushBuffersFile(FileHandle, IoStatusBlock);
}

__declspec(dllexport) NTSTATUS NtFsControlFile(HANDLE FileHandle, HANDLE Event, void* ApcRoutine, void* ApcContext,
                                               void* IoStatusBlock, ULONG IoControlCode, void* InputBuffer,
                                               ULONG InputBufferLength, void* OutputBuffer, ULONG OutputBufferLength)
{
    (void)FileHandle;
    (void)Event;
    (void)ApcRoutine;
    (void)ApcContext;
    (void)IoControlCode;
    (void)InputBuffer;
    (void)InputBufferLength;
    (void)OutputBuffer;
    (void)OutputBufferLength;
    if (IoStatusBlock != (void*)0)
    {
        unsigned long long* iosb = (unsigned long long*)IoStatusBlock;
        iosb[0] = 0xC0000002;
        iosb[1] = 0;
    }
    return (NTSTATUS)0xC0000002;
}

__declspec(dllexport) NTSTATUS ZwFsControlFile(HANDLE FileHandle, HANDLE Event, void* ApcRoutine, void* ApcContext,
                                               void* IoStatusBlock, ULONG IoControlCode, void* InputBuffer,
                                               ULONG InputBufferLength, void* OutputBuffer, ULONG OutputBufferLength)
{
    return NtFsControlFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, IoControlCode, InputBuffer,
                           InputBufferLength, OutputBuffer, OutputBufferLength);
}

__declspec(dllexport) NTSTATUS NtDeviceIoControlFile(HANDLE FileHandle, HANDLE Event, void* ApcRoutine,
                                                     void* ApcContext, void* IoStatusBlock, ULONG IoControlCode,
                                                     void* InputBuffer, ULONG InputBufferLength, void* OutputBuffer,
                                                     ULONG OutputBufferLength)
{
    return NtFsControlFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, IoControlCode, InputBuffer,
                           InputBufferLength, OutputBuffer, OutputBufferLength);
}

__declspec(dllexport) NTSTATUS ZwDeviceIoControlFile(HANDLE FileHandle, HANDLE Event, void* ApcRoutine,
                                                     void* ApcContext, void* IoStatusBlock, ULONG IoControlCode,
                                                     void* InputBuffer, ULONG InputBufferLength, void* OutputBuffer,
                                                     ULONG OutputBufferLength)
{
    return NtDeviceIoControlFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, IoControlCode, InputBuffer,
                                 InputBufferLength, OutputBuffer, OutputBufferLength);
}

/* ------------------------------------------------------------------
 * NtQueryAttributesFile / NtQueryFullAttributesFile — path-based
 * file stat. Both forward to SYS_FILE_QUERY_ATTRIBUTES (151).
 *
 * NtQueryAttributesFile fills a 40-byte FILE_BASIC_INFORMATION
 * (Times×4 + Attrs); NtQueryFullAttributesFile fills the 56-byte
 * FILE_NETWORK_OPEN_INFORMATION which adds AllocationSize +
 * EndOfFile. The kernel writes the larger struct; the Basic
 * variant truncates locally.
 * ------------------------------------------------------------------ */
static int ExtractAsciiPathFromObjectAttributes(void* ObjectAttributes, char* out, unsigned cap, unsigned* out_len)
{
    if (ObjectAttributes == (void*)0)
        return 0;
    unsigned char* base = (unsigned char*)ObjectAttributes;
    UNICODE_STRING* name = *(UNICODE_STRING**)(base + 16);
    if (name == (UNICODE_STRING*)0 || name->Buffer == (wchar_t16*)0)
        return 0;
    const unsigned chars = (unsigned)(name->Length / 2);
    unsigned start = 0;
    if (chars >= 4 && name->Buffer[0] == '\\' && name->Buffer[1] == '?' && name->Buffer[2] == '?' &&
        name->Buffer[3] == '\\')
        start = 4;
    if (chars - start + 1 > cap)
        return 0;
    for (unsigned i = start; i < chars; ++i)
    {
        unsigned short w = name->Buffer[i];
        out[i - start] = (w <= 0x7F) ? (char)w : '?';
    }
    out[chars - start] = 0;
    if (out_len != (unsigned*)0)
        *out_len = chars - start;
    return 1;
}

__declspec(dllexport) NTSTATUS NtQueryAttributesFile(void* ObjectAttributes, void* FileInformation)
{
    char path[256];
    unsigned path_len = 0;
    if (!ExtractAsciiPathFromObjectAttributes(ObjectAttributes, path, sizeof(path), &path_len))
        return NTSTATUS_INVALID_PARAMETER;
    if (FileInformation == (void*)0)
        return NTSTATUS_INVALID_PARAMETER;
    unsigned char stage[56];
    long long status;
    __asm__ volatile("mov %4, %%r10\n\t"
                     "int $0x80"
                     : "=a"(status)
                     : "a"((long long)151), "D"((long long)path), "S"((long long)path_len), "d"((long long)stage),
                       "r"((long long)sizeof(stage))
                     : "r10", "memory");
    if (status != 0)
        return (NTSTATUS)status;
    /* FILE_BASIC_INFORMATION: 4×FILETIME + Attributes + 4-byte pad. */
    unsigned char* out = (unsigned char*)FileInformation;
    for (unsigned i = 0; i < 32; ++i)
        out[i] = stage[i];
    for (unsigned i = 0; i < 4; ++i)
        out[32 + i] = stage[48 + i];
    out[36] = 0;
    out[37] = 0;
    out[38] = 0;
    out[39] = 0;
    return NTSTATUS_SUCCESS;
}

__declspec(dllexport) NTSTATUS ZwQueryAttributesFile(void* ObjectAttributes, void* FileInformation)
{
    return NtQueryAttributesFile(ObjectAttributes, FileInformation);
}

__declspec(dllexport) NTSTATUS NtQueryFullAttributesFile(void* ObjectAttributes, void* FileInformation)
{
    char path[256];
    unsigned path_len = 0;
    if (!ExtractAsciiPathFromObjectAttributes(ObjectAttributes, path, sizeof(path), &path_len))
        return NTSTATUS_INVALID_PARAMETER;
    if (FileInformation == (void*)0)
        return NTSTATUS_INVALID_PARAMETER;
    long long status;
    __asm__ volatile("mov %4, %%r10\n\t"
                     "int $0x80"
                     : "=a"(status)
                     : "a"((long long)151), "D"((long long)path), "S"((long long)path_len),
                       "d"((long long)FileInformation), "r"((long long)56)
                     : "r10", "memory");
    return (NTSTATUS)status;
}

__declspec(dllexport) NTSTATUS ZwQueryFullAttributesFile(void* ObjectAttributes, void* FileInformation)
{
    return NtQueryFullAttributesFile(ObjectAttributes, FileInformation);
}

/* ------------------------------------------------------------------
 * NtCreateThreadEx — same-process thread create.
 *
 * Win32 NT signature:
 *   NTSTATUS NtCreateThreadEx(
 *     PHANDLE     ThreadHandle,
 *     ACCESS_MASK DesiredAccess,
 *     POBJECT_ATTRIBUTES ObjectAttributes,
 *     HANDLE      ProcessHandle,
 *     PVOID       StartRoutine,
 *     PVOID       Argument,
 *     ULONG       CreateFlags,
 *     ULONG_PTR   ZeroBits,
 *     SIZE_T      StackSize,
 *     SIZE_T      MaximumStackSize,
 *     PPS_ATTRIBUTE_LIST AttributeList);
 *
 * v0 honours ProcessHandle == NtCurrentProcess() (-1) only —
 * cross-process thread injection (the substrate of process
 * hollowing's kick-off path) needs cross-AS handle plumbing
 * we don't have on the SYS_THREAD_CREATE side yet. CreateFlags
 * other than 0 (no CREATE_SUSPENDED yet — needs an extra
 * arg to SchedCreateUser to start the task pre-suspended)
 * return NOT_IMPLEMENTED.
 * ------------------------------------------------------------------ */
__declspec(dllexport) NTSTATUS NtCreateThreadEx(HANDLE* ThreadHandle, ULONG DesiredAccess, void* ObjectAttributes,
                                                HANDLE hProcess, void* StartRoutine, void* Argument, ULONG CreateFlags,
                                                SIZE_T ZeroBits, SIZE_T StackSize, SIZE_T MaximumStackSize,
                                                void* AttributeList)
{
    (void)DesiredAccess;
    (void)ObjectAttributes;
    (void)ZeroBits;
    (void)StackSize;
    (void)MaximumStackSize;
    (void)AttributeList;
    if (hProcess != (HANDLE)-1)
        return NTSTATUS_NOT_IMPLEMENTED;
    if (CreateFlags != 0)
        return NTSTATUS_NOT_IMPLEMENTED;
    long long handle;
    /* SYS_THREAD_CREATE = 45. Args: rdi = start RIP, rsi = param. */
    __asm__ volatile("int $0x80"
                     : "=a"(handle)
                     : "a"((long long)45), "D"((long long)StartRoutine), "S"((long long)Argument)
                     : "memory");
    if (handle < 0)
        return NTSTATUS_NO_MEMORY;
    if (ThreadHandle != (HANDLE*)0)
        *ThreadHandle = (HANDLE)handle;
    return NTSTATUS_SUCCESS;
}

__declspec(dllexport) NTSTATUS ZwCreateThreadEx(HANDLE* ThreadHandle, ULONG DesiredAccess, void* ObjectAttributes,
                                                HANDLE hProcess, void* StartRoutine, void* Argument, ULONG CreateFlags,
                                                SIZE_T ZeroBits, SIZE_T StackSize, SIZE_T MaximumStackSize,
                                                void* AttributeList)
{
    return NtCreateThreadEx(ThreadHandle, DesiredAccess, ObjectAttributes, hProcess, StartRoutine, Argument,
                            CreateFlags, ZeroBits, StackSize, MaximumStackSize, AttributeList);
}

/* ------------------------------------------------------------------
 * NtQueryInformationProcess — read per-process state.
 *
 * Win32 NT signature:
 *   NTSTATUS NtQueryInformationProcess(
 *     HANDLE ProcessHandle,
 *     ULONG  ProcessInformationClass,
 *     PVOID  ProcessInformation,
 *     ULONG  ProcessInformationLength,
 *     PULONG ReturnLength);
 *
 * v0 honours the ProcessBasicInformation class only — that's
 * what every real Win32 caller asks for first (PEB pointer +
 * UniqueProcessId discovery). Other classes return
 * STATUS_NOT_IMPLEMENTED so callers fall back rather than
 * misinterpret zeros.
 *
 * The buffer layout the kernel writes is exactly the 48-byte
 * PROCESS_BASIC_INFORMATION on x64 — no userland repacking.
 * ------------------------------------------------------------------ */
__declspec(dllexport) NTSTATUS NtQueryInformationProcess(HANDLE ProcessHandle, ULONG ProcessInformationClass,
                                                         void* ProcessInformation, ULONG ProcessInformationLength,
                                                         ULONG* ReturnLength)
{
    long long status;
    /* SYS_PROCESS_QUERY_INFO = 147.
     * Args: rdi=handle, rsi=class, rdx=buf, r10=cap, r8=&retlen. */
    __asm__ volatile("mov %4, %%r10\n\t"
                     "mov %5, %%r8\n\t"
                     "int $0x80"
                     : "=a"(status)
                     : "a"((long long)147), "D"((long long)ProcessHandle), "S"((long long)ProcessInformationClass),
                       "r"((long long)ProcessInformationLength), "r"((long long)ReturnLength),
                       "d"((long long)ProcessInformation)
                     : "r10", "r8", "memory");
    return (NTSTATUS)status;
}

__declspec(dllexport) NTSTATUS ZwQueryInformationProcess(HANDLE ProcessHandle, ULONG ProcessInformationClass,
                                                         void* ProcessInformation, ULONG ProcessInformationLength,
                                                         ULONG* ReturnLength)
{
    return NtQueryInformationProcess(ProcessHandle, ProcessInformationClass, ProcessInformation,
                                     ProcessInformationLength, ReturnLength);
}
