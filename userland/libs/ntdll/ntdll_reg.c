#include "ntdll_internal.h"

/* ------------------------------------------------------------------
 * Registry — NtOpenKey + NtQueryValueKey
 *
 * These wrap SYS_REGISTRY (= 130) which is op-multiplexed by rdi:
 *   op=1 (kOpOpenKey)    rsi=parent, rdx=ASCII-path, r10=&out_handle
 *   op=2 (kOpClose)      rsi=handle  — already reachable via NtClose
 *                                       (SYS_FILE_CLOSE dispatches by
 *                                        handle range)
 *   op=3 (kOpQueryValue) rsi=handle, rdx=ASCII-name, r10=buf,
 *                        r8=buf_cap, r9=&packed (size:32 | type:32)
 *
 * Win32 callers pass UNICODE_STRING + OBJECT_ATTRIBUTES; the kernel
 * registry only takes ASCII paths. The thunks below do the conversion
 * inline (low-byte strip; non-ASCII becomes '?'). The path also gets
 * the leading "\\Registry\\Machine\\" / "\\Registry\\User\\" prefix
 * stripped so the kernel sees the same path advapi32 already serves
 * (HKLM\\Software\\... etc. — the leading-prefix-and-HKEY pair is
 * how Windows turns a UNICODE path into an HKEY-rooted lookup).
 * ------------------------------------------------------------------ */

/* UNICODE_STRING reuses the typedef declared earlier in this TU
 * (line ~408). The OBJECT_ATTRIBUTES struct is registry-specific
 * so it lives next to the registry thunks instead. */
typedef struct _OBJECT_ATTRIBUTES
{
    ULONG Length;               /* sizeof(OBJECT_ATTRIBUTES) — 48 on x64 */
    HANDLE RootDirectory;       /* parent HKEY (predefined or previously-opened) */
    UNICODE_STRING* ObjectName; /* full registry path; sometimes NULL */
    ULONG Attributes;
    void* SecurityDescriptor;
    void* SecurityQualityOfService;
} OBJECT_ATTRIBUTES;

/* KEY_VALUE_INFORMATION_CLASS values used by NtQueryValueKey. v0
 * supports only KeyValuePartialInformation (the one MSVC PE startup
 * + advapi32 + every common Windows-side caller asks for). */
#define KeyValueBasicInformation 0
#define KeyValueFullInformation 1
#define KeyValuePartialInformation 2

#define NTSTATUS_OBJECT_NAME_NOT_FOUND 0xC0000034UL
#define NTSTATUS_INVALID_HANDLE 0xC0000008UL
#define NTSTATUS_BUFFER_TOO_SMALL 0xC0000023UL

#define HKEY_CLASSES_ROOT_NT ((HANDLE)(unsigned long long)0x80000000ULL)
#define HKEY_CURRENT_USER_NT ((HANDLE)(unsigned long long)0x80000001ULL)
#define HKEY_LOCAL_MACHINE_NT ((HANDLE)(unsigned long long)0x80000002ULL)
#define HKEY_USERS_NT ((HANDLE)(unsigned long long)0x80000003ULL)

static unsigned ntdll_strlen_a(const char* s)
{
    unsigned n = 0;
    while (s && s[n])
        ++n;
    return n;
}

/* ASCII case-insensitive prefix match. Returns the length of the
 * prefix on success (so the caller can advance past it) or 0 on
 * miss. `prefix` is NUL-terminated; `s` is a wide buffer of length
 * `s_chars` and is treated as ASCII (low-byte strip). */
static unsigned ntdll_w_starts_with_ci(const wchar_t16* s, unsigned s_chars, const char* prefix)
{
    const unsigned plen = ntdll_strlen_a(prefix);
    if (s_chars < plen)
        return 0;
    for (unsigned i = 0; i < plen; ++i)
    {
        char a = (char)(s[i] & 0xFF);
        char b = prefix[i];
        if (a >= 'A' && a <= 'Z')
            a = (char)(a + ('a' - 'A'));
        if (b >= 'A' && b <= 'Z')
            b = (char)(b + ('a' - 'A'));
        if (a != b)
            return 0;
    }
    return plen;
}

/* Translate a Windows-shape registry path into a (parent_hkey,
 * ASCII subkey) pair the kernel-side SYS_REGISTRY recognises.
 *
 * Input contract (from OBJECT_ATTRIBUTES):
 *   - If RootDirectory is one of the predefined HKEY sentinels,
 *     the ObjectName is the subkey path with no \Registry\
 *     prefix.
 *   - If RootDirectory is NULL, the ObjectName must start with
 *     \Registry\Machine\ (→ HKLM) or \Registry\User\ (→ HKCU).
 *     We strip the prefix and pick the matching sentinel.
 *
 * Output: writes ASCII path into `dst` (cap bytes), returns the
 * resolved parent HKEY sentinel (or NULL on parse failure).
 */
static HANDLE ntdll_reg_resolve(HANDLE root_dir, const UNICODE_STRING* name, char* dst, unsigned cap)
{
    if (cap == 0 || dst == (char*)0 || name == (const UNICODE_STRING*)0 || name->Buffer == (wchar_t16*)0)
        return (HANDLE)0;

    const unsigned chars = (unsigned)(name->Length / 2);
    const wchar_t16* s = name->Buffer;
    unsigned skip = 0;
    HANDLE parent = root_dir;

    if (root_dir == (HANDLE)0)
    {
        unsigned p = ntdll_w_starts_with_ci(s, chars, "\\Registry\\Machine\\");
        if (p != 0)
        {
            parent = HKEY_LOCAL_MACHINE_NT;
            skip = p;
        }
        else if ((p = ntdll_w_starts_with_ci(s, chars, "\\Registry\\User\\")) != 0)
        {
            parent = HKEY_CURRENT_USER_NT;
            skip = p;
        }
        else
        {
            return (HANDLE)0; /* unrecognised root — only Machine/User in v0 */
        }
    }

    unsigned o = 0;
    for (unsigned i = skip; i < chars; ++i)
    {
        if (o + 1 >= cap)
            return (HANDLE)0; /* path too long for the kernel buffer */
        unsigned short w = s[i];
        char c = (w <= 0x7F) ? (char)w : '?';
        dst[o++] = c;
    }
    dst[o] = 0;
    return parent;
}

__declspec(dllexport) NTSTATUS NtOpenKey(HANDLE* KeyHandle, ULONG DesiredAccess, OBJECT_ATTRIBUTES* ObjectAttributes)
{
    (void)DesiredAccess;
    if (KeyHandle == (HANDLE*)0 || ObjectAttributes == (OBJECT_ATTRIBUTES*)0)
        return NTSTATUS_INVALID_PARAMETER;

    char path[256];
    HANDLE parent =
        ntdll_reg_resolve(ObjectAttributes->RootDirectory, ObjectAttributes->ObjectName, path, sizeof(path));
    if (parent == (HANDLE)0)
        return NTSTATUS_OBJECT_NAME_NOT_FOUND;

    long long out_handle = 0;
    long long status;
    /* SYS_REGISTRY = 130, op = 1 (kOpOpenKey).
     * Operand indexing: %0=status(rax), %1=130(rax-in), %2=1(rdi),
     * %3=parent(rsi), %4=&out_handle(r), %5=path(rdx). */
    __asm__ volatile("mov %4, %%r10\n\t"
                     "int $0x80"
                     : "=a"(status)
                     : "a"((long long)130), "D"((long long)1), "S"((long long)parent), "r"((long long)&out_handle),
                       "d"((long long)path)
                     : "r10", "memory");
    if (status != 0)
        return (NTSTATUS)status;
    *KeyHandle = (HANDLE)out_handle;
    return NTSTATUS_SUCCESS;
}

/* Same surface, narrowed: OpenKeyEx adds an Attributes ULONG before
 * RootDirectory in some headers but the runtime ABI (3 args) is
 * identical for our purposes — just forward. */
__declspec(dllexport) NTSTATUS NtOpenKeyEx(HANDLE* KeyHandle, ULONG DesiredAccess, OBJECT_ATTRIBUTES* ObjectAttributes,
                                           ULONG OpenOptions)
{
    (void)OpenOptions;
    return NtOpenKey(KeyHandle, DesiredAccess, ObjectAttributes);
}

/* ------------------------------------------------------------------
 * NtOpenProcess — open a handle to another process by PID.
 *
 * Win32 NT signature:
 *   NTSTATUS NtOpenProcess(
 *     PHANDLE             ProcessHandle,
 *     ACCESS_MASK         DesiredAccess,
 *     POBJECT_ATTRIBUTES  ObjectAttributes,  // initialised but unused
 *     PCLIENT_ID          ClientId);          // { HANDLE Pid; HANDLE Tid; }
 *
 * v0 only honours the PID; thread-targeted opens (Pid == 0) are
 * STATUS_INVALID_PARAMETER. ACCESS_MASK + ObjectAttributes are
 * accepted but ignored — we have no ACL machinery, and the
 * kernel-side cap-gates via kCapDebug.
 * ------------------------------------------------------------------ */
typedef struct
{
    HANDLE Pid;
    HANDLE Tid;
} CLIENT_ID;

__declspec(dllexport) NTSTATUS NtOpenProcess(HANDLE* ProcessHandle, ULONG DesiredAccess,
                                             OBJECT_ATTRIBUTES* ObjectAttributes, CLIENT_ID* ClientId)
{
    (void)DesiredAccess;
    (void)ObjectAttributes;
    if (ProcessHandle == (HANDLE*)0 || ClientId == (CLIENT_ID*)0)
        return NTSTATUS_INVALID_PARAMETER;
    if (ClientId->Pid == (HANDLE)0)
        return NTSTATUS_INVALID_PARAMETER;
    long long handle = 0;
    /* SYS_PROCESS_OPEN = 131; rdi = pid. rax = handle (0 on failure). */
    __asm__ volatile("int $0x80" : "=a"(handle) : "a"((long long)131), "D"((long long)ClientId->Pid) : "memory");
    if (handle == 0)
        return (NTSTATUS)NTSTATUS_INVALID_PARAMETER;
    *ProcessHandle = (HANDLE)handle;
    return NTSTATUS_SUCCESS;
}

/* ------------------------------------------------------------------
 * NtOpenThread — open a handle to a target thread by TID.
 *
 * Win32 NT signature:
 *   NTSTATUS NtOpenThread(
 *     PHANDLE             ThreadHandle,
 *     ACCESS_MASK         DesiredAccess,
 *     POBJECT_ATTRIBUTES  ObjectAttributes,
 *     PCLIENT_ID          ClientId);  // { HANDLE Pid; HANDLE Tid; }
 *
 * v0 only honours Tid; the Pid field is accepted but unused — the
 * kernel resolves Tid against every live task regardless of PID.
 * ACCESS_MASK + ObjectAttributes are accepted but ignored (no
 * ACL machinery; the kernel cap-gates via kCapDebug). The
 * returned handle plugs into NtSuspendThread / NtResumeThread /
 * NtGetContextThread / NtSetContextThread for cross-process
 * thread inspection — completes the malware "thread hijack"
 * pipeline against a target outside the caller's process.
 * ------------------------------------------------------------------ */
__declspec(dllexport) NTSTATUS NtOpenThread(HANDLE* ThreadHandle, ULONG DesiredAccess,
                                            OBJECT_ATTRIBUTES* ObjectAttributes, CLIENT_ID* ClientId)
{
    (void)DesiredAccess;
    (void)ObjectAttributes;
    if (ThreadHandle == (HANDLE*)0 || ClientId == (CLIENT_ID*)0)
        return NTSTATUS_INVALID_PARAMETER;
    if (ClientId->Tid == (HANDLE)0)
        return NTSTATUS_INVALID_PARAMETER;
    long long handle = 0;
    /* SYS_THREAD_OPEN = 139; rdi = tid. rax = handle (0 on failure). */
    __asm__ volatile("int $0x80" : "=a"(handle) : "a"((long long)139), "D"((long long)ClientId->Tid) : "memory");
    if (handle == 0)
        return (NTSTATUS)NTSTATUS_INVALID_PARAMETER;
    *ThreadHandle = (HANDLE)handle;
    return NTSTATUS_SUCCESS;
}

/* ------------------------------------------------------------------
 * NtCreateSection — allocate an anonymous (pagefile-backed)
 * section of `*MaximumSize` bytes.
 *
 * Win32 NT signature:
 *   NTSTATUS NtCreateSection(
 *     PHANDLE             SectionHandle,
 *     ACCESS_MASK         DesiredAccess,
 *     POBJECT_ATTRIBUTES  ObjectAttributes,
 *     PLARGE_INTEGER      MaximumSize,           // bytes
 *     ULONG               SectionPageProtection, // PAGE_*
 *     ULONG               AllocationAttributes,
 *     HANDLE              FileHandle);            // 0 = anonymous
 *
 * v0 only honours anonymous (FileHandle == 0); file-backed
 * sections return STATUS_NOT_IMPLEMENTED. AllocationAttributes
 * + ObjectAttributes are accepted but ignored (no SEC_RESERVE
 * separation; every section is committed on creation).
 * ------------------------------------------------------------------ */
__declspec(dllexport) NTSTATUS NtCreateSection(HANDLE* SectionHandle, ULONG DesiredAccess,
                                               OBJECT_ATTRIBUTES* ObjectAttributes, unsigned long long* MaximumSize,
                                               ULONG SectionPageProtection, ULONG AllocationAttributes,
                                               HANDLE FileHandle)
{
    (void)DesiredAccess;
    (void)ObjectAttributes;
    (void)AllocationAttributes;
    if (SectionHandle == (HANDLE*)0 || MaximumSize == (unsigned long long*)0)
        return NTSTATUS_INVALID_PARAMETER;
    if (FileHandle != (HANDLE)0)
        return (NTSTATUS)0xC0000002UL; /* STATUS_NOT_IMPLEMENTED */
    long long handle = 0;
    /* SYS_SECTION_CREATE = 140; rdi = size, rsi = page_protect. */
    __asm__ volatile("int $0x80"
                     : "=a"(handle)
                     : "a"((long long)140), "D"(*MaximumSize), "S"((long long)SectionPageProtection)
                     : "memory");
    if (handle == 0)
        return NTSTATUS_INVALID_PARAMETER;
    *SectionHandle = (HANDLE)handle;
    return NTSTATUS_SUCCESS;
}

/* ------------------------------------------------------------------
 * NtMapViewOfSection — install a view of `SectionHandle` into
 * the address space of `ProcessHandle` at `*BaseAddress`.
 *
 * Win32 NT signature:
 *   NTSTATUS NtMapViewOfSection(
 *     HANDLE    SectionHandle,
 *     HANDLE    ProcessHandle,        // -1 = NtCurrentProcess()
 *     PVOID*    BaseAddress,           // in/out, 0 hint = kernel-picks
 *     ULONG_PTR ZeroBits,
 *     SIZE_T    CommitSize,
 *     PLARGE_INTEGER SectionOffset,    // v0: must be 0
 *     PSIZE_T   ViewSize,              // in/out, kernel writes actual
 *     SECTION_INHERIT InheritDisposition,
 *     ULONG     AllocationType,
 *     ULONG     Win32Protect);         // PAGE_*
 *
 * v0 honours the section→AS mapping but ignores ZeroBits,
 * CommitSize, SectionOffset (must be 0), InheritDisposition,
 * and AllocationType. The kernel always maps the section's
 * full size; partial views land later.
 * ------------------------------------------------------------------ */
__declspec(dllexport) NTSTATUS NtMapViewOfSection(HANDLE SectionHandle, HANDLE ProcessHandle, void** BaseAddress,
                                                  unsigned long long ZeroBits, unsigned long long CommitSize,
                                                  unsigned long long* SectionOffset, unsigned long long* ViewSize,
                                                  unsigned long Inherit, unsigned long AllocationType,
                                                  unsigned long Win32Protect)
{
    (void)ZeroBits;
    (void)CommitSize;
    (void)Inherit;
    (void)AllocationType;
    if (BaseAddress == (void**)0 || ViewSize == (unsigned long long*)0)
        return NTSTATUS_INVALID_PARAMETER;
    if (SectionOffset != (unsigned long long*)0 && *SectionOffset != 0)
        return NTSTATUS_INVALID_PARAMETER;
    long long status = 0;
    register long long r10 __asm__("r10") = (long long)ViewSize;
    register long long r8 __asm__("r8") = (long long)Win32Protect;
    /* SYS_SECTION_MAP = 141; rdi = sect, rsi = proc, rdx = &base, r10 = &size, r8 = protect. */
    __asm__ volatile("int $0x80"
                     : "=a"(status)
                     : "a"((long long)141), "D"((long long)SectionHandle), "S"((long long)ProcessHandle),
                       "d"((long long)BaseAddress), "r"(r10), "r"(r8)
                     : "memory");
    return (NTSTATUS)status;
}

/* ------------------------------------------------------------------
 * NtUnmapViewOfSection — tear down a view previously installed
 * by NtMapViewOfSection. The kernel walks every live section
 * pool entry to find which one's first frame lives at
 * BaseAddress in the target AS, unmaps that section's view,
 * and drops one section refcount.
 * ------------------------------------------------------------------ */
__declspec(dllexport) NTSTATUS NtUnmapViewOfSection(HANDLE ProcessHandle, void* BaseAddress)
{
    long long status = 0;
    /* SYS_SECTION_UNMAP = 142; rdi = proc, rsi = base. */
    __asm__ volatile("int $0x80"
                     : "=a"(status)
                     : "a"((long long)142), "D"((long long)ProcessHandle), "S"((long long)BaseAddress)
                     : "memory");
    return (NTSTATUS)status;
}

/* ------------------------------------------------------------------
 * NtDeleteFile — delete a file by OBJECT_ATTRIBUTES path.
 *
 * Win32 NT signature:
 *   NTSTATUS NtDeleteFile(POBJECT_ATTRIBUTES ObjectAttributes);
 *
 * v0 narrows the wide ObjectName to ASCII, drops the
 * "\??\" / "\DosDevices\" Win32 namespace prefix if present
 * (callers built on top of RtlDosPathNameToNtPathName_U
 * routinely emit it), and forwards the result to
 * SYS_FILE_UNLINK. Names exceeding 255 chars truncate.
 * ------------------------------------------------------------------ */
__declspec(dllexport) NTSTATUS NtDeleteFile(OBJECT_ATTRIBUTES* ObjectAttributes)
{
    if (ObjectAttributes == (OBJECT_ATTRIBUTES*)0)
        return NTSTATUS_INVALID_PARAMETER;
    UNICODE_STRING* name = ObjectAttributes->ObjectName;
    if (name == (UNICODE_STRING*)0 || name->Buffer == (wchar_t16*)0)
        return NTSTATUS_INVALID_PARAMETER;
    char ascii[256];
    int wlen = (int)(name->Length / 2);
    int start = 0;
    /* Strip "\??\" and "\DosDevices\" Win32-namespace prefixes. */
    if (wlen >= 4 && name->Buffer[0] == '\\' && name->Buffer[1] == '?' && name->Buffer[2] == '?' &&
        name->Buffer[3] == '\\')
        start = 4;
    int i = 0;
    while (i < 255 && (start + i) < wlen)
    {
        ascii[i] = (char)(name->Buffer[start + i] & 0xFF);
        ++i;
    }
    ascii[i] = '\0';
    long long status;
    __asm__ volatile("int $0x80"
                     : "=a"(status)
                     : "a"((long long)143), /* SYS_FILE_UNLINK */
                       "D"((long long)ascii), "S"((long long)i)
                     : "memory");
    return (NTSTATUS)status;
}

/* ------------------------------------------------------------------
 * NtReadVirtualMemory — read another process's user memory through
 * a previously-opened process handle.
 *
 * Win32 NT signature:
 *   NTSTATUS NtReadVirtualMemory(
 *     HANDLE   ProcessHandle,
 *     PVOID    BaseAddress,        // VA inside target's AS
 *     PVOID    Buffer,             // VA inside caller's AS
 *     SIZE_T   NumberOfBytesToRead,
 *     PSIZE_T  NumberOfBytesRead);  // optional out-pointer
 *
 * Backed by SYS_PROCESS_VM_READ (132). The kernel caps any single
 * call at kSyscallProcessVmMax (16 KiB); larger transfers chunk on
 * this side. v0 does not surface STATUS_PARTIAL_COPY — a partial
 * transfer returns STATUS_ACCESS_VIOLATION, with the
 * NumberOfBytesRead out-pointer carrying the actual count moved.
 * ------------------------------------------------------------------ */
__declspec(dllexport) NTSTATUS NtReadVirtualMemory(HANDLE ProcessHandle, void* BaseAddress, void* Buffer,
                                                   unsigned long long NumberOfBytesToRead,
                                                   unsigned long long* NumberOfBytesRead)
{
    long long status;
    /* SYS_PROCESS_VM_READ = 132. Args: rdi=handle, rsi=target_va,
     * rdx=caller_buf, r10=len, r8=out_count_va. */
    __asm__ volatile("mov %5, %%r10\n\t"
                     "mov %6, %%r8\n\t"
                     "int $0x80"
                     : "=a"(status)
                     : "a"((long long)132), "D"((long long)ProcessHandle), "S"((long long)BaseAddress),
                       "d"((long long)Buffer), "r"((long long)NumberOfBytesToRead), "r"((long long)NumberOfBytesRead)
                     : "r10", "r8", "memory");
    return (NTSTATUS)status;
}

/* NtWriteVirtualMemory — symmetric to the read path.
 *
 * Win32 NT signature:
 *   NTSTATUS NtWriteVirtualMemory(
 *     HANDLE   ProcessHandle,
 *     PVOID    BaseAddress,
 *     PVOID    Buffer,
 *     SIZE_T   NumberOfBytesToWrite,
 *     PSIZE_T  NumberOfBytesWritten);
 *
 * Backed by SYS_PROCESS_VM_WRITE (133). Same cap, same partial-
 * copy contract.  */
__declspec(dllexport) NTSTATUS NtWriteVirtualMemory(HANDLE ProcessHandle, void* BaseAddress, void* Buffer,
                                                    unsigned long long NumberOfBytesToWrite,
                                                    unsigned long long* NumberOfBytesWritten)
{
    long long status;
    __asm__ volatile("mov %5, %%r10\n\t"
                     "mov %6, %%r8\n\t"
                     "int $0x80"
                     : "=a"(status)
                     : "a"((long long)133), "D"((long long)ProcessHandle), "S"((long long)BaseAddress),
                       "d"((long long)Buffer), "r"((long long)NumberOfBytesToWrite),
                       "r"((long long)NumberOfBytesWritten)
                     : "r10", "r8", "memory");
    return (NTSTATUS)status;
}

/* NtQueryVirtualMemory — probe one VA in a target process.
 *
 * Win32 NT signature (we serve only MemoryBasicInformation = 0):
 *   NTSTATUS NtQueryVirtualMemory(
 *     HANDLE   ProcessHandle,
 *     PVOID    BaseAddress,
 *     int      MemoryInformationClass,  // 0 = MemoryBasicInformation
 *     PVOID    MemoryInformation,        // MEMORY_BASIC_INFORMATION
 *     SIZE_T   MemoryInformationLength,
 *     PSIZE_T  ReturnLength);            // optional
 *
 * Backed by SYS_PROCESS_VM_QUERY (134). v0 returns a single-page
 * region (RegionSize = 4096) — Windows would coalesce adjacent
 * pages with identical attributes, but the v0 region table doesn't
 * track per-page protection, so we can't honestly coalesce.
 * STATUS_INVALID_INFO_CLASS for any class != MemoryBasicInformation.
 * ------------------------------------------------------------------ */
/* ------------------------------------------------------------------
 * NtSuspendThread / NtResumeThread — bump or decrement a target
 * thread's suspend count.
 *
 * Win32 NT signature:
 *   NTSTATUS NtSuspendThread(HANDLE ThreadHandle, PULONG PrevCount);
 *   NTSTATUS NtResumeThread(HANDLE ThreadHandle, PULONG PrevCount);
 *
 * Both back onto SYS_THREAD_SUSPEND / SYS_THREAD_RESUME. v0 only
 * accepts caller-local thread handles (kWin32ThreadBase + idx in
 * the calling Process's win32_threads[] table — i.e. the same
 * handles CreateThread returned). Cross-process thread suspend
 * needs NtOpenThread, which is its own slice.
 *
 * Kernel returns rax = previous suspend count (a small non-
 * negative number) on success or a negative errno on any error.
 * We map every negative value to STATUS_INVALID_HANDLE because
 * that is the only NTSTATUS this v0 surface distinguishes today.
 * ------------------------------------------------------------------ */
__declspec(dllexport) NTSTATUS NtSuspendThread(HANDLE ThreadHandle, unsigned long* PreviousSuspendCount)
{
    long long rc;
    /* SYS_THREAD_SUSPEND = 135 */
    __asm__ volatile("int $0x80" : "=a"(rc) : "a"((long long)135), "D"((long long)ThreadHandle) : "memory");
    if (rc < 0)
        return (NTSTATUS)0xC0000008L; /* STATUS_INVALID_HANDLE */
    if (PreviousSuspendCount != (unsigned long*)0)
        *PreviousSuspendCount = (unsigned long)rc;
    return NTSTATUS_SUCCESS;
}

__declspec(dllexport) NTSTATUS NtResumeThread(HANDLE ThreadHandle, unsigned long* PreviousSuspendCount)
{
    long long rc;
    /* SYS_THREAD_RESUME = 136 */
    __asm__ volatile("int $0x80" : "=a"(rc) : "a"((long long)136), "D"((long long)ThreadHandle) : "memory");
    if (rc < 0)
        return (NTSTATUS)0xC0000008L;
    if (PreviousSuspendCount != (unsigned long*)0)
        *PreviousSuspendCount = (unsigned long)rc;
    return NTSTATUS_SUCCESS;
}

/* NtAlertResumeThread is documented as "resume thread and signal
 * any pending alert." v0 has no alert/APC machinery, so the
 * resume part is the entire effect — alias to NtResumeThread. */
__declspec(dllexport) NTSTATUS NtAlertResumeThread(HANDLE ThreadHandle, unsigned long* PreviousSuspendCount)
{
    return NtResumeThread(ThreadHandle, PreviousSuspendCount);
}

/* ------------------------------------------------------------------
 * NtGetContextThread / NtSetContextThread — read or rewrite a
 * suspended target's user-mode register state. Backs the
 * malware "thread hijack" pattern's CONTEXT-manipulation step
 * (the freeze half lives in NtSuspendThread, the patch-bytes
 * half in NtWriteVirtualMemory).
 *
 * Win32 NT signature:
 *   NTSTATUS NtGetContextThread(HANDLE Thread, PCONTEXT Context);
 *   NTSTATUS NtSetContextThread(HANDLE Thread, PCONTEXT Context);
 *
 * Caller passes a CONTEXT* whose ContextFlags member tells the
 * kernel which classes to honour (CONTEXT_INTEGER, CONTEXT_CONTROL,
 * CONTEXT_FULL, etc.). Kernel reads ContextFlags from rdx and
 * the buffer pointer from rsi; the v0 implementation honours
 * INTEGER + CONTROL fully and ignores the FLOATING_POINT /
 * DEBUG_REGISTERS classes (the buffer is left untouched on GET
 * for those classes; the corresponding bytes are read but not
 * applied on SET).
 *
 * Returns:
 *   STATUS_SUCCESS on full success
 *   STATUS_INVALID_HANDLE — handle not in caller's table /
 *     target dead
 *   STATUS_INVALID_PARAMETER — target not suspended OR no user
 *     trap frame yet (target hasn't entered user mode)
 *   STATUS_ACCESS_DENIED — caller missing kCapDebug
 *   STATUS_ACCESS_VIOLATION — Context buffer unmapped /
 *     unwritable
 *
 * The caller must hand a fully-sized CONTEXT (1232 bytes); the
 * kernel only writes the first 0x100 bytes (the integer +
 * control region — Microsoft's CONTEXT layout has the integer
 * registers there and Rip at +0xF8). The remaining bytes
 * (XMM0..XMM15, AVX vectors, DR* mirrors) are left as the caller
 * supplied them on GET.
 * ------------------------------------------------------------------ */
__declspec(dllexport) NTSTATUS NtGetContextThread(HANDLE ThreadHandle, void* Context)
{
    long long rc;
    /* SYS_THREAD_GET_CONTEXT = 137. Read ContextFlags out of
     * the caller's CONTEXT to forward to the kernel via rdx. */
    if (Context == (void*)0)
        return (NTSTATUS)0xC000000DL; /* STATUS_INVALID_PARAMETER */
    /* ContextFlags lives at +0x30 in the canonical CONTEXT
     * layout. Read directly without dragging in winnt.h. */
    unsigned int flags = *(unsigned int*)((unsigned char*)Context + 0x30);
    __asm__ volatile("int $0x80"
                     : "=a"(rc)
                     : "a"((long long)137), "D"((long long)ThreadHandle), "S"((long long)Context), "d"((long long)flags)
                     : "memory");
    return (NTSTATUS)rc;
}

__declspec(dllexport) NTSTATUS NtSetContextThread(HANDLE ThreadHandle, const void* Context)
{
    long long rc;
    if (Context == (const void*)0)
        return (NTSTATUS)0xC000000DL;
    unsigned int flags = *(const unsigned int*)((const unsigned char*)Context + 0x30);
    __asm__ volatile("int $0x80"
                     : "=a"(rc)
                     : "a"((long long)138), "D"((long long)ThreadHandle), "S"((long long)Context), "d"((long long)flags)
                     : "memory");
    return (NTSTATUS)rc;
}

__declspec(dllexport) NTSTATUS NtQueryVirtualMemory(HANDLE ProcessHandle, void* BaseAddress, int MemoryInformationClass,
                                                    void* MemoryInformation, unsigned long long MemoryInformationLength,
                                                    unsigned long long* ReturnLength)
{
    /* MemoryBasicInformation = 0. Anything else returns
     * STATUS_INVALID_INFO_CLASS without crossing the syscall
     * boundary. */
    if (MemoryInformationClass != 0)
        return (NTSTATUS)0xC0000003L; /* STATUS_INVALID_INFO_CLASS */
    if (MemoryInformation == (void*)0)
        return NTSTATUS_INVALID_PARAMETER;
    if (MemoryInformationLength < 48)
        return (NTSTATUS)0xC0000023L; /* STATUS_BUFFER_TOO_SMALL */

    long long status;
    /* SYS_PROCESS_VM_QUERY = 134. Args: rdi=handle, rsi=probe_va,
     * rdx=out_buf. */
    __asm__ volatile("int $0x80"
                     : "=a"(status)
                     : "a"((long long)134), "D"((long long)ProcessHandle), "S"((long long)BaseAddress),
                       "d"((long long)MemoryInformation)
                     : "memory");
    if (status == 0 && ReturnLength != (unsigned long long*)0)
        *ReturnLength = 48;
    return (NTSTATUS)status;
}

__declspec(dllexport) NTSTATUS NtQueryValueKey(HANDLE KeyHandle, UNICODE_STRING* ValueName, ULONG InfoClass,
                                               void* KeyValueInformation, ULONG Length, ULONG* ResultLength)
{
    if (ValueName == (UNICODE_STRING*)0 || ValueName->Buffer == (wchar_t16*)0)
        return NTSTATUS_INVALID_PARAMETER;

    /* Strip the value name to ASCII. */
    char name[64];
    {
        const unsigned chars = (unsigned)(ValueName->Length / 2);
        if (chars + 1 > sizeof(name))
            return NTSTATUS_INVALID_PARAMETER;
        for (unsigned i = 0; i < chars; ++i)
        {
            unsigned short w = ValueName->Buffer[i];
            name[i] = (w <= 0x7F) ? (char)w : '?';
        }
        name[chars] = 0;
    }

    /* First trip: size-only query. The kernel-side QueryValue
     * writes a packed [size:32 | type:32] u64 to r9 even on
     * STATUS_BUFFER_TOO_SMALL, so we know how much to allocate /
     * advertise even if the caller's buffer is short. */
    long long packed = 0;
    long long status;
    /* SYS_REGISTRY = 130, op = 3 (kOpQueryValue) */
    /* Args: rdi=op, rsi=handle, rdx=name, r10=buf (0 = size-only),
     *       r8=cap (0), r9=&packed. */
    __asm__ volatile("mov %4, %%r10\n\t"
                     "mov %5, %%r8\n\t"
                     "mov %6, %%r9\n\t"
                     "int $0x80"
                     : "=a"(status)
                     : "a"((long long)130), "D"((long long)3), "S"((long long)KeyHandle), "r"((long long)0),
                       "r"((long long)0), "r"((long long)&packed), "d"((long long)name)
                     : "r10", "r8", "r9", "memory");
    if (status != 0)
        return (NTSTATUS)status;

    const unsigned data_size = (unsigned)(packed >> 32);
    const unsigned data_type = (unsigned)(packed & 0xFFFFFFFFu);

    /* Compute output size in the requested info-class layout.
     * Only KeyValuePartialInformation is implemented in v0;
     * other classes return STATUS_NOT_IMPLEMENTED so callers
     * fall back rather than misinterpret. */
    if (InfoClass != KeyValuePartialInformation)
        return (NTSTATUS)NTSTATUS_NOT_IMPLEMENTED;

    /* KEY_VALUE_PARTIAL_INFORMATION:
     *   ULONG TitleIndex;   // 0
     *   ULONG Type;         // value type
     *   ULONG DataLength;   // bytes of Data
     *   UCHAR Data[1];      // VLA */
    const ULONG header_size = 12;
    const ULONG total_size = header_size + (ULONG)data_size;
    if (ResultLength != (ULONG*)0)
        *ResultLength = total_size;
    if (Length < total_size)
        return (NTSTATUS)NTSTATUS_BUFFER_TOO_SMALL;
    if (KeyValueInformation == (void*)0)
        return NTSTATUS_INVALID_PARAMETER;

    unsigned char* out = (unsigned char*)KeyValueInformation;
    /* TitleIndex = 0 */
    out[0] = 0;
    out[1] = 0;
    out[2] = 0;
    out[3] = 0;
    /* Type */
    out[4] = (unsigned char)(data_type & 0xFF);
    out[5] = (unsigned char)((data_type >> 8) & 0xFF);
    out[6] = (unsigned char)((data_type >> 16) & 0xFF);
    out[7] = (unsigned char)((data_type >> 24) & 0xFF);
    /* DataLength */
    out[8] = (unsigned char)(data_size & 0xFF);
    out[9] = (unsigned char)((data_size >> 8) & 0xFF);
    out[10] = (unsigned char)((data_size >> 16) & 0xFF);
    out[11] = (unsigned char)((data_size >> 24) & 0xFF);

    /* Second trip: copy bytes into the Data[] tail. */
    long long status2;
    __asm__ volatile("mov %4, %%r10\n\t"
                     "mov %5, %%r8\n\t"
                     "mov %6, %%r9\n\t"
                     "int $0x80"
                     : "=a"(status2)
                     : "a"((long long)130), "D"((long long)3), "S"((long long)KeyHandle),
                       "r"((long long)(out + header_size)), "r"((long long)data_size), "r"((long long)&packed),
                       "d"((long long)name)
                     : "r10", "r8", "r9", "memory");
    if (status2 != 0)
        return (NTSTATUS)status2;
    return NTSTATUS_SUCCESS;
}

/* ------------------------------------------------------------------
 * NtSetValueKey — write a value into a previously-opened key.
 *
 * Win32 NT signature:
 *   NTSTATUS NtSetValueKey(
 *     HANDLE          KeyHandle,
 *     PUNICODE_STRING ValueName,
 *     ULONG           TitleIndex,
 *     ULONG           Type,
 *     PVOID           Data,
 *     ULONG           DataSize);
 *
 * v0 forwards to SYS_REGISTRY op=4 (kOpSetValue). Cap on
 * data size = 256 bytes per value (kSidecarDataMax kernel-side);
 * larger requests return STATUS_INSUFFICIENT_RESOURCES. The
 * kernel writes the value into a sidecar pool that shadows the
 * static tree on subsequent NtQueryValueKey reads.
 * ------------------------------------------------------------------ */
__declspec(dllexport) NTSTATUS NtSetValueKey(HANDLE KeyHandle, UNICODE_STRING* ValueName, ULONG TitleIndex, ULONG Type,
                                             void* Data, ULONG DataSize)
{
    (void)TitleIndex;
    if (ValueName == (UNICODE_STRING*)0 || ValueName->Buffer == (wchar_t16*)0)
        return NTSTATUS_INVALID_PARAMETER;
    char name[64];
    const unsigned chars = (unsigned)(ValueName->Length / 2);
    if (chars + 1 > sizeof(name))
        return NTSTATUS_INVALID_PARAMETER;
    for (unsigned i = 0; i < chars; ++i)
    {
        unsigned short w = ValueName->Buffer[i];
        name[i] = (w <= 0x7F) ? (char)w : '?';
    }
    name[chars] = 0;
    long long status;
    /* SYS_REGISTRY = 130, op = 4 (kOpSetValue).
     * Args: rdi=op, rsi=handle, rdx=name, r10=data, r8=size, r9=type. */
    __asm__ volatile("mov %4, %%r10\n\t"
                     "mov %5, %%r8\n\t"
                     "mov %6, %%r9\n\t"
                     "int $0x80"
                     : "=a"(status)
                     : "a"((long long)130), "D"((long long)4), "S"((long long)KeyHandle), "r"((long long)Data),
                       "r"((long long)DataSize), "r"((long long)Type), "d"((long long)name)
                     : "r10", "r8", "r9", "memory");
    return (NTSTATUS)status;
}

/* ------------------------------------------------------------------
 * NtDeleteValueKey — remove a value from a previously-opened key.
 *
 * Win32 NT signature:
 *   NTSTATUS NtDeleteValueKey(HANDLE KeyHandle, PUNICODE_STRING ValueName);
 *
 * v0 only deletes values previously written via NtSetValueKey
 * (the sidecar). Static-tree values cannot be deleted (live in
 * .rodata) — the kernel returns STATUS_INSUFFICIENT_RESOURCES
 * for that case as the closest signal that the value exists but
 * is unmodifiable.
 * ------------------------------------------------------------------ */
__declspec(dllexport) NTSTATUS NtDeleteValueKey(HANDLE KeyHandle, UNICODE_STRING* ValueName)
{
    if (ValueName == (UNICODE_STRING*)0 || ValueName->Buffer == (wchar_t16*)0)
        return NTSTATUS_INVALID_PARAMETER;
    char name[64];
    const unsigned chars = (unsigned)(ValueName->Length / 2);
    if (chars + 1 > sizeof(name))
        return NTSTATUS_INVALID_PARAMETER;
    for (unsigned i = 0; i < chars; ++i)
    {
        unsigned short w = ValueName->Buffer[i];
        name[i] = (w <= 0x7F) ? (char)w : '?';
    }
    name[chars] = 0;
    long long status;
    /* SYS_REGISTRY = 130, op = 5 (kOpDeleteValue). */
    __asm__ volatile("int $0x80"
                     : "=a"(status)
                     : "a"((long long)130), "D"((long long)5), "S"((long long)KeyHandle), "d"((long long)name)
                     : "memory");
    return (NTSTATUS)status;
}

/* ------------------------------------------------------------------
 * NtFlushKey — persist any pending writes for the key.
 *
 * v0 has no on-disk hive, so flush is a success-no-op. Provided
 * for API completeness — well-behaved app installers call it
 * after a batch of NtSetValueKey calls to ensure the writes
 * land before the installer exits.
 * ------------------------------------------------------------------ */
