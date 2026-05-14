/*
 * pe32_smoke — minimal PE32 (i386) test image.
 *
 * Built with the i686 mingw cross compiler so the resulting PE has
 * Machine=IMAGE_FILE_MACHINE_I386 (0x014C) and OptHdrMagic=PE32 (0x10B).
 *
 * Today's purpose: the kernel's PE loader recognises PE32 (Layer 1 of
 * 32-bit PE support) but rejects MapAndRun with the typed status
 * `PeStatus::Pe32ExecutionNotReady` (Layer 4/5 not in yet). This image
 * exists so the loader's reject path can be exercised end-to-end on
 * the boot smoke — proving:
 *
 *   1. The validator accepts PE32 / Machine=0x14C / OptHdrMagic=0x10B
 *   2. The optional-header parser uses the PE32 layout (ImageBase at
 *      offset 28, data-directory array at offset 96)
 *   3. PeReport can walk the imports of a real 32-bit PE
 *   4. The reject status surfaces as "Pe32ExecutionNotReady" in the
 *      FixJournal pin format, distinct from the older "NotPe32Plus"
 *      (which now only fires for malformed magic values)
 *
 * Once Layers 4 (32-bit DLL set) and 5 (pointer marshalling) land,
 * the loader will route this image through EnterUserMode32 and the
 * `int 0x80` below will hit the kernel's syscall handler with the
 * 32-bit register-remap path active. SYS_EXIT (syscall #1) with
 * rc=0x32 (50 in decimal) is the success signature.
 */

typedef void* HANDLE;
typedef unsigned long DWORD;
typedef int BOOL;

#define STD_OUTPUT_HANDLE ((DWORD) - 11)

__declspec(dllimport) void __stdcall ExitProcess(unsigned);
__declspec(dllimport) HANDLE __stdcall GetStdHandle(DWORD);
__declspec(dllimport) BOOL __stdcall WriteConsoleA(HANDLE, const void*, DWORD, DWORD*, void*);
__declspec(dllimport) DWORD __stdcall GetCurrentProcessId(void);

static void say(const char* s)
{
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD n = 0;
    DWORD len = 0;
    while (s[len] != '\0')
        ++len;
    WriteConsoleA(h, s, len, &n, (void*)0);
}

void __cdecl mainCRTStartup(void)
{
    /* Exercise the Layer-4 import chain: GetStdHandle returns the
     * STD_OUTPUT_HANDLE sentinel, WriteConsoleA issues SYS_WRITE
     * (syscall 2) with fd=1 via our 32-bit kernel32 stub. Each
     * call is an indirect-call through the post-reloc IAT slot
     * the loader patched to point at the kernel32_32.dll export.
     *
     * GetCurrentProcessId returns the kernel-assigned pid; we pass
     * it to ExitProcess so the destroy line carries it as the
     * exit code — both the "[pe32] hello" print and the
     * exit-rc=<pid> line are end-to-end signals that the PE32
     * IAT walker resolved every import correctly. */
    say("[pe32] hello from compat mode\r\n");
    /* Exit code carries the pid so the boot-log scraper has a
     * value to check. Pid 8 (or whatever ProcessCreate assigned)
     * appears in both `[proc] destroy` and the exit code. */
    ExitProcess(GetCurrentProcessId());

    /* Belt-and-braces fallback: if ExitProcess somehow returned
     * (it never should — it's __declspec(noreturn) on the real API
     * AND we noreturn-marked our 32-bit stub), issue the SYS_EXIT
     * syscall directly via int 0x80. */
    __asm__ volatile("movl $0, %%eax\n\t"    /* SYS_EXIT */
                     "movl $0x32, %%ebx\n\t" /* rc = 0x32 */
                     "int $0x80\n\t"
                     :
                     :
                     : "eax", "ebx", "memory");
}
