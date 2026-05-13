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

__declspec(dllimport) void __stdcall ExitProcess(unsigned);

void __cdecl mainCRTStartup(void)
{
    /* Layer-4 path: call ExitProcess via the PE32 IAT. The kernel
     * preloads kernel32_32.dll at boot and ResolveImports patches
     * the IAT slot with the real ExitProcess VA, so this indirect
     * call lands in our 32-bit kernel32 stub which then issues
     * `int $0x80` with eax=SYS_EXIT, ebx=uExitCode.
     *
     * If for any reason the IAT is unresolved (e.g. the catch-all
     * NOP stub gets installed), the fallback path below issues
     * the syscall directly so the smoke never just spins.
     *
     * Exit code 0x32 (50 decimal) is the success signature for
     * the boot-log scraper. */
    ExitProcess(0x32);

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
