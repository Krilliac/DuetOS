/*
 * userland/libs/msvcrt_32/chkstk.S
 *
 * Microsoft x86 (i386) chkstk family — stack-probe helpers.
 *
 * MSVC's 32-bit codegen emits a `call _chkstk` (or _alloca_probe
 * for explicit _alloca) at the head of any function whose locals
 * exceed one page. Three names export the same body, matching
 * Microsoft's runtime which has aliased them since VC6:
 *
 *     _chkstk          — canonical name, called from prologues
 *     __chkstk         — alternate name (gcc/clang i386 codegen)
 *     _alloca_probe    — explicit _alloca callsites
 *
 * Contract (Microsoft x86 ABI, mirrors Microsoft's chkstk.asm
 * shipping in vcruntime):
 *
 *   In:    EAX = bytes the caller wants subtracted from ESP.
 *          [ESP] = return address.
 *   Out:   ESP = ESP_in - EAX (we DO adjust ESP — this is the
 *                key difference from the x64 variant).
 *          EAX = ESP_in (the old top, prior to our adjustment;
 *                conventionally treated as scratch by the caller).
 *          ECX clobbered.
 *          EBP/EBX/ESI/EDI preserved (callee-saved).
 *          The return address that was at [ESP_in] is now at the
 *          new [ESP] — the ret falls through naturally.
 *   Side:  Touch one byte per 4 KiB stride from ESP_in down to
 *          the new ESP, so a stack-guard hit faults here rather
 *          than mid-prologue.
 *
 * The two paths (probepages / lastpage) handle the "full pages
 * to probe" loop and the trailing partial page respectively.
 *
 * Mirrors the x86_64 sibling in ../ntdll/chkstk.S. Both should
 * stay aligned on probe semantics — they only differ in the
 * convention around RSP/ESP adjustment.
 *
 * Symbol names are i386-cdecl-decorated (one extra leading
 * underscore on top of the C source name) — that's what
 * msvcrt_32.def's EXPORTS list resolves to.
 */

    /* Declare this object SafeSEH-compatible (we install no
     * handlers, so the empty handler list is correct).
     * lld-link's /safeseh requires every i386 obj to opt in;
     * C-compiled objects get this for free from clang, but
     * hand-written asm must emit it explicitly. */
    .globl  @feat.00
    .set    @feat.00, 1

    .text
    .globl  __chkstk           /* C: _chkstk         */
    .globl  ___chkstk          /* C: __chkstk        */
    .globl  __alloca_probe     /* C: _alloca_probe   */
    .def    __chkstk;       .scl 2; .type 32; .endef
    .def    ___chkstk;      .scl 2; .type 32; .endef
    .def    __alloca_probe; .scl 2; .type 32; .endef
__chkstk:
___chkstk:
__alloca_probe:
    pushl   %ecx                    /* save ecx (caller-saved but we want it back) */
    cmpl    $4096, %eax
    leal    8(%esp), %ecx           /* ecx = caller ESP at call site
                                       (saved-ECX + return-addr = 8 bytes) */
    jb      .Llastpage
.Lprobepages:
    subl    $4096, %ecx
    subl    $4096, %eax
    testl   %eax, (%ecx)            /* probe one full page */
    cmpl    $4096, %eax
    jae     .Lprobepages
.Llastpage:
    subl    %eax, %ecx              /* ecx = address of last (partial) page */
    movl    %esp, %eax              /* eax = current TOS (our pushed-ecx slot) */
    testl   %eax, (%ecx)            /* probe final page */
    movl    %ecx, %esp              /* commit new ESP */
    movl    (%eax), %ecx            /* restore saved ecx */
    movl    4(%eax), %eax           /* fetch return addr from old [ESP+4] */
    pushl   %eax                    /* deposit return addr at new ESP */
    ret
