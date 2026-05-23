/*
 * userland/libs/vcruntime140/guard_icall.S
 *
 * Control Flow Guard (CFG) and eXtended Flow Guard (XFG) indirect-
 * call dispatchers — exported by vcruntime140.dll. MSVC's
 * `/guard:cf` and `/guard:xfg` codegen turns every indirect call
 * site into a tuple:
 *
 *   mov  rax, <target>
 *   call _guard_dispatch_icall          ; or _guard_xfg_dispatch_icall
 *
 * The dispatcher's job on real Windows is to validate `rax` against
 * the per-image guard CF/XFG bitmap, then `jmp rax`. On a CFG
 * violation Windows raises STATUS_GUARD_CHECK; XFG additionally
 * verifies a per-function type hash matched at the call site.
 *
 * DuetOS does not yet ship per-image CFG/XFG bitmaps (the loader
 * doesn't surface IMAGE_LOAD_CONFIG_DIRECTORY's GuardCFCheckFunction
 * field), so the dispatcher reduces to the validate-and-jump's
 * "and-jump" part: trust the target, transfer control. Same
 * stance as Wine and the older Windows builds before CFG enforce-
 * ment. // GAP: per-image CFG/XFG bitmap walk — lands with the
 * image-load-config slice.
 *
 * Naked so the prologue/epilogue can't perturb rax (which holds
 * the call target). Both dispatchers share the body — XFG only
 * differs in the type-hash arm that we don't yet implement.
 */

    .text

    .globl  _guard_dispatch_icall
    .def    _guard_dispatch_icall; .scl 2; .type 32; .endef
_guard_dispatch_icall:
    jmpq    *%rax                       /* tail-jump; rax = target */

    .globl  _guard_xfg_dispatch_icall
    .def    _guard_xfg_dispatch_icall; .scl 2; .type 32; .endef
_guard_xfg_dispatch_icall:
    jmpq    *%rax                       /* same body — XFG arm is the GAP above */
