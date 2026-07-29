/*
 * userland/libs/msvcrt_32/msvcrt_32_crt.c
 *
 * The MSVC CRT-startup cluster for the i386 msvcrt.dll companion —
 * the symbols an MSVC-built PE32 touches between its entry point and
 * main(). Nothing 32-bit reaches main() without these: on a survey of
 * the 32-bit binaries under SysWOW64, _except_handler4_common,
 * _cexit, _XcptFilter, _controlfp and ?terminate@@YAXXZ are each
 * imported by ~228 distinct executables.
 *
 * Where the x86_64 side keeps these
 * ---------------------------------
 * There is no 64-bit msvcrt.c implementation to mirror: the PE32+
 * path resolves them through the in-kernel flat thunk table
 * (kernel/subsystems/win32/thunks_table.inc), which is NOT mapped for
 * PE32 images. The intended semantics are read off that table and
 * reproduced here in real code:
 *
 *   _cexit / _c_exit  -> the apiset rows route to kOffCexit, "the
 *                        proc-env atexit walker ... runs every handler
 *                        registered ... in LIFO order". Implemented
 *                        below against a DLL-local table, which is the
 *                        same object for a single-image PE32.
 *   _onexit /
 *   __dllonexit       -> registration for that table (the msvcrt rows
 *                        pin return-0, i.e. "registration failed";
 *                        a real table is strictly better and is what
 *                        _cexit needs to have anything to walk).
 *   _XcptFilter       -> kOffPinReturn0 = EXCEPTION_EXECUTE_HANDLER.
 *   terminate         -> kOffTerminate = abort.
 *   _purecall         -> kOffTerminate = abort.
 *   _callnewh         -> kOffCallnewhNoop = 0, "no new-handler
 *                        installed".
 *   __wgetmainargs    -> kOffGetMainArgs, the wide twin of the
 *                        __getmainargs already in msvcrt_32.c.
 *   _controlfp        -> kOffPinReturn0; bookkeeping is implemented
 *                        here so the CRT's read-back is coherent.
 *
 * __cdecl throughout — msvcrt's historical convention; the caller
 * cleans the stack.
 */

typedef unsigned int size_t;

/* Defined in msvcrt_32.c. */
void abort(void);

/* ------------------------------------------------------------------
 * CRT internal locks — _lock(locknum) / _unlock(locknum)
 *
 * The MSVC CRT serialises its own globals (the stdio FILE table, the
 * heap, the locale) through a fixed array of numbered locks. The
 * numbering is a CRT-internal enum whose largest member across the
 * MSVC versions that shipped msvcrt.dll sits well below 64, so a
 * 64-entry array covers every caller; an out-of-range index is
 * ignored rather than allowed to index off the end.
 *
 * Each lock is a recursive spin lock keyed on the caller's TID, which
 * matches the CRT's expectation that _lock is re-entrant on the same
 * thread (its stdio paths nest _lock(_STREAM_LOCKS + n) inside
 * _lock(_IOB_SCAN_LOCK)).
 * ------------------------------------------------------------------ */

#define MSVCRT32_LOCK_SLOTS 64

static int volatile g_lock_owner[MSVCRT32_LOCK_SLOTS];
static int volatile g_lock_depth[MSVCRT32_LOCK_SLOTS];

static int msvcrt32_tid(void)
{
    int rv;
    __asm__ volatile("int $0x80" : "=a"(rv) : "a"(1 /* SYS_GETPID */) : "memory");
    return rv;
}

static void msvcrt32_yield(void)
{
    int rv;
    __asm__ volatile("int $0x80" : "=a"(rv) : "a"(3 /* SYS_YIELD */) : "memory");
    (void)rv;
}

__declspec(dllexport) void _lock(int locknum)
{
    if (locknum < 0 || locknum >= MSVCRT32_LOCK_SLOTS)
        return;
    const int tid = msvcrt32_tid();
    int volatile* owner = &g_lock_owner[locknum];
    for (;;)
    {
        int expected = 0;
        if (__atomic_compare_exchange_n(owner, &expected, tid, 0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST))
        {
            g_lock_depth[locknum] = 1;
            return;
        }
        if (expected == tid)
        {
            g_lock_depth[locknum] = g_lock_depth[locknum] + 1;
            return;
        }
        msvcrt32_yield();
    }
}

__declspec(dllexport) void _unlock(int locknum)
{
    if (locknum < 0 || locknum >= MSVCRT32_LOCK_SLOTS)
        return;
    const int next = g_lock_depth[locknum] - 1;
    g_lock_depth[locknum] = next;
    if (next <= 0)
        __atomic_store_n(&g_lock_owner[locknum], 0, __ATOMIC_RELEASE);
}

/* ------------------------------------------------------------------
 * atexit / onexit table
 * ------------------------------------------------------------------ */

#define MSVCRT32_ATEXIT_SLOTS 32

typedef void(__cdecl* Msvcrt32AtexitFn)(void);

static Msvcrt32AtexitFn g_atexit[MSVCRT32_ATEXIT_SLOTS];
static int g_atexit_count;

/* The table needs its own lock rather than one of the numbered CRT
 * locks: those indices belong to the guest's CRT and reusing one
 * would let our bookkeeping deadlock against its stdio nesting. */
static int volatile g_atexit_lock;

static void msvcrt32_atexit_lock(void)
{
    int expected = 0;
    while (!__atomic_compare_exchange_n(&g_atexit_lock, &expected, 1, 0, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED))
    {
        expected = 0;
        msvcrt32_yield();
    }
}

static void msvcrt32_atexit_unlock(void)
{
    __atomic_store_n(&g_atexit_lock, 0, __ATOMIC_RELEASE);
}

/* _onexit(fn) returns fn on success, NULL if the table is full —
 * exactly the Win32 contract. `atexit` is the same registration with
 * a void return. */
__declspec(dllexport) Msvcrt32AtexitFn _onexit(Msvcrt32AtexitFn fn)
{
    if (fn == (Msvcrt32AtexitFn)0)
        return (Msvcrt32AtexitFn)0;
    msvcrt32_atexit_lock();
    if (g_atexit_count >= MSVCRT32_ATEXIT_SLOTS)
    {
        msvcrt32_atexit_unlock();
        return (Msvcrt32AtexitFn)0;
    }
    g_atexit[g_atexit_count++] = fn;
    msvcrt32_atexit_unlock();
    return fn;
}

__declspec(dllexport) int atexit(Msvcrt32AtexitFn fn)
{
    return _onexit(fn) != (Msvcrt32AtexitFn)0 ? 0 : -1;
}

/* __dllonexit(fn, pbegin, pend) is the DLL-scoped registrar. Its real
 * signature threads the caller's own table through pbegin/pend so
 * each DLL owns its list; we register into the single process table
 * instead, which is equivalent for an image set that is never
 * unloaded (FreeLibrary is a no-op in kernel32_32). */
// GAP: the caller's per-DLL table (pbegin/pend) is not threaded - a
// handler registered here runs at process exit rather than at
// FreeLibrary time. Revisit if DLL unload ever becomes real.
__declspec(dllexport) Msvcrt32AtexitFn __dllonexit(Msvcrt32AtexitFn fn, Msvcrt32AtexitFn** pbegin,
                                                   Msvcrt32AtexitFn** pend)
{
    (void)pbegin;
    (void)pend;
    return _onexit(fn);
}

/* _cexit runs every registered handler in LIFO order and returns
 * WITHOUT exiting the process — that separation is the whole point of
 * _cexit versus exit. The table is drained as it is walked so a
 * handler that itself calls exit() cannot re-enter the same
 * callback. */
__declspec(dllexport) void _cexit(void)
{
    for (;;)
    {
        msvcrt32_atexit_lock();
        if (g_atexit_count <= 0)
        {
            msvcrt32_atexit_unlock();
            return;
        }
        Msvcrt32AtexitFn fn = g_atexit[--g_atexit_count];
        msvcrt32_atexit_unlock();
        if (fn != (Msvcrt32AtexitFn)0)
            fn();
    }
}

/* _c_exit is _cexit minus the stdio flush. We have no buffered stdio
 * to flush, so the two are the same walk. */
__declspec(dllexport) void _c_exit(void)
{
    _cexit();
}

/* ------------------------------------------------------------------
 * Termination
 * ------------------------------------------------------------------ */

/* ?terminate@@YAXXZ is the C++ std::terminate export. No C identifier
 * can spell its MSVC mangling, so the export is renamed in the .def
 * (`?terminate@@YAXXZ = msvcrt32_cxx_terminate`) and the C function
 * carries an ordinary name. Deliberately NOT dllexport: the .def line
 * is what publishes it, and a dllexport directive here would also
 * publish the internal spelling as a second, junk export. */
void msvcrt32_cxx_terminate(void)
{
    /* std::terminate calls the terminate handler and then abort().
     * set_terminate is not exported, so there is never a handler. */
    abort();
}

/* _purecall — a virtual call reached through a partially-constructed
 * object. Unrecoverable by definition; the x86_64 thunk row maps it
 * to the same abort. */
__declspec(dllexport) void _purecall(void)
{
    abort();
}

/* _callnewh(size) asks the C++ new-handler to free memory and report
 * whether it succeeded. set_new_handler is not exported, so there is
 * never a handler and 0 ("no handler ran, give up") is the accurate
 * answer rather than a placeholder. */
__declspec(dllexport) int _callnewh(size_t size)
{
    (void)size;
    return 0;
}

/* ------------------------------------------------------------------
 * Structured-exception entry points
 * ------------------------------------------------------------------ */

/* _XcptFilter(code, ptrs) is the __except filter MSVC wraps main() in.
 * On Windows it runs the unhandled-exception path and then reports a
 * disposition. Returning EXCEPTION_EXECUTE_HANDLER (0) makes the
 * generated __except block run, which calls _exit(code) — i.e. an
 * unhandled exception terminates, which is the behaviour we can
 * actually deliver. Matches the x86_64 thunk row (kOffPinReturn0). */
// GAP: no unhandled-exception reporting - the filter neither invokes
// SetUnhandledExceptionFilter's callback nor writes a dump; it only
// selects the caller's terminate path.
__declspec(dllexport) int _XcptFilter(unsigned long xcptnum, void* pxcptinfoptrs)
{
    (void)xcptnum;
    (void)pxcptinfoptrs;
    return 0; /* EXCEPTION_EXECUTE_HANDLER */
}

/* _except_handler4_common is the SEH4 (/GS-hardened) frame handler
 * that every MSVC 32-bit function with a try/finally registers. A
 * real implementation walks the caller's scope table, validates the
 * security cookie, and runs filters and finally-blocks in order —
 * none of which exists on the i386 path, and none of which this DLL
 * could add without a kernel-side SEH dispatcher.
 *
 * ExceptionContinueSearch (1) is the honest disposition: "this frame
 * does not handle the exception". It is also the only safe one — the
 * alternatives require unwinding state we do not have.
 *
 * This export exists because an import the loader cannot bind is
 * wired to a stub that SYS_EXITs on first call, and MSVC emits the
 * IAT slot for _except_handler4_common in the image's static data
 * whether or not an exception is ever raised. Resolving it to a
 * defined no-handler is the difference between "runs" and "dies at
 * load-adjacent first touch". */
// STUB: no SEH4 scope-table walk, no cookie validation, no filter or
// finally-block execution - every frame reports "not mine", so a
// guest's try/except and try/finally blocks never run. Requires a
// kernel-side 32-bit exception dispatcher first: the x86_64 path
// works end to end (kernel seh_dispatch.cpp -> ntdll
// KiUserExceptionDispatcher -> __C_specific_handler), but it builds
// an x64 CONTEXT and resumes at an x64 entry point. i386 SEH is a
// different shape entirely - the fs:[0] registration chain rather
// than .pdata tables - so none of that engine is reusable here.
__declspec(dllexport) int _except_handler4_common(unsigned long* cookie, void* check_fn, void* exception_record,
                                                  void* registration, void* context, void* dispatcher)
{
    (void)cookie;
    (void)check_fn;
    (void)exception_record;
    (void)registration;
    (void)context;
    (void)dispatcher;
    return 1; /* ExceptionContinueSearch */
}

/* ------------------------------------------------------------------
 * Floating-point control word
 * ------------------------------------------------------------------ */

/* _controlfp(new, mask) reads-modifies-writes the CRT's view of the
 * FP control word and returns the resulting value. The CRT startup
 * path calls it to pin precision and then stores the answer, so a
 * constant 0 return (what the x86_64 thunk gives) tells the CRT that
 * every exception mask is CLEAR — the opposite of the MSVC default,
 * and a value it may later try to restore. Tracking the word here
 * keeps the read-back coherent.
 *
 * The seed is MSVC's _CW_DEFAULT: all six FP exceptions masked
 * (_MCW_EM = 0x0008001F) with round-to-nearest and 53-bit precision,
 * i.e. 0x0008001F. */
// GAP: bookkeeping only - the x87/SSE control registers are not
// actually reprogrammed, so a guest that sets a rounding mode or
// unmasks an FP exception gets the value back but not the behaviour.
static unsigned g_fp_control = 0x0008001Fu;

__declspec(dllexport) unsigned _controlfp(unsigned newcw, unsigned mask)
{
    if (mask != 0)
        g_fp_control = (g_fp_control & ~mask) | (newcw & mask);
    return g_fp_control;
}

/* ------------------------------------------------------------------
 * Wide entry-point setup
 * ------------------------------------------------------------------ */

/* __wgetmainargs is the wide twin of __getmainargs in msvcrt_32.c and
 * carries the same v0 answer: one argument, the sentinel program
 * name, and an empty environment block. The sentinel is spelled
 * "a.exe" everywhere in this DLL set (msvcrt_32.c's __getmainargs and
 * __p__acmdln, kernel32_32.c's GetCommandLineA/W) — keep it that way;
 * a second spelling is how the sentinel-divergence bug class starts.
 *
 * The out-pointers are written unconditionally when non-NULL because
 * the CRT dereferences *argv immediately after the call. */
// GAP: fixed one-argument command line - the PE32 spawn path does not
// plumb a real command line through yet, matching GetCommandLineW.
__declspec(dllexport) int __wgetmainargs(int* argc, unsigned short*** argv, unsigned short*** envp, int do_wildcard,
                                         void* new_mode)
{
    (void)do_wildcard;
    (void)new_mode;
    static unsigned short g_prog[] = {'a', '.', 'e', 'x', 'e', 0};
    static unsigned short* g_wargv[2] = {g_prog, 0};
    static unsigned short* g_wenvp[1] = {0};
    if (argc != (int*)0)
        *argc = 1;
    if (argv != (unsigned short***)0)
        *argv = g_wargv;
    if (envp != (unsigned short***)0)
        *envp = g_wenvp;
    return 0;
}

/* _wcmdln is the wide command-line pointer, exported as DATA. It has
 * to be a live pointer at image load — a caller reads it directly
 * rather than through an accessor, so a lazily-filled NULL would
 * fault. Same "a.exe" sentinel as everything above. */
static unsigned short g_wcmdln_text[] = {'a', '.', 'e', 'x', 'e', 0};
__declspec(dllexport) unsigned short* _wcmdln = g_wcmdln_text;
