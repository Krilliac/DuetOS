/*
 * userland/libs/kernel32/kernel32_seh.c
 *
 * kernel32.dll's software-exception entry: RaiseException.
 *
 * Windows layers this as kernelbase!RaiseException building an
 * EXCEPTION_RECORD and ntdll!RtlRaiseException dispatching it. We
 * keep the same split: this TU owns the record, ntdll owns the
 * two-pass search / unwind engine (KiUserExceptionDispatcher,
 * RtlUnwindEx, RtlRestoreContext) and is imported, not duplicated.
 *
 * The caller's CONTEXT is captured by raise_exception.S before any
 * compiler prologue runs — see that file for the frame layout and
 * why the dispatch has to start at the caller's frame rather than
 * ours.
 *
 * The rest of the Rtl* unwind family kernel32 publishes is either a
 * real body in kernel32_interlocked.c + seh_capture.S
 * (RtlCaptureContext / RtlLookupFunctionEntry / RtlVirtualUnwind /
 * RtlCaptureStackBackTrace) or a PE forwarder to ntdll declared on
 * the link line (RtlUnwindEx / RtlUnwind / RtlRestoreContext).
 */

/* EXCEPTION_MAXIMUM_PARAMETERS. */
#define K32_EXCEPTION_MAX_PARAMS 15

/* Canonical Windows x64 CONTEXT offset, shared with
 * raise_exception.S, ntdll/seh_trampolines.S, vcruntime140's
 * cxx_throw.S, and kernel seh_dispatch.cpp. */
#define K32_CONTEXT_RIP_OFF 0xF8u

/* EXCEPTION_RECORD — layout asserted kernel-side; sizeof == 0x98. */
typedef struct
{
    unsigned int ExceptionCode;
    unsigned int ExceptionFlags;
    unsigned long long ExceptionRecordPtr;
    unsigned long long ExceptionAddress;
    unsigned int NumberParameters;
    unsigned int _align;
    unsigned long long ExceptionInformation[K32_EXCEPTION_MAX_PARAMS];
} K32_EXCEPTION_RECORD;

/* ntdll engine (imported — kernel32.dll links ntdll.lib). */
extern long NtRaiseException(void* ExceptionRecord, void* ContextRecord, int HandleException);

/* Called from raise_exception.S with the caller's complete CONTEXT.
 * Returns only when the arguments are rejected; a claimed exception
 * transfers control and a filter answering
 * EXCEPTION_CONTINUE_EXECUTION resumes at the caller's captured RIP,
 * so neither path comes back through here. */
void RaiseExceptionImpl(unsigned long dwExceptionCode, unsigned long dwExceptionFlags, unsigned long nNumberOfArguments,
                        const unsigned long long* lpArguments, unsigned char* caller_context)
{
    if (caller_context == (unsigned char*)0)
        return;

    K32_EXCEPTION_RECORD rec;
    for (unsigned i = 0; i < sizeof(rec); ++i)
        ((unsigned char*)&rec)[i] = 0;

    rec.ExceptionCode = (unsigned int)dwExceptionCode;
    rec.ExceptionFlags = (unsigned int)dwExceptionFlags;
    rec.ExceptionAddress = *(const unsigned long long*)(caller_context + K32_CONTEXT_RIP_OFF);

    /* Documented contract: more than EXCEPTION_MAXIMUM_PARAMETERS
     * arguments, or a null argument vector, means "no arguments" —
     * not an error and not a truncated copy. */
    if (lpArguments != (const unsigned long long*)0 && nNumberOfArguments <= K32_EXCEPTION_MAX_PARAMS)
    {
        rec.NumberParameters = (unsigned int)nNumberOfArguments;
        for (unsigned long i = 0; i < nNumberOfArguments; ++i)
            rec.ExceptionInformation[i] = lpArguments[i];
    }

    NtRaiseException(&rec, caller_context, 1 /* first chance — enter the dispatcher */);
}
