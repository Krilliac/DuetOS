#include "ntdll_internal.h"

/* ------------------------------------------------------------------
 * T6-02 slice 3 — kernel fault → user SEH dispatch (user half).
 *
 * The kernel, on a ring-3 #DE/#UD/#GP/#PF in a Win32 PE, builds a
 * Microsoft EXCEPTION_RECORD + CONTEXT on the faulting thread's
 * stack and resumes the thread HERE, at KiUserExceptionDispatcher,
 * with rcx = EXCEPTION_RECORD, rdx = CONTEXT. This file is the
 * user-mode structured-exception engine that walks the .pdata /
 * .xdata frame chain, runs language handlers (__C_specific_handler
 * for MSVC-style __try/__except/__finally), unwinds to the chosen
 * handler frame (RtlUnwindEx), and resumes there (RtlRestoreContext)
 * — or terminates the process if nothing handles the exception.
 *
 * RtlCaptureContext / RtlLookupFunctionEntry / RtlVirtualUnwind
 * (the slice 1-2 unwinder) live in ntdll_seh.c and are reused
 * here unchanged.
 * ------------------------------------------------------------------ */

/* CONTEXT GPR offsets by x64 unwind register number (RSP=4). */
static const unsigned short k_ctx_gpr_off[16] = {0x78, 0x80, 0x88, 0x90, 0x98, 0xA0, 0xA8, 0xB0,
                                                 0xB8, 0xC0, 0xC8, 0xD0, 0xD8, 0xE0, 0xE8, 0xF0};
#define CTX_RSP 0x98
#define CTX_RBP 0xA0
#define CTX_RIP 0xF8
#define CTX_RAX 0x78

static unsigned long long* ctx_reg(void* c, int i)
{
    return (unsigned long long*)((unsigned char*)c + k_ctx_gpr_off[i & 15]);
}
static unsigned long long* ctx_rsp(void* c)
{
    return (unsigned long long*)((unsigned char*)c + CTX_RSP);
}
static unsigned long long* ctx_rip(void* c)
{
    return (unsigned long long*)((unsigned char*)c + CTX_RIP);
}

/* EXCEPTION_RECORD byte offsets (Microsoft x64). */
#define ER_CODE 0x00
#define ER_FLAGS 0x04
#define ER_ADDRESS 0x10
static unsigned int* er_code(void* r)
{
    return (unsigned int*)((unsigned char*)r + ER_CODE);
}
static unsigned int* er_flags(void* r)
{
    return (unsigned int*)((unsigned char*)r + ER_FLAGS);
}

#define EXCEPTION_UNWINDING 0x02
#define EXCEPTION_TARGET_UNWIND 0x20

#define UNW_FLAG_EHANDLER 0x01
#define UNW_FLAG_UHANDLER 0x02
#define UNW_FLAG_CHAININFO 0x04

/* x64 IMAGE_RUNTIME_FUNCTION_ENTRY — three RVAs. */
typedef struct
{
    unsigned int BeginAddress;
    unsigned int EndAddress;
    unsigned int UnwindInfoAddress;
} RUNTIME_FUNCTION;

/* Our DISPATCHER_CONTEXT — laid out in the canonical Windows x64
 * order. Only our __C_specific_handler reads it; the field set is
 * the subset that handler needs. */
typedef struct
{
    unsigned long long ControlPc;
    unsigned long long ImageBase;
    RUNTIME_FUNCTION* FunctionEntry;
    unsigned long long EstablisherFrame;
    unsigned long long TargetIp;
    void* ContextRecord;
    void* LanguageHandler;
    void* HandlerData;
    void* HistoryTable;
    unsigned int ScopeIndex;
    unsigned int Fill0;
} DISPATCHER_CONTEXT;

typedef long(__attribute__((ms_abi)) * PEXCEPTION_ROUTINE)(void* /*rec*/, void* /*frame*/, void* /*ctx*/,
                                                           void* /*dispatch*/);

/* slice 1-2 unwinder, reused. */
extern void* RtlLookupFunctionEntry(unsigned long long ControlPc, unsigned long long* ImageBase, void* HistoryTable);
extern void* RtlVirtualUnwind(unsigned long HandlerType, unsigned long long ImageBase, unsigned long long ControlPc,
                              void* FunctionEntry, void* ContextRecord, void** HandlerData,
                              unsigned long long* EstablisherFrame, void* ContextPointers);

/* ---- RtlRestoreContext: load every register out of CONTEXT and
 * resume at ctx->Rip. Mirrors kernel/subsystems/win32/seh_unwind.S.
 * rcx = ctx, rdx = rec (rec ignored at this layer). Naked so no
 * prologue perturbs the restore. ---- */
__attribute__((naked)) __declspec(dllexport) void RtlRestoreContext(void* ContextRecord, void* ExceptionRecord)
{
    __asm__ volatile("fxrstor64 0x100(%%rcx)\n\t"
                     "movl 0x44(%%rcx), %%eax\n\t"
                     "pushq %%rax\n\t"
                     "popfq\n\t"
                     "movq 0x90(%%rcx), %%rbx\n\t"
                     "movq 0xA0(%%rcx), %%rbp\n\t"
                     "movq 0xA8(%%rcx), %%rsi\n\t"
                     "movq 0xB0(%%rcx), %%rdi\n\t"
                     "movq 0xD8(%%rcx), %%r12\n\t"
                     "movq 0xE0(%%rcx), %%r13\n\t"
                     "movq 0xE8(%%rcx), %%r14\n\t"
                     "movq 0xF0(%%rcx), %%r15\n\t"
                     "movq 0xB8(%%rcx), %%r8\n\t"
                     "movq 0xC0(%%rcx), %%r9\n\t"
                     "movq 0xC8(%%rcx), %%r10\n\t"
                     "movq 0xD0(%%rcx), %%r11\n\t"
                     "movq 0xF8(%%rcx), %%rax\n\t" /* target rip */
                     "movq 0x98(%%rcx), %%rdx\n\t" /* target rsp */
                     "subq $8, %%rdx\n\t"
                     "movq %%rax, (%%rdx)\n\t" /* [rsp-8] = rip (synthetic ret) */
                     "movq %%rdx, %%rsp\n\t"
                     "movq 0x78(%%rcx), %%rax\n\t"
                     "movq 0x88(%%rcx), %%rdx\n\t"
                     "movq 0x80(%%rcx), %%rcx\n\t"
                     "ret\n\t" ::
                         : "memory");
}

/* Forward decls. */
__declspec(dllexport) void RtlUnwindEx(void* TargetFrame, void* TargetIp, void* ExceptionRecord, void* ReturnValue,
                                       void* ContextRecord, void* HistoryTable);

/* Pull (handler-flags, language-handler-VA, handler-data-ptr,
 * establisher-frame) out of a function's UNWIND_INFO given the
 * per-frame context `c`. Returns the UNWIND_INFO flags; *handler
 * and *hdata are set only when an E/U handler is present (and the
 * function is not pure chain-info). */
static unsigned char read_unwind_handler(unsigned long long ImageBase, RUNTIME_FUNCTION* rf, void* c, void** handler,
                                         void** hdata, unsigned long long* establisher)
{
    const unsigned char* ui = (const unsigned char*)(ImageBase + rf->UnwindInfoAddress);
    /* Chase chained info to the root for the flag/handler that
     * actually applies; the frame register lives on the head. */
    const unsigned char head_frreg = (unsigned char)(ui[3] & 0x0F);
    const unsigned char head_froff = (unsigned char)(ui[3] >> 4);
    if (head_frreg)
        *establisher = *ctx_reg(c, (int)head_frreg) - (unsigned long long)head_froff * 16ULL;
    else
        *establisher = *ctx_rsp(c);

    for (int guard = 0; guard < 32; ++guard)
    {
        const unsigned char flags = (unsigned char)(ui[0] >> 3);
        const unsigned char count = ui[2];
        const unsigned short* codes = (const unsigned short*)(ui + 4);
        if (flags & UNW_FLAG_CHAININFO)
        {
            const RUNTIME_FUNCTION* next = (const RUNTIME_FUNCTION*)(codes + (unsigned)((count + 1) & ~1u));
            ui = (const unsigned char*)(ImageBase + next->UnwindInfoAddress);
            continue;
        }
        if (flags & (UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER))
        {
            const unsigned char* after = (const unsigned char*)(codes + (unsigned)((count + 1) & ~1u));
            const unsigned int hrva = *(const unsigned int*)after;
            *handler = (void*)(ImageBase + hrva);
            *hdata = (void*)(after + 4);
        }
        return flags;
    }
    return 0;
}

/* Advance `c` one frame toward the caller. Handles the leaf case
 * (no .pdata: pop the return address) so the walk doesn't dead-end
 * on a CRT/loader frame. Returns 0 when the chain is exhausted. */
static int unwind_one(void* c)
{
    unsigned long long pc = *ctx_rip(c);
    if (pc == 0)
        return 0;
    unsigned long long ib = 0;
    RUNTIME_FUNCTION* fe = (RUNTIME_FUNCTION*)RtlLookupFunctionEntry(pc, &ib, (void*)0);
    if (fe == (RUNTIME_FUNCTION*)0)
    {
        /* Leaf: RIP = [RSP], RSP += 8. */
        unsigned long long* rsp = ctx_rsp(c);
        unsigned long long ra = *(unsigned long long*)(*rsp);
        *ctx_rip(c) = ra;
        *rsp += 8;
        return ra != 0;
    }
    unsigned long long est = 0;
    RtlVirtualUnwind(0, ib, pc, fe, c, (void**)0, &est, (void*)0);
    return *ctx_rip(c) != 0;
}

/* ---- Vectored Exception Handlers (VEH).
 *
 * Windows keeps the VEH chain in ntdll (RtlAddVectoredException-
 * Handler); kernel32!AddVectoredExceptionHandler is a thin
 * forwarder. The chain is consulted by the dispatcher BEFORE the
 * frame-based __try/__except search — a vectored handler can fix
 * up the CONTEXT and resume (EXCEPTION_CONTINUE_EXECUTION) or
 * decline (EXCEPTION_CONTINUE_SEARCH). Chrome / V8 / Crashpad rely
 * on VEH heavily.
 *
 * GAP: the registry is a fixed array with no lock — correct for
 * single-threaded callers; a real cross-thread Add/Remove race is
 * the multiprocess-sandbox slice's concern. Revisit when threaded
 * Chrome procs land. ---- */
typedef long(__attribute__((ms_abi)) * PVECTORED_HANDLER)(void* /*ExceptionPointers*/);

#define VEH_MAX 32
static PVECTORED_HANDLER g_veh[VEH_MAX];
static unsigned g_veh_count;

__declspec(dllexport) void* RtlAddVectoredExceptionHandler(unsigned long First, void* Handler)
{
    if (Handler == (void*)0 || g_veh_count >= VEH_MAX)
        return (void*)0;
    if (First)
    {
        for (unsigned i = g_veh_count; i > 0; --i)
            g_veh[i] = g_veh[i - 1];
        g_veh[0] = (PVECTORED_HANDLER)Handler;
    }
    else
    {
        g_veh[g_veh_count] = (PVECTORED_HANDLER)Handler;
    }
    ++g_veh_count;
    return Handler; /* handle == the handler pointer */
}

__declspec(dllexport) unsigned long RtlRemoveVectoredExceptionHandler(void* Handle)
{
    for (unsigned i = 0; i < g_veh_count; ++i)
    {
        if ((void*)g_veh[i] == Handle)
        {
            for (unsigned j = i + 1; j < g_veh_count; ++j)
                g_veh[j - 1] = g_veh[j];
            --g_veh_count;
            return 1;
        }
    }
    return 0;
}

/* Run the VEH chain. Returns 1 if a handler asked to continue
 * execution (caller must RtlRestoreContext), 0 to fall through to
 * the frame-based search. EXCEPTION_POINTERS { rec, ctx }. */
static int call_vectored(void* ExceptionRecord, void* ContextRecord)
{
    void* ep[2];
    ep[0] = ExceptionRecord;
    ep[1] = ContextRecord;
    for (unsigned i = 0; i < g_veh_count; ++i)
    {
        long d = g_veh[i](ep);
        if (d == -1) /* EXCEPTION_CONTINUE_EXECUTION */
            return 1;
        /* 0 = EXCEPTION_CONTINUE_SEARCH → next handler. */
    }
    return 0;
}

/* ---- The exception-dispatch core. First the VEH chain, then the
 * frame-based __try/__except walk. A handler that handles the
 * exception calls RtlUnwindEx and never returns;
 * ExceptionContinueExecution resumes the (possibly handler-edited)
 * context; ExceptionContinueSearch keeps walking. Unhandled →
 * terminate the process. Non-static + stable name so the naked
 * KiUserExceptionDispatcher trampoline can `call` it. ---- */
__attribute__((noreturn)) void KiUserExceptionDispatcherImpl(void* ExceptionRecord, void* ContextRecord)
{
    if (call_vectored(ExceptionRecord, ContextRecord))
        RtlRestoreContext(ContextRecord, ExceptionRecord); /* noreturn */

    unsigned char work[1232];
    for (unsigned i = 0; i < 1232; ++i)
        work[i] = ((unsigned char*)ContextRecord)[i];

    for (int depth = 0; depth < 256; ++depth)
    {
        unsigned long long pc = *ctx_rip(work);
        if (pc == 0)
            break;
        unsigned long long ib = 0;
        RUNTIME_FUNCTION* fe = (RUNTIME_FUNCTION*)RtlLookupFunctionEntry(pc, &ib, (void*)0);
        if (fe == (RUNTIME_FUNCTION*)0)
        {
            /* No unwind data — leaf frame; step over and continue
             * the search (its caller may have a __try). */
            if (!unwind_one(work))
                break;
            continue;
        }

        void* handler = (void*)0;
        void* hdata = (void*)0;
        unsigned long long establisher = 0;
        unsigned char flags = read_unwind_handler(ib, fe, work, &handler, &hdata, &establisher);

        if ((flags & UNW_FLAG_EHANDLER) && handler != (void*)0)
        {
            DISPATCHER_CONTEXT dc;
            dc.ControlPc = pc;
            dc.ImageBase = ib;
            dc.FunctionEntry = fe;
            dc.EstablisherFrame = establisher;
            dc.TargetIp = 0;
            dc.ContextRecord = ContextRecord; /* original fault ctx */
            dc.LanguageHandler = handler;
            dc.HandlerData = hdata;
            dc.HistoryTable = (void*)0;
            dc.ScopeIndex = 0;
            dc.Fill0 = 0;
            PEXCEPTION_ROUTINE lang = (PEXCEPTION_ROUTINE)handler;
            long disp = lang(ExceptionRecord, (void*)establisher, ContextRecord, &dc);
            /* 0 = ExceptionContinueExecution, 1 = ContinueSearch.
             * A handler that executes its __except has already
             * called RtlUnwindEx and never returns here. */
            if (disp == 0)
                RtlRestoreContext(ContextRecord, ExceptionRecord); /* noreturn */
            /* else keep searching outward. */
        }

        if (!unwind_one(work))
            break;
    }

    /* Unhandled exception: terminate the process. SYS_EXIT(code).
     * Use the exception code's low byte as the exit status so a
     * crashing PE still reports failure. */
    {
        long long code = (long long)(*er_code(ExceptionRecord));
        __asm__ volatile("int $0x80" : : "a"((long long)0), "D"(code) : "memory");
    }
    DUET_USER_TRAP_UNREACHABLE();
}

/* KiUserExceptionDispatcher: kernel resumes the faulting thread
 * here with rcx = EXCEPTION_RECORD, rdx = CONTEXT and rsp ≡ 8
 * (mod 16) (post-CALL shape). Naked: re-align + reserve shadow
 * space, then tail into the C core (which never returns). */
__attribute__((naked)) __declspec(dllexport) void KiUserExceptionDispatcher(void)
{
    __asm__ volatile("subq $0x28, %%rsp\n\t" /* 0x20 shadow + 8 → 16-align before call */
                     "call KiUserExceptionDispatcherImpl\n\t"
                     "ud2\n\t" ::
                         : "memory");
}

/* RtlUnwindEx: unwind from the current context to TargetFrame,
 * running each frame's termination handler (__finally / SEH
 * unwind handler) along the way, then resume at TargetIp with
 * Rax = ReturnValue. Does not return. */
__declspec(dllexport) void RtlUnwindEx(void* TargetFrame, void* TargetIp, void* ExceptionRecord, void* ReturnValue,
                                       void* ContextRecord, void* HistoryTable)
{
    (void)HistoryTable;
    unsigned char c[1232];
    for (unsigned i = 0; i < 1232; ++i)
        c[i] = ((unsigned char*)ContextRecord)[i];

    *er_flags(ExceptionRecord) |= EXCEPTION_UNWINDING;

    for (int depth = 0; depth < 256; ++depth)
    {
        unsigned long long pc = *ctx_rip(c);
        if (pc == 0)
            break;
        unsigned long long ib = 0;
        RUNTIME_FUNCTION* fe = (RUNTIME_FUNCTION*)RtlLookupFunctionEntry(pc, &ib, (void*)0);
        if (fe == (RUNTIME_FUNCTION*)0)
        {
            if (!unwind_one(c))
                break;
            continue;
        }

        void* handler = (void*)0;
        void* hdata = (void*)0;
        unsigned long long establisher = 0;
        unsigned char flags = read_unwind_handler(ib, fe, c, &handler, &hdata, &establisher);

        const int is_target = (establisher == (unsigned long long)TargetFrame);

        if ((flags & UNW_FLAG_UHANDLER) && handler != (void*)0)
        {
            unsigned int saved = *er_flags(ExceptionRecord);
            if (is_target)
                *er_flags(ExceptionRecord) = saved | EXCEPTION_TARGET_UNWIND;
            DISPATCHER_CONTEXT dc;
            dc.ControlPc = pc;
            dc.ImageBase = ib;
            dc.FunctionEntry = fe;
            dc.EstablisherFrame = establisher;
            dc.TargetIp = (unsigned long long)TargetIp;
            dc.ContextRecord = ContextRecord;
            dc.LanguageHandler = handler;
            dc.HandlerData = hdata;
            dc.HistoryTable = (void*)0;
            dc.ScopeIndex = 0;
            dc.Fill0 = 0;
            PEXCEPTION_ROUTINE lang = (PEXCEPTION_ROUTINE)handler;
            lang(ExceptionRecord, (void*)establisher, ContextRecord, &dc);
            *er_flags(ExceptionRecord) = saved;
        }

        if (is_target)
            break;

        if (!unwind_one(c))
            break;
    }

    /* Resume in the target frame at TargetIp. Rebuild the resume
     * context from the original fault context (registers the
     * handler block expects) but with Rip = TargetIp and the
     * unwound Rsp/Rbp of the target frame. */
    {
        unsigned char r[1232];
        for (unsigned i = 0; i < 1232; ++i)
            r[i] = ((unsigned char*)ContextRecord)[i];
        *(unsigned long long*)((unsigned char*)r + CTX_RSP) = *(unsigned long long*)((unsigned char*)c + CTX_RSP);
        *(unsigned long long*)((unsigned char*)r + CTX_RBP) = *(unsigned long long*)((unsigned char*)c + CTX_RBP);
        *(unsigned long long*)((unsigned char*)r + CTX_RIP) = (unsigned long long)TargetIp;
        *(unsigned long long*)((unsigned char*)r + CTX_RAX) = (unsigned long long)ReturnValue;
        RtlRestoreContext(r, ExceptionRecord);
    }
    DUET_USER_TRAP_UNREACHABLE();
}

/* RtlUnwind — legacy 4-arg form; forward to RtlUnwindEx with a
 * captured context. */
__declspec(dllexport) void RtlUnwind(void* TargetFrame, void* TargetIp, void* ExceptionRecord, void* ReturnValue)
{
    unsigned char ctx[1232];
    for (unsigned i = 0; i < 1232; ++i)
        ctx[i] = 0;
    extern void RtlCaptureContext(void* ContextRecord);
    RtlCaptureContext(ctx);
    RtlUnwindEx(TargetFrame, TargetIp, ExceptionRecord, ReturnValue, ctx, (void*)0);
}

/* __C_specific_handler — the MSVC/mingw language handler for
 * __try/__except/__finally. Reads the SCOPE_TABLE the compiler
 * emitted as the handler data, finds the scope covering the fault
 * PC, evaluates the __except filter, and on
 * EXCEPTION_EXECUTE_HANDLER unwinds to the handler block. In the
 * unwind pass it runs __finally termination handlers. */
typedef long(__attribute__((ms_abi)) * PEXCEPT_FILTER)(void* /*ExceptionPointers*/, void* /*EstablisherFrame*/);
typedef void(__attribute__((ms_abi)) * PTERM_HANDLER)(unsigned char /*abnormal*/, void* /*EstablisherFrame*/);

__declspec(dllexport) long __C_specific_handler(void* ExceptionRecord, void* EstablisherFrame, void* ContextRecord,
                                                void* DispatcherContext)
{
    DISPATCHER_CONTEXT* dc = (DISPATCHER_CONTEXT*)DispatcherContext;
    const unsigned int* st = (const unsigned int*)dc->HandlerData; /* SCOPE_TABLE */
    const unsigned int count = st[0];
    const unsigned int* recs = st + 1; /* 4 u32 per record */
    const unsigned long long IB = dc->ImageBase;
    const unsigned long long pc = dc->ControlPc;
    const int unwinding = (*er_flags(ExceptionRecord) & EXCEPTION_UNWINDING) != 0;

    for (unsigned i = dc->ScopeIndex; i < count; ++i)
    {
        const unsigned int begin = recs[i * 4 + 0];
        const unsigned int end = recs[i * 4 + 1];
        const unsigned int haddr = recs[i * 4 + 2];
        const unsigned int target = recs[i * 4 + 3];
        if (pc < IB + begin || pc >= IB + end)
            continue;

        if (!unwinding)
        {
            if (target == 0)
                continue; /* __finally — not in the search pass */
            long filt;
            if (haddr == 1)
            {
                filt = 1; /* EXCEPTION_EXECUTE_HANDLER, no filter */
            }
            else
            {
                /* EXCEPTION_POINTERS { rec, ctx } on the stack. */
                void* ep[2];
                ep[0] = ExceptionRecord;
                ep[1] = ContextRecord;
                PEXCEPT_FILTER filter = (PEXCEPT_FILTER)(IB + haddr);
                filt = filter(ep, EstablisherFrame);
            }
            if (filt < 0)
                return 0; /* EXCEPTION_CONTINUE_EXECUTION → ContinueExecution */
            if (filt > 0)
            {
                /* EXCEPTION_EXECUTE_HANDLER: unwind to this frame
                 * and resume at the __except block. Noreturn. */
                RtlUnwindEx(EstablisherFrame, (void*)(IB + target), ExceptionRecord,
                            (void*)(unsigned long long)(*er_code(ExceptionRecord)), dc->ContextRecord,
                            dc->HistoryTable);
            }
            /* filt == 0: EXCEPTION_CONTINUE_SEARCH — keep scanning. */
        }
        else
        {
            /* Unwind pass: run __finally termination handlers for
             * scopes being exited (JumpTarget == 0). */
            if (target == 0 && haddr != 0 && haddr != 1)
            {
                PTERM_HANDLER term = (PTERM_HANDLER)(IB + haddr);
                term(1 /*abnormal*/, EstablisherFrame);
            }
        }
    }
    return 1; /* ExceptionContinueSearch */
}

/* NtRaiseException — software-raised structured exception. With
 * HandleException (FirstChance) TRUE this funnels through the same
 * frame-walking dispatcher as a hardware fault: a covering handler
 * catches it (control transfers, never returns); otherwise the
 * process terminates. FirstChance FALSE means "second chance, no
 * more handlers" — terminate directly. The NTSTATUS return type is
 * kept for ABI shape; this never actually returns to the caller. */
__declspec(dllexport) NTSTATUS NtRaiseException(void* ExceptionRecord, void* ContextRecord, BOOL HandleException)
{
    if (HandleException && ExceptionRecord != (void*)0 && ContextRecord != (void*)0)
        KiUserExceptionDispatcherImpl(ExceptionRecord, ContextRecord); /* noreturn */
    {
        long long code = ExceptionRecord ? (long long)(*er_code(ExceptionRecord)) : 0;
        __asm__ volatile("int $0x80" : : "a"((long long)0), "D"(code) : "memory");
    }
    DUET_USER_TRAP_UNREACHABLE();
}
