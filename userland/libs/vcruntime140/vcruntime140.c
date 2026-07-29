/*
 * userland/libs/vcruntime140/vcruntime140.c
 *
 * Freestanding DuetOS vcruntime140.dll — memory intrinsics
 * (memset / memcpy / memmove). Retires the corresponding flat stubs
 * in kernel/subsystems/win32/thunks.cpp.
 *
 * These three functions are the workhorse of any MSVC-built
 * PE: the CRT uses them for virtually every non-trivial data
 * movement, and clang itself generates direct calls to them
 * for large aggregate copies and zero-inits (`struct s = {0};`,
 * `*p = other_struct;`, etc.).
 *
 * All three implementations are byte-at-a-time loops so the
 * compiler can't "optimise" them into... calls to themselves.
 * `__attribute__((no_builtin("memset", "memcpy", "memmove")))`
 * and `-fno-builtin` on the command line cooperate to keep
 * the bodies loop-shaped.
 *
 * Build: tools/build/build-vcruntime140-dll.sh
 *   clang --target=x86_64-pc-windows-msvc + lld-link /dll
 *   /noentry /nodefaultlib /base:0x10030000.
 */

typedef unsigned long long size_t;

/* Every MSVC C++ object that uses floating point references
 * `_fltused`; every C++ EH TypeDescriptor embeds a pointer to
 * `type_info`'s vftable (`??_7type_info@@6B@`). The vtable is never
 * dereferenced by our personality (we only read TypeDescriptor.name
 * — see __CxxFrameHandler3), so a single null slot is sufficient
 * for linking + type matching. Both are exported so MSVC C++ PEs
 * resolve them against vcruntime140. */
__declspec(dllexport) int _fltused = 0x9875;
__asm__(".section .rdata,\"dr\"\n\t"
        ".globl \"??_7type_info@@6B@\"\n\t"
        "\"??_7type_info@@6B@\":\n\t"
        ".quad 0\n\t");

/* `(a)buf_*` annotations keep clang from "helpfully" recognising
 * the loops as memset/memcpy and turning them into tail calls
 * to themselves. -fno-builtin in the build script does the same
 * at a coarser granularity; the attributes are belt + braces. */
#define NO_BUILTIN_MEMOPS __attribute__((no_builtin("memset", "memcpy", "memmove")))

__declspec(dllexport) NO_BUILTIN_MEMOPS void* memset(void* dst, int c, size_t n)
{
    unsigned char* d = (unsigned char*)dst;
    const unsigned char v = (unsigned char)c;
    for (size_t i = 0; i < n; ++i)
        d[i] = v;
    return dst;
}

__declspec(dllexport) NO_BUILTIN_MEMOPS void* memcpy(void* dst, const void* src, size_t n)
{
    unsigned char* d = (unsigned char*)dst;
    const unsigned char* s = (const unsigned char*)src;
    for (size_t i = 0; i < n; ++i)
        d[i] = s[i];
    return dst;
}

/* memmove has to handle overlap: if dst > src but dst < src+n,
 * a forward copy clobbers the source before it's read. Detect
 * the overlap-going-forward case and copy backward. */
__declspec(dllexport) NO_BUILTIN_MEMOPS void* memmove(void* dst, const void* src, size_t n)
{
    unsigned char* d = (unsigned char*)dst;
    const unsigned char* s = (const unsigned char*)src;
    if (d == s || n == 0)
        return dst;
    if (d < s)
    {
        for (size_t i = 0; i < n; ++i)
            d[i] = s[i];
    }
    else
    {
        for (size_t i = n; i > 0; --i)
            d[i - 1] = s[i - 1];
    }
    return dst;
}

__declspec(dllexport) NO_BUILTIN_MEMOPS int memcmp(const void* a, const void* b, size_t n)
{
    const unsigned char* x = (const unsigned char*)a;
    const unsigned char* y = (const unsigned char*)b;
    for (size_t i = 0; i < n; ++i)
        if (x[i] != y[i])
            return (int)x[i] - (int)y[i];
    return 0;
}

__declspec(dllexport) NO_BUILTIN_MEMOPS void* memchr(const void* ptr, int c, size_t n)
{
    const unsigned char* p = (const unsigned char*)ptr;
    unsigned char ch = (unsigned char)c;
    for (size_t i = 0; i < n; ++i)
        if (p[i] == ch)
            return (void*)(p + i);
    return (void*)0;
}

/* ------------------------------------------------------------------
 * SEH / C++ exception support
 *
 * The two-pass dispatch + unwind engine lives in ntdll. This file
 * supplies the MSVC C++ personality + throw entry on top of it:
 *
 * - __CxxFrameHandler3 / __CxxFrameHandler4 — REAL FH3 personality
 *   (FuncInfo/ip2state/try/catch decode, type match, destructor
 *   unwind, catch funclet). See the block below for the algorithm
 *   and bounded GAPs.
 *
 * - _CxxThrowException — builds the C++ EXCEPTION_RECORD
 *   (0xE06D7363) and enters ntdll's NtRaiseException dispatcher.
 *
 * - __C_specific_handler — PE forwarder to ntdll's real
 *   scope-table walker (link line, not a body here).
 *
 * - _purecall / __std_terminate — terminate.
 * - __std_exception_copy / _destroy — no-op.
 * - __vcrt_InitializeCriticalSectionEx — forward to Init CS.
 * ------------------------------------------------------------------ */

#define SEH_NORETURN __attribute__((noreturn))
#define DUET_USER_TRAP_UNREACHABLE()                                                                                   \
    do                                                                                                                 \
    {                                                                                                                  \
        __asm__ volatile("ud2" ::: "memory");                                                                          \
        __builtin_unreachable();                                                                                       \
    } while (0)

/* __C_specific_handler is NOT defined here. It is a PE forwarder to
 * ntdll's real scope-table walker, declared on the link line — see
 * build-vcruntime140-dll.sh. The local body used to be a constant
 * ExceptionContinueSearch, so a PE that resolved the SEH personality
 * against vcruntime140 rather than ntdll silently lost every
 * __except filter while the working engine sat one DLL away. */

/* ------------------------------------------------------------------
 * MSVC x64 C++ exception handling (FH3).
 *
 * The two-pass dispatch + unwind engine already lives in ntdll
 * (KiUserExceptionDispatcher / RtlUnwindEx / RtlLookupFunctionEntry
 * / RtlVirtualUnwind, entered by the kernel fault path OR by
 * NtRaiseException for software throws). This file only supplies
 * the MSVC C++ *personality* (`__CxxFrameHandler3/4`) and the
 * throw entry (`_CxxThrowException`). ntdll symbols are imported
 * (vcruntime140 links ntdll.lib).
 *
 * Implemented (FH3): FuncInfo / ip2state / try / catch decode,
 * type matching (exact mangled name across the CatchableTypeArray
 * — which already enumerates base classes — plus catch(...)),
 * in-frame destructor unwind, catch-object placement, catch
 * funclet invocation + continuation.
 *
 * GAP — revisit: catch objects requiring a real copy-constructor
 * (only trivial memcpy / by-reference / by-pointer in v0); strict
 * ordering of *inner-frame* destructors vs. the catch body when a
 * throw crosses C++ frames that themselves have destructors (the
 * common scalar / single-cross case is correct); the FH4
 * compressed FuncInfo encoding (FH4 falls back to FH3 decode and
 * only works for the uncompressed subset); ESTypeList /
 * exception-spec.
 *
 * STUB: rethrow. A bare `throw;` compiles to
 * _CxxThrowException(NULL, NULL), and this personality has no
 * record of which exception the running catch is handling, so the
 * re-raise carries a NULL ThrowInfo, matches nothing, and the
 * process dies on the unhandled path. Supplying the in-flight
 * object is the easy half; the hard half is that the re-raise's
 * frame walk arrives back at the SAME function whose ControlPc is
 * still inside the inner try, so the search re-selects the catch it
 * just came from. MSVC resolves that with the tryblock the catch
 * funclet belongs to; wiring it needs the funclet-to-tryblock link
 * threaded through the dispatch, not just a saved object.
 * ------------------------------------------------------------------ */

#define CXX_EXCEPTION 0xE06D7363u
#define CXX_FRAME_MAGIC_VC8 0x19930522u
#define EH_NONCONTINUABLE 0x01u
#define EH_UNWINDING 0x02u
#define EH_EXIT_UNWIND 0x04u
#define EH_TARGET_UNWIND 0x20u
#define HT_IS_REFERENCE 0x08u
#define ExceptionContinueSearch 1L

typedef unsigned int u32_;
typedef int i32_;
typedef unsigned long long u64_;

/* All "pointers" below are 32-bit image-relative (add image base). */
typedef struct
{
    i32_ prev_state; /* toState */
    i32_ action;     /* RVA of the destructor funclet, 0 = none */
} unwind_map_entry;

typedef struct
{
    u32_ adjectives;
    i32_ type_info;      /* RVA of TypeDescriptor, 0 = catch(...) */
    i32_ disp_catch_obj; /* frame disp of the catch variable */
    i32_ handler;        /* RVA of the catch funclet */
    i32_ disp_frame;     /* x64: frame disp passed to the funclet */
} catchblock_info;

typedef struct
{
    i32_ start_level;
    i32_ end_level;
    i32_ catch_level;
    i32_ catchblock_count;
    i32_ catchblock; /* RVA catchblock_info[] */
} tryblock_info;

typedef struct
{
    i32_ ip; /* RVA */
    i32_ state;
} ip2state_entry;

/* MSVC x64 FH3 FuncInfo. Total size = 0x28 (40 bytes). Order MUST
 * match `ehdata.h::_s_FuncInfo` — the compiler emits this layout
 * verbatim into `.xdata`. Missing the `unwind_help` field between
 * `ipmap` and `expect_list` would silently shift `expect_list` and
 * `flags` by 4 bytes; today neither is consumed, but a future read
 * would land on the wrong source bytes. */
typedef struct
{
    u32_ magic;          /* 0x00 — CXX_FRAME_MAGIC_VC{6,7,8} */
    i32_ unwind_count;   /* 0x04 — maxState */
    i32_ unwind_map;     /* 0x08 — RVA unwind_map_entry[] */
    i32_ tryblock_count; /* 0x0C — nTryBlocks */
    i32_ tryblock;       /* 0x10 — RVA tryblock_info[] */
    i32_ ipmap_count;    /* 0x14 — nIPMapEntries */
    i32_ ipmap;          /* 0x18 — RVA ip2state_entry[] */
    i32_ unwind_help;    /* 0x1C — FP offset of unwind helper (x64) */
    i32_ expect_list;    /* 0x20 — RVA ESTypeList (exception spec) */
    i32_ flags;          /* 0x24 — EHFlags */
} cxx_function_descr;

typedef struct
{
    u32_ properties;
    i32_ type_info; /* RVA TypeDescriptor */
    i32_ this_mdisp;
    i32_ this_pdisp;
    i32_ this_vdisp;
    i32_ size;
    i32_ copy_ctor; /* RVA, 0 = bitwise copy */
} catchable_type;

typedef struct
{
    i32_ count;
    i32_ types[1]; /* RVA catchable_type[] */
} catchable_type_array;

typedef struct
{
    u32_ attributes;
    i32_ unwind; /* RVA destructor for the thrown object */
    i32_ forward_compat;
    i32_ catchable_types; /* RVA catchable_type_array */
} throw_info;

typedef struct
{
    void* vtable;
    void* spare;
    char name[1];
} type_descriptor;

/* DISPATCHER_CONTEXT — canonical Windows x64 order; we read the
 * ImageBase + HandlerData (RVA of our FuncInfo). */
typedef struct
{
    u64_ ControlPc;
    u64_ ImageBase;
    void* FunctionEntry;
    u64_ EstablisherFrame;
    u64_ TargetIp;
    void* ContextRecord;
    void* LanguageHandler;
    void* HandlerData;
    void* HistoryTable;
    u32_ ScopeIndex;
    u32_ Fill0;
} CXX_DISPATCHER_CONTEXT;

/* Minimal EXCEPTION_RECORD accessors (layout asserted kernel-side,
 * sizeof == 0x98). */
typedef struct
{
    u32_ ExceptionCode;
    u32_ ExceptionFlags;
    u64_ ExceptionRecordPtr;
    u64_ ExceptionAddress;
    u32_ NumberParameters;
    u32_ _align;
    u64_ ExceptionInformation[15];
} CXX_EXCEPTION_RECORD;

/* ntdll engine (imported — vcruntime140 links ntdll.lib). */
extern void __attribute__((ms_abi)) RtlUnwindEx(void* TargetFrame, void* TargetIp, void* Rec, void* RetVal, void* Ctx,
                                                void* Hist);
extern long __attribute__((ms_abi)) NtRaiseException(void* Rec, void* Ctx, int FirstChance);
extern void* __attribute__((ms_abi)) RtlLookupFunctionEntry(u64_ Pc, u64_* ImageBase, void* Hist);

/* Canonical Windows x64 CONTEXT offset, shared with cxx_throw.S,
 * ntdll/seh_trampolines.S, and kernel seh_dispatch.cpp. */
#define CXX_CONTEXT_RIP_OFF 0xF8u

static int cxx_streq(const char* a, const char* b)
{
    while (*a && *a == *b)
    {
        ++a;
        ++b;
    }
    return *a == 0 && *b == 0;
}

/* Diagnostic — direct SYS_DEBUG_PRINT (46) so vcruntime140 can dump
 * state without depending on kernel32!OutputDebugString. The first
 * throw fires four lines tagged `[cxxeh-dbg]` so a future runtime
 * diagnosis of T6-05 fault #2 (image_base wrong/0, funclet a bare
 * RVA) can grep one boot transcript instead of rebuilding +
 * re-instrumenting. The fault would surface as `funclet=0x000023d8`
 * (or similar low value) with `image_base=...` and the funclet RVA
 * separately printable from `cb->handler`. Gated on a static "first
 * throw" guard so a steady-state PE that throws repeatedly doesn't
 * flood the log. */
static int s_cxxeh_dbg_armed = 1;

static void cxxeh_dbg_emit(const char* s)
{
    long long discard;
    __asm__ volatile("int $0x80" : "=a"(discard) : "a"((long long)46), "D"((long long)s) : "memory");
}

static void cxxeh_dbg_hex64(char* out, unsigned long long v)
{
    /* 16 hex digits + NUL. Caller's buffer must be >= 17 bytes. */
    static const char hex[] = "0123456789abcdef";
    for (int i = 15; i >= 0; --i)
    {
        out[i] = hex[v & 0xFu];
        v >>= 4;
    }
    out[16] = '\0';
}

/* Invoke a catch / destructor funclet. The body lives in
 * cxx_funclet.S: it has to honour the MSVC funclet ABI's
 * establisher-frame spill AND carry real unwind data so a `throw;`
 * inside a catch body can be unwound back out through this frame.
 * See that file for both. */
extern void* __attribute__((ms_abi)) cxx_call_funclet(void* handler, u64_ frame);

static void cxx_local_unwind(u64_ image_base, const cxx_function_descr* d, u64_ frame, int cur, int target)
{
    if (d->unwind_map == 0)
        return;
    const unwind_map_entry* um = (const unwind_map_entry*)(image_base + (u32_)d->unwind_map);
    /* Bound the walk by unwind_count. `prev_state` comes straight out of
     * the image's .xdata, so the chain is attacker-controlled and is NOT
     * guaranteed to strictly decrease toward -1. A self-loop
     * (um[3].prev_state == 3) or a cycle would otherwise re-run the same
     * destructor funclet forever — a double-free / use-after-free of
     * whatever it releases, and an unwind that never returns to
     * RtlUnwindEx. A well-formed chain visits each state at most once, so
     * unwind_count iterations is a sufficient bound; matches the bounded
     * frame walks in ntdll_dispatch.c. */
    for (int steps = 0; steps < d->unwind_count; ++steps)
    {
        if (cur == target || cur < 0 || cur >= d->unwind_count)
            break;
        const int next = um[cur].prev_state;
        if (um[cur].action != 0)
            (void)cxx_call_funclet((void*)(image_base + (u32_)um[cur].action), frame);
        cur = next;
    }
}

static int cxx_state_from_ip(u64_ image_base, const cxx_function_descr* d, u64_ control_pc)
{
    if (d->ipmap == 0 || d->ipmap_count == 0)
        return -1;
    const ip2state_entry* m = (const ip2state_entry*)(image_base + (u32_)d->ipmap);
    const u32_ rva = (u32_)(control_pc - image_base);
    int state = -1;
    for (int i = 0; i < d->ipmap_count; ++i)
    {
        if ((u32_)m[i].ip <= rva)
            state = m[i].state;
        else
            break;
    }
    return state;
}

/* Does the thrown object (throw_info, RVAs vs `throw_base`) satisfy
 * the catch `cb` (type_info RVA vs the handler module `image_base`)?
 * catch(...) (type_info==0) always matches; otherwise exact mangled
 * name against any CatchableType (the array already enumerates base
 * classes, so derived→base catch works). */
static const catchable_type* cxx_match_type(u64_ image_base, const catchblock_info* cb, u64_ throw_base,
                                            const throw_info* ti)
{
    if (cb->type_info == 0)
    {
        static catchable_type any = {0, 0, 0, 0, 0, 0, 0};
        return &any; /* catch(...) — no object typing */
    }
    if (ti == (const throw_info*)0 || ti->catchable_types == 0)
        return (const catchable_type*)0;
    const type_descriptor* want = (const type_descriptor*)(image_base + (u32_)cb->type_info);
    const catchable_type_array* cta = (const catchable_type_array*)(throw_base + (u32_)ti->catchable_types);
    for (int i = 0; i < cta->count; ++i)
    {
        const catchable_type* ct = (const catchable_type*)(throw_base + (u32_)cta->types[i]);
        const type_descriptor* have = (const type_descriptor*)(throw_base + (u32_)ct->type_info);
        if (cxx_streq(want->name, have->name))
            return ct;
    }
    return (const catchable_type*)0;
}

static long __attribute__((ms_abi)) cxx_frame_handler(CXX_EXCEPTION_RECORD* rec, u64_ frame, void* ctx,
                                                      CXX_DISPATCHER_CONTEXT* disp)
{
    const u64_ image_base = disp->ImageBase;
    const cxx_function_descr* d = (const cxx_function_descr*)(image_base + *(u32_*)disp->HandlerData);
    const int cur_state = cxx_state_from_ip(image_base, d, disp->ControlPc);

    const int is_unwinding = (rec->ExceptionFlags & (EH_UNWINDING | EH_EXIT_UNWIND)) != 0;
    const int is_target_unwind = (rec->ExceptionFlags & EH_TARGET_UNWIND) != 0;
    if (is_unwinding && !is_target_unwind)
    {
        /* Pass 2, crossed frame: run every cleanup before the
         * selected catch body is entered at the target frame. */
        if (d->unwind_count != 0)
            cxx_local_unwind(image_base, d, frame, cur_state, -1);
        return ExceptionContinueSearch;
    }

    if (rec->ExceptionCode != CXX_EXCEPTION || rec->NumberParameters < 3)
        return ExceptionContinueSearch; /* not ours */
    if (d->tryblock == 0 || d->tryblock_count == 0)
        return ExceptionContinueSearch;

    const u64_ throw_base = rec->ExceptionInformation[3];
    const throw_info* ti = (const throw_info*)rec->ExceptionInformation[2];
    void* thrown_obj = (void*)rec->ExceptionInformation[1];
    const tryblock_info* tb = (const tryblock_info*)(image_base + (u32_)d->tryblock);

    for (int t = 0; t < d->tryblock_count; ++t)
    {
        if (cur_state < tb[t].start_level || cur_state > tb[t].end_level)
            continue;
        const catchblock_info* cbs = (const catchblock_info*)(image_base + (u32_)tb[t].catchblock);
        for (int c = 0; c < tb[t].catchblock_count; ++c)
        {
            const catchblock_info* cb = &cbs[c];
            const catchable_type* ct = cxx_match_type(image_base, cb, throw_base, ti);
            if (ct == (const catchable_type*)0)
                continue;

            if (!is_target_unwind)
            {
                /* Search pass only selects the target. RtlUnwindEx
                 * revisits this personality with TARGET_UNWIND after
                 * every crossed frame has run its cleanup funclets. */
                RtlUnwindEx((void*)frame, (void*)0, (void*)rec, thrown_obj, ctx, disp->HistoryTable);
                return ExceptionContinueSearch;
            }

            /* Found the handler. Binding kind comes from HandlerType
             * adjectives, not CatchableType properties:
             * HT_IsReference says the catch variable is a reference,
             * while CT_IsSimpleType only describes the thrown type.
             * Confusing them swaps `catch (int)` and `catch (T&)`. */
            if (cb->disp_catch_obj != 0)
            {
                void** slot = (void**)(frame + (u32_)cb->disp_catch_obj);
                if ((cb->adjectives & HT_IS_REFERENCE) != 0)
                {
                    *slot = thrown_obj;
                }
                else if (cb->type_info != 0 && ct->size != 0 && ct->copy_ctor == 0)
                {
                    /* by value, trivially copyable */
                    unsigned char* dstb = (unsigned char*)slot;
                    const unsigned char* srcb = (const unsigned char*)thrown_obj;
                    for (int k = 0; k < ct->size; ++k)
                        dstb[k] = srcb[k];
                }
                else
                {
                    /* Non-trivial by-value construction remains a
                     * bounded GAP until copy-ctor funclets are wired. */
                    *slot = thrown_obj;
                }
            }

            /* Crossed frames are already unwound. Unwind the target
             * frame down to the selected try, then enter the catch. */
            cxx_local_unwind(image_base, d, frame, cur_state, tb[t].start_level - 1);

            void* funclet = (void*)(image_base + (u32_)cb->handler);

            /* Gated diagnostic — fires once on the first throw so a
             * future T6-05-fault-#2 investigation can read the four
             * load-bearing values straight off the boot log without
             * re-instrumenting. The expected shapes:
             *   image_base   = the catch-site module's load address
             *                  (non-zero); a 0 here IS the bug.
             *   cb->handler  = the catch funclet's RVA (small u32).
             *   funclet      = image_base + cb->handler — absolute
             *                  VA in the catch-site module's .text.
             *                  If this equals cb->handler, image_base
             *                  was 0 and the call would fault at a
             *                  bare RVA in .rdata (the reported 0x23d8). */
            const int dbg_this_dispatch = s_cxxeh_dbg_armed;
            if (dbg_this_dispatch)
            {
                s_cxxeh_dbg_armed = 0;
                char buf[80];
                cxxeh_dbg_emit("[cxxeh-dbg] catch dispatch (first throw)\n");
                /* "ib=<hex16>\n" — 21 bytes incl. NUL. */
                buf[0] = 'i';
                buf[1] = 'b';
                buf[2] = '=';
                cxxeh_dbg_hex64(buf + 3, (unsigned long long)image_base);
                buf[19] = '\n';
                buf[20] = '\0';
                cxxeh_dbg_emit(buf);
                buf[0] = 'h';
                buf[1] = 'r';
                buf[2] = '=';
                cxxeh_dbg_hex64(buf + 3, (unsigned long long)(unsigned int)cb->handler);
                buf[19] = '\n';
                buf[20] = '\0';
                cxxeh_dbg_emit(buf);
                buf[0] = 'f';
                buf[1] = 'u';
                buf[2] = '=';
                cxxeh_dbg_hex64(buf + 3, (unsigned long long)funclet);
                buf[19] = '\n';
                buf[20] = '\0';
                cxxeh_dbg_emit(buf);
                buf[0] = 'd';
                buf[1] = 'i';
                buf[2] = '=';
                cxxeh_dbg_hex64(buf + 3, (unsigned long long)disp);
                buf[19] = '\n';
                buf[20] = '\0';
                cxxeh_dbg_emit(buf);
            }

            void* cont = cxx_call_funclet(funclet, frame);

            if (dbg_this_dispatch)
            {
                /* Closes the one-shot block above: the post-funclet
                 * continuation. If the funclet faulted (jumped to a
                 * bare RVA), we never reach this line — the absence
                 * of `[cxxeh-dbg] co=` in the log AFTER the `fu=`
                 * line confirms `call *funclet` was the fault site.
                 *
                 * Keyed off the SAME dispatch, not off "the flag has
                 * been cleared at some point", which fired on every
                 * catch in the process forever and buried the one
                 * line that carries meaning under N that don't. */
                char buf[80];
                buf[0] = 'c';
                buf[1] = 'o';
                buf[2] = '=';
                cxxeh_dbg_hex64(buf + 3, (unsigned long long)cont);
                buf[19] = '\n';
                buf[20] = '\0';
                cxxeh_dbg_emit(buf);
            }

            /* Hand the catch continuation back to RtlUnwindEx. It
             * owns the final restore from the now-fully-unwound
             * CONTEXT and will not return to this personality. */
            disp->TargetIp = (u64_)cont;
            return ExceptionContinueSearch;
        }
    }
    return ExceptionContinueSearch;
}

__declspec(dllexport) long __attribute__((ms_abi)) __CxxFrameHandler3(void* ExceptionRecord, void* EstablisherFrame,
                                                                      void* ContextRecord, void* DispatcherContext)
{
    return cxx_frame_handler((CXX_EXCEPTION_RECORD*)ExceptionRecord, (u64_)EstablisherFrame, ContextRecord,
                             (CXX_DISPATCHER_CONTEXT*)DispatcherContext);
}

/* FH4 uses a compressed FuncInfo. v0 routes it through the FH3
 * decoder, which only handles the uncompressed subset (GAP). */
__declspec(dllexport) long __attribute__((ms_abi)) __CxxFrameHandler4(void* ExceptionRecord, void* EstablisherFrame,
                                                                      void* ContextRecord, void* DispatcherContext)
{
    return cxx_frame_handler((CXX_EXCEPTION_RECORD*)ExceptionRecord, (u64_)EstablisherFrame, ContextRecord,
                             (CXX_DISPATCHER_CONTEXT*)DispatcherContext);
}

/* The exported assembly entry captures a complete, aligned caller
 * CONTEXT before any compiler prologue can perturb register state,
 * then calls this core.  The core remains externally visible only
 * for that assembly reference; _CxxThrowException is the DLL export. */
SEH_NORETURN void __attribute__((ms_abi)) _CxxThrowExceptionImpl(void* object, const void* throwInfo,
                                                                 unsigned char* caller_context)
{
    /* Image base the throw_info RVAs are relative to = the module
     * that owns throwInfo. RtlLookupFunctionEntry sets ImageBase
     * from the containing image even when that address has no
     * individual runtime-function entry. */
    u64_ image_base = 0;
    (void)RtlLookupFunctionEntry((u64_)throwInfo, &image_base, (void*)0);
    const u64_ caller_rip = *(const u64_*)(caller_context + CXX_CONTEXT_RIP_OFF);

    CXX_EXCEPTION_RECORD rec;
    for (unsigned i = 0; i < sizeof(rec); ++i)
        ((unsigned char*)&rec)[i] = 0;
    rec.ExceptionCode = CXX_EXCEPTION;
    rec.ExceptionFlags = EH_NONCONTINUABLE;
    rec.ExceptionAddress = caller_rip;
    rec.NumberParameters = 4;
    rec.ExceptionInformation[0] = CXX_FRAME_MAGIC_VC8;
    rec.ExceptionInformation[1] = (u64_)object;
    rec.ExceptionInformation[2] = (u64_)throwInfo;
    rec.ExceptionInformation[3] = image_base;

    NtRaiseException(&rec, caller_context, 1 /* first chance — enter dispatcher */);
    /* A handler transferred control and we never get here; if no
     * handler matched, NtRaiseException terminated the process. */
    DUET_USER_TRAP_UNREACHABLE();
}

__declspec(dllexport) SEH_NORETURN void _purecall(void)
{
    __asm__ volatile("int $0x80" : : "a"((long long)0), "D"((long long)3));
    DUET_USER_TRAP_UNREACHABLE();
}

__declspec(dllexport) SEH_NORETURN void __std_terminate(void)
{
    __asm__ volatile("int $0x80" : : "a"((long long)0), "D"((long long)3));
    DUET_USER_TRAP_UNREACHABLE();
}

__declspec(dllexport) void __std_exception_copy(void* from, void* to)
{
    (void)from;
    (void)to;
}

__declspec(dllexport) void __std_exception_destroy(void* what)
{
    (void)what;
}

/* __vcrt_InitializeCriticalSectionEx — same contract as
 * kernel32.dll!InitializeCriticalSectionEx: zero the 40-byte
 * CRITICAL_SECTION, return BOOL TRUE. Inlined here so the
 * DLL doesn't depend on kernel32 being loaded first. */
__declspec(dllexport) int __vcrt_InitializeCriticalSectionEx(void* cs, unsigned int spin, unsigned int flags)
{
    (void)spin;
    (void)flags;
    if (cs != (void*)0)
    {
        unsigned char* b = (unsigned char*)cs;
        for (int i = 0; i < 40; ++i)
            b[i] = 0;
    }
    return 1;
}

/* RtlUnwind / RtlUnwindEx stubs — normally provided by
 * ntdll, but some PEs import them via vcruntime140 indirectly.
 * v0 can't unwind; noreturn fall-through to abort. */
__declspec(dllexport) SEH_NORETURN void __CxxUnwind(void* target_frame, void* target_ip, void* exc_record,
                                                    void* return_value)
{
    (void)target_frame;
    (void)target_ip;
    (void)exc_record;
    (void)return_value;
    __asm__ volatile("int $0x80" : : "a"((long long)0), "D"((long long)3));
    DUET_USER_TRAP_UNREACHABLE();
}

/* ------------------------------------------------------------------
 * /GS stack-cookie facade (T9-02 v0)
 *
 * MSVC /GS-protected functions emit a save / check pair around the
 * stack frame. The save reads `__security_cookie` and stores it
 * just below the saved frame pointer; the check reloads it and
 * calls `__security_check_cookie(saved)` on exit. The check function
 * compares against `__security_cookie` and, on mismatch, calls
 * `__report_gsfailure` (noreturn).
 *
 * v0 takes the lowest-effort posture: provide the variable +
 * the check + the failure path as exports. The compiler's
 * save/check pair is a self-consistent comparison of the same
 * value across one function call — no external mutator can flip
 * it — so the no-op check stays "consistent → no false abort".
 * Real cookie randomisation requires the PE loader reading the
 * SecurityCookie field of IMAGE_LOAD_CONFIG_DIRECTORY and
 * stamping a per-image fresh value; that's the T9-02 follow-on.
 *
 * `__security_cookie` lives in vcruntime140's data section so
 * every PE that imports it sees the same backing storage. The
 * value below is the documented MSVC default cookie
 * (`0x00002B992DDFA232` on x64), which the per-image cookie
 * normally overrides at startup. Apps whose CRT calls
 * `__security_init_cookie` (no-op here) keep the default.
 * ------------------------------------------------------------------ */
__declspec(dllexport) unsigned long long __security_cookie = 0x00002B992DDFA232ULL;
__declspec(dllexport) unsigned long long __security_cookie_complement = ~0x00002B992DDFA232ULL;

__declspec(dllexport) void __security_init_cookie(void)
{
    /* No randomness source wired in — leave the default in place. */
}

__declspec(dllexport) void __security_check_cookie(unsigned long long cookie)
{
    /* Compiler's save/check pair compares the value to itself
     * across one function call; if they differ, real corruption
     * occurred. Trip the abort path (matches Windows' contract:
     * `__report_gsfailure` is noreturn). */
    if (cookie != __security_cookie)
    {
        __asm__ volatile("int $0x80" : : "a"((long long)0), "D"((long long)3));
        DUET_USER_TRAP_UNREACHABLE();
    }
}

__declspec(dllexport) SEH_NORETURN void __report_gsfailure(unsigned long long cookie)
{
    (void)cookie;
    __asm__ volatile("int $0x80" : : "a"((long long)0), "D"((long long)3));
    DUET_USER_TRAP_UNREACHABLE();
}

/* MSVC also emits __report_rangefailure for /GS-related range
 * checks (e.g. variable-length array bounds). Treat as fatal. */
__declspec(dllexport) SEH_NORETURN void __report_rangefailure(void)
{
    __asm__ volatile("int $0x80" : : "a"((long long)0), "D"((long long)3));
    DUET_USER_TRAP_UNREACHABLE();
}

/* ------------------------------------------------------------------
 * CFG (Control Flow Guard) facade (T9-03 v0)
 *
 * CFG-enabled binaries (compiled with /guard:cf) call
 * `_guard_check_icall(target)` before each indirect call to verify
 * the target is in the per-image CFG bitmap. The PE loader
 * normally patches the per-image function pointer slots
 * (`__guard_check_icall_fptr`, `__guard_dispatch_icall_fptr`)
 * to point at ntdll's enforcement helpers; absent that, the
 * pointers stay at their compile-time defaults which point at
 * exactly these no-op shims.
 *
 * v0 doesn't enforce CFG — the bitmap isn't materialised — so
 * both helpers reduce to "trust the call." `_guard_check_icall`
 * just returns; `_guard_dispatch_icall` is a naked tail call
 * to whatever target the compiler put in `rax`.
 *
 * Real enforcement waits for a PE loader that walks
 * IMAGE_LOAD_CONFIG_DIRECTORY's GuardCFCheckFunctionPointer
 * field and either patches per-image slots to enforcement
 * helpers or zeroes them so the compiler's default fallback
 * (these shims) runs.
 * ------------------------------------------------------------------ */
__declspec(dllexport) void _guard_check_icall(void* target)
{
    (void)target;
}

/* _guard_dispatch_icall / _guard_xfg_dispatch_icall live in
 * guard_icall.S — both are single-instruction tail-jumps through
 * rax. _guard_xfg_check_icall stays in C because it's a regular
 * (non-naked) function that takes the target pointer and would
 * eventually consult the per-image XFG bitmap (currently a no-op
 * v0 stance). */
__declspec(dllexport) void _guard_xfg_check_icall(void* target)
{
    (void)target;
}
