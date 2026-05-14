/*
 * DuetOS — UBSAN klog runtime implementation, v0 (plan D5).
 *
 * See `ubsan.h` for the public contract. This TU answers the
 * `__ubsan_handle_*` calls clang/gcc generate under
 * `-fsanitize=undefined -fno-sanitize-trap=all`.
 *
 * Each handler logs one structured line via klog and returns. The
 * compiler treats the call as "may return" so execution proceeds —
 * the kernel keeps running with whatever undefined value it just
 * computed. That's the v0 behaviour: visibility, not enforcement.
 * A future debug-build knob (e.g. `g_ubsan_panic_on_hit`) can flip
 * to halt-on-first-hit for adversarial test runs.
 *
 * Source-location structs are clang's documented ABI (see
 * compiler-rt/lib/ubsan/ubsan_handlers.h). Layouts copied here
 * verbatim — they're stable across LLVM versions because the
 * compiler's emitted call sites depend on the exact field order.
 */

#include "diag/ubsan.h"

#include "arch/x86_64/serial.h"
#include "log/klog.h"
#include "util/saturating.h"
#include "util/types.h"

namespace duetos::diag
{

namespace
{

// Per-handler total — saturating per class BB. An adversarial path
// that keeps hitting one UBSAN handler cannot wrap the report count
// to zero and fool the "report freshness" health probe.
constinit util::SatU64 g_reports = 0;

// Source location pointed to by every handler. Filename is a string
// literal embedded in the calling TU's rodata; we don't own it.
struct SourceLocation
{
    const char* filename;
    u32 line;
    u32 column;
};

// Type descriptor — variable-length name field. Used by the
// type-mismatch handler. We only read `name` (the printable name),
// never the encoded `kind` / `info` fields.
struct TypeDescriptor
{
    u16 kind; // 0 = integer, 1 = float, 0xFFFF = unknown
    u16 info; // signedness / width — we don't decode it
    char name[1];
};

struct TypeMismatchData
{
    SourceLocation loc;
    const TypeDescriptor* type;
    u8 log_alignment;
    u8 type_check_kind;
};

struct OverflowData
{
    SourceLocation loc;
    const TypeDescriptor* type;
};

struct ShiftOutOfBoundsData
{
    SourceLocation loc;
    const TypeDescriptor* lhs_type;
    const TypeDescriptor* rhs_type;
};

struct OutOfBoundsData
{
    SourceLocation loc;
    const TypeDescriptor* array_type;
    const TypeDescriptor* index_type;
};

struct InvalidValueData
{
    SourceLocation loc;
    const TypeDescriptor* type;
};

struct NonNullArgData
{
    SourceLocation loc;
    SourceLocation attr_loc;
    int arg_index;
};

struct UnreachableData
{
    SourceLocation loc;
};

struct PointerOverflowData
{
    SourceLocation loc;
};

struct InvalidBuiltinData
{
    SourceLocation loc;
    u8 kind;
};

struct AlignmentAssumptionData
{
    SourceLocation loc;
    SourceLocation assumption_loc;
    const TypeDescriptor* type;
};

// Centralised report path. Keeps every handler down to one line of
// glue and ensures every report increments the counter, so a future
// runtime checker can ask "any UB since boot?" in O(1) (see
// `UbsanReportsEmitted` / `inspect health`).
//
// Two outputs per incident:
//
//   1. A verbatim "[ubsan] <kind> at <file>:<line>:<col>\n" serial
//      line. Host-side tooling already greps for this anchor, so
//      the format is stable. Bypasses klog level/area gating —
//      host capture wants every incident on the wire.
//
//   2. One klog WARN line whose MESSAGE field carries the UBSan
//      kind ("add-overflow", "type-mismatch", …) — NOT a generic
//      placeholder. Previously this path routed through
//      diag::FaultReactDispatch with kind=Unknown, which logged
//      `[W] diag/ubsan : unknown   val=...` and made the BSOD's
//      recent-klog tail (which renders only `subsystem : message`
//      from the in-kernel ring) read as `[W] DIAG/UBSAN : UNKNOWN`
//      for every UBSan incident. The dispatcher's only effect was
//      that log line — bookkeeping is already covered by g_reports
//      and surfaced through `inspect health` — so we log directly
//      with the actual kind, keeping the BSOD tail informative.
void Report(const char* kind, const SourceLocation* loc)
{
    ++g_reports;

    const char* file = (loc != nullptr && loc->filename != nullptr) ? loc->filename : "<no-loc>";

    // Detailed serial line, preserved verbatim — host-side
    // tooling already greps for "[ubsan]" and the file:line:col
    // anchor, so we keep the format stable.
    if (loc != nullptr && loc->filename != nullptr)
    {
        arch::SerialWrite("[ubsan] ");
        arch::SerialWrite(kind);
        arch::SerialWrite(" at ");
        arch::SerialWrite(loc->filename);
        arch::SerialWrite(":");
        arch::SerialWriteHex(loc->line);
        arch::SerialWrite(":");
        arch::SerialWriteHex(loc->column);
        arch::SerialWrite("\n");
    }

    // klog ring entry — message = kind so the in-ring entry
    // (and therefore the BSOD recent-log tail) carries the
    // failing UBSan class, not a generic placeholder. The
    // labelled `file` string keeps the source anchor on serial
    // and any registered tee; the line/column are already on
    // the "[ubsan]" serial line above. UBSan handlers can run
    // from any context the compiler emitted them in (including
    // IRQ); klog is IRQ-safe (no locks, no allocation).
    KLOG_WARN_S("diag/ubsan", kind, "at", file);
}

} // namespace

u64 UbsanReportsEmitted()
{
    return g_reports;
}

// Deliberately trigger a signed-integer overflow so the
// compiler's `-fsanitize=undefined` instrumentation calls
// `__ubsan_handle_add_overflow` for real, exercising the entire
// emit-path (not just the synthetic Report() call). The volatile
// inputs prevent constant-folding; without `volatile` clang
// would const-fold the overflow and skip the handler emit
// entirely. Only compiled into the path when the kernel itself
// is built with the UBSAN compile flag (preset
// `x86_64-debug-ubsan` defines `DUETOS_UBSAN=1`); under any
// other preset this is a no-op so the daily release build sees
// no overhead. (D5-followup, 2026-04-27.)
#if defined(DUETOS_UBSAN) && DUETOS_UBSAN
static void UbsanPresetSmoke()
{
    arch::SerialWrite("[ubsan] preset smoke: triggering signed-integer overflow on purpose\n");
    // `volatile` on every load and the result keeps clang from
    // const-folding the overflow at compile time. The
    // -fsanitize=signed-integer-overflow instrumentation lands on
    // the `+` and emits __ubsan_handle_add_overflow at runtime.
    volatile int a = 0x7FFFFFFE;
    volatile int b = 0x7FFFFFFE;
    volatile int c = static_cast<int>(a + b); // UB by design
    (void)c;
}
#endif

void UbsanSelfTest()
{
    arch::SerialWrite("[ubsan] self-test: synthesising one report via the runtime path\n");

    const u64 before = g_reports;
    SourceLocation fake_loc = {.filename = "ubsan-selftest", .line = 0xCAFE, .column = 1};
    Report("selftest-synthetic", &fake_loc);
    if (g_reports != before + 1)
    {
        arch::SerialWrite("[ubsan] self-test FAILED: counter did not advance\n");
        return; // not a panic — UBSAN is purely diagnostic
    }
    arch::SerialWrite("[ubsan] self-test OK (runtime linked + counter advanced).\n");

#if defined(DUETOS_UBSAN) && DUETOS_UBSAN
    // Preset-only smoke: confirm the compiler instrumentation
    // reaches our handler. The Report() path advanced once
    // above; if instrumentation works, it advances again here.
    const u64 preset_before = g_reports;
    UbsanPresetSmoke();
    if (g_reports == preset_before)
    {
        arch::SerialWrite("[ubsan] PRESET SMOKE FAILED: signed overflow did not trigger handler.\n");
        arch::SerialWrite("[ubsan]   build flags missing? expected -fsanitize=undefined\n");
    }
    else
    {
        arch::SerialWrite("[ubsan] preset smoke OK (compiler-emitted handler reached runtime).\n");
    }
#endif
}

} // namespace duetos::diag

// ---------------------------------------------------------------
// extern "C" handler implementations.
//
// Names + arg shapes match clang/gcc's `-fsanitize=undefined`
// emitted call sites verbatim (see compiler-rt/lib/ubsan).
// ---------------------------------------------------------------

extern "C"
{

    using ::duetos::diag::AlignmentAssumptionData;
    using ::duetos::diag::InvalidBuiltinData;
    using ::duetos::diag::InvalidValueData;
    using ::duetos::diag::NonNullArgData;
    using ::duetos::diag::OutOfBoundsData;
    using ::duetos::diag::OverflowData;
    using ::duetos::diag::PointerOverflowData;
    using ::duetos::diag::ShiftOutOfBoundsData;
    using ::duetos::diag::TypeMismatchData;
    using ::duetos::diag::UnreachableData;

    // Re-introduce the kernel typedef inside the extern "C" block —
    // `using` works through the language-linkage block, and avoids
    // hard-coding `unsigned long long` in every signature.
    using ::duetos::u64;

    // We can't refer to the static `Report` from this scope, so re-
    // expose a thin shim. The forward-declared kind constants are
    // just string literals, kept short so a typical klog line stays
    // inside the 256-byte ring entry width.
    namespace
    {
    void Emit(const char* kind, const ::duetos::diag::SourceLocation* loc)
    {
        ::duetos::diag::Report(kind, loc);
    }
    } // namespace

    void __ubsan_handle_add_overflow(void* data, u64, u64)
    {
        Emit("add-overflow", &reinterpret_cast<OverflowData*>(data)->loc);
    }
    void __ubsan_handle_sub_overflow(void* data, u64, u64)
    {
        Emit("sub-overflow", &reinterpret_cast<OverflowData*>(data)->loc);
    }
    void __ubsan_handle_mul_overflow(void* data, u64, u64)
    {
        Emit("mul-overflow", &reinterpret_cast<OverflowData*>(data)->loc);
    }
    void __ubsan_handle_negate_overflow(void* data, u64)
    {
        Emit("negate-overflow", &reinterpret_cast<OverflowData*>(data)->loc);
    }
    void __ubsan_handle_divrem_overflow(void* data, u64, u64)
    {
        Emit("divrem-overflow", &reinterpret_cast<OverflowData*>(data)->loc);
    }
    void __ubsan_handle_shift_out_of_bounds(void* data, u64, u64)
    {
        Emit("shift-out-of-bounds", &reinterpret_cast<ShiftOutOfBoundsData*>(data)->loc);
    }
    void __ubsan_handle_out_of_bounds(void* data, u64)
    {
        Emit("array-oob", &reinterpret_cast<OutOfBoundsData*>(data)->loc);
    }
    void __ubsan_handle_load_invalid_value(void* data, u64)
    {
        Emit("load-invalid-value", &reinterpret_cast<InvalidValueData*>(data)->loc);
    }
    void __ubsan_handle_type_mismatch_v1(void* data, u64)
    {
        // Covers null deref / unaligned access / unrelated-type access.
        // We don't decode the kind in v0 — the source location alone
        // tells the dev which line to look at.
        Emit("type-mismatch", &reinterpret_cast<TypeMismatchData*>(data)->loc);
    }
    void __ubsan_handle_pointer_overflow(void* data, u64, u64)
    {
        Emit("pointer-overflow", &reinterpret_cast<PointerOverflowData*>(data)->loc);
    }
    void __ubsan_handle_invalid_builtin(void* data)
    {
        Emit("invalid-builtin", &reinterpret_cast<InvalidBuiltinData*>(data)->loc);
    }
    void __ubsan_handle_alignment_assumption(void* data, u64, u64, u64)
    {
        Emit("alignment-assumption", &reinterpret_cast<AlignmentAssumptionData*>(data)->loc);
    }
    void __ubsan_handle_nonnull_arg(void* data)
    {
        Emit("nonnull-arg-violated", &reinterpret_cast<NonNullArgData*>(data)->loc);
    }
    void __ubsan_handle_builtin_unreachable(void* data)
    {
        // Compiler-emitted "we proved this can't happen" landed at
        // runtime — the strongest "we have a bug" signal in the set.
        Emit("builtin-unreachable", &reinterpret_cast<UnreachableData*>(data)->loc);
    }

} // extern "C"
