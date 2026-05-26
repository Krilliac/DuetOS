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

// Pointer-sanity guard for handler arguments. The compiler emits
// UBSan handler calls with a static metadata pointer that's always
// inside the kernel image. If we observe a value that's not in the
// canonical high-half kernel range (≥ 0xFFFFFFFF80000000) — null,
// a small integer cast through, the all-ones sentinel, or any
// userland VA — the call is corrupt and dereferencing it would
// page-fault. The check costs one compare and lets us replace the
// crash with a logged sentinel so the rest of the boot survives.
constexpr u64 kKernelLowBound = 0xFFFFFFFF80000000ULL;
inline bool LooksLikeKernelPtr(const void* p)
{
    const auto v = reinterpret_cast<u64>(p);
    return v >= kKernelLowBound && v != ~u64{0};
}

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

// Emitted by `-fsanitize=integer` (implicit-conversion /
// implicit-integer-truncation / implicit-integer-sign-change).
struct ImplicitConversionData
{
    SourceLocation loc;
    const TypeDescriptor* from_type;
    const TypeDescriptor* to_type;
    u8 kind;
};

// `-fsanitize=nullability-return` / `-fsanitize=returns-nonnull`.
// The real source location is passed as the handler's SECOND
// argument (a SourceLocation*), not embedded in this struct.
struct NonNullReturnData
{
    SourceLocation attr_loc;
};

// `-fsanitize=vla-bound` (part of -fsanitize=undefined).
struct VLABoundData
{
    SourceLocation loc;
    const TypeDescriptor* type;
};

// `-fsanitize=float-cast-overflow` (part of -fsanitize=undefined).
// LLVM >= 5 (toolchain baseline is clang 18+) puts `loc` first.
struct FloatCastOverflowData
{
    SourceLocation loc;
    const TypeDescriptor* from_type;
    const TypeDescriptor* to_type;
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

    // Defensive: every compiler-emitted call passes a static
    // SourceLocation pointer inside the kernel image. If we see
    // something else (null, small int, all-ones sentinel, userland
    // VA) the call is corrupt — dereferencing loc->filename would
    // page-fault and turn one bad caller into a triple-fault.
    // Log the wild pointer to serial + counter and bail. Real
    // recursive call sites (Report from ReportTypeMismatch with a
    // valid d->loc) pass the LooksLikeKernelPtr gate trivially.
    if (!LooksLikeKernelPtr(loc))
    {
        arch::SerialWrite("[ubsan] wild loc= ");
        arch::SerialWriteHex(reinterpret_cast<u64>(loc));
        arch::SerialWrite(" kind=");
        arch::SerialWrite(kind != nullptr ? kind : "<null>");
        arch::SerialWrite(" (handler arg corrupt; skipping deref)\n");
        return;
    }

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

// clang TypeCheckKind enum (compiler-rt/lib/ubsan/ubsan_handlers.cpp).
// The numbering is part of the emitted-call ABI, stable across LLVM.
const char* TypeCheckKindName(u8 k)
{
    switch (k)
    {
    case 0:
        return "load";
    case 1:
        return "store";
    case 2:
        return "reference-bind";
    case 3:
        return "member-access";
    case 4:
        return "member-call";
    case 5:
        return "constructor-call";
    case 6:
        return "downcast-ptr";
    case 7:
        return "downcast-ref";
    case 8:
        return "upcast";
    case 9:
        return "upcast-virtual-base";
    case 10:
        return "nonnull-bind";
    case 11:
        return "dynamic-op";
    default:
        return "kind?";
    }
}

// type-mismatch fires once per *dynamic* hit; a hot path (e.g. a
// password hash) can produce hundreds of identical incidents. The
// stable "[ubsan] type-mismatch at file:line:col" line + g_reports
// counter still fire every time (host tooling + `inspect health`
// depend on that). The richer decode below is what a human needs to
// actually pin the bug, and it only needs to be seen ONCE per call
// site — so dedupe it on the SourceLocation pointer, which is a
// stable rodata literal owned by the calling TU. Best-effort: the
// scan/insert is lock-free and may race under SMP/IRQ reentrancy,
// at worst double-printing one detail line — acceptable for a
// diagnostic, and it keeps this path allocation- and lock-free so
// it stays safe in every context the compiler emitted it in.
constexpr u32 kSeenLocCap = 32;
constinit const SourceLocation* g_seen_locs[kSeenLocCap] = {};
constinit u32 g_seen_loc_count = 0;

bool DetailAlreadyEmitted(const SourceLocation* loc)
{
    for (u32 i = 0; i < g_seen_loc_count && i < kSeenLocCap; ++i)
        if (g_seen_locs[i] == loc)
            return true;
    const u32 slot = g_seen_loc_count;
    if (slot < kSeenLocCap)
    {
        g_seen_locs[slot] = loc;
        g_seen_loc_count = slot + 1;
    }
    return false;
}

// Enriched type-mismatch path. `ptr` is the value that failed the
// check — clang passes it as the handler's second argument and the
// v0 handler threw it away, leaving every incident opaque. With the
// pointer + log_alignment + type_check_kind we can say *which* of
// the three type-mismatch faults this is (null / misaligned /
// object-too-small) instead of just pointing at a line.
void ReportTypeMismatch(const TypeMismatchData* d, u64 ptr)
{
    // Mirror Report's defensive guard: a compiler-emitted call
    // always supplies a static TypeMismatchData* inside the kernel
    // image. A wild d (null, small int, all-ones) means the call
    // was corrupted — derefing &d->loc would still hand Report a
    // wild pointer, and Report's own guard would catch it but only
    // after we'd already taken one extra wild branch. Catch it at
    // the entry so the recursion stops here.
    if (!LooksLikeKernelPtr(d))
    {
        arch::SerialWrite("[ubsan] wild type-mismatch data=");
        arch::SerialWrite(" ");
        arch::SerialWriteHex(reinterpret_cast<u64>(d));
        arch::SerialWrite(" ptr=");
        arch::SerialWriteHex(ptr);
        arch::SerialWrite(" (handler data corrupt; skipping report)\n");
        return;
    }

    Report("type-mismatch", &d->loc);

    if (d->loc.filename == nullptr || DetailAlreadyEmitted(&d->loc))
        return;

    const u64 align = (d->log_alignment < 64) ? (1ULL << d->log_alignment) : 0;
    const char* fault = "obj-too-small";
    if (ptr == 0)
        fault = "null-deref";
    else if (align > 1 && (ptr & (align - 1)) != 0)
        fault = "misaligned";

    arch::SerialWrite("[ubsan]   tm-detail ");
    arch::SerialWrite(TypeCheckKindName(d->type_check_kind));
    arch::SerialWrite(" fault=");
    arch::SerialWrite(fault);
    arch::SerialWrite(" ptr=");
    arch::SerialWriteHex(ptr);
    arch::SerialWrite(" need-align=");
    arch::SerialWriteHex(align);
    if (d->type != nullptr)
    {
        arch::SerialWrite(" ty=");
        arch::SerialWrite(d->type->name);
    }
    arch::SerialWrite("\n");
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
    using ::duetos::diag::FloatCastOverflowData;
    using ::duetos::diag::ImplicitConversionData;
    using ::duetos::diag::InvalidBuiltinData;
    using ::duetos::diag::InvalidValueData;
    using ::duetos::diag::NonNullArgData;
    using ::duetos::diag::NonNullReturnData;
    using ::duetos::diag::OutOfBoundsData;
    using ::duetos::diag::OverflowData;
    using ::duetos::diag::PointerOverflowData;
    using ::duetos::diag::ShiftOutOfBoundsData;
    using ::duetos::diag::TypeMismatchData;
    using ::duetos::diag::UnreachableData;
    using ::duetos::diag::VLABoundData;

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
    void __ubsan_handle_type_mismatch_v1(void* data, u64 ptr)
    {
        // Covers null deref / unaligned access / object-too-small.
        // ReportTypeMismatch decodes which one (and the access kind +
        // failing pointer), deduped per call site so a hot path can't
        // flood serial. The stable "[ubsan] type-mismatch at ..." line
        // + g_reports counter still fire on every hit inside Report().
        ::duetos::diag::ReportTypeMismatch(reinterpret_cast<TypeMismatchData*>(data), ptr);
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

    // ---------------------------------------------------------------
    // Handlers below close the link for every recoverable check the
    // broadened sanitizer flag set can emit. The first four
    // (float-cast-overflow, missing-return, returns-nonnull,
    // vla-bound) are reachable under plain `-fsanitize=undefined`
    // too — without these symbols a single trigger under the
    // existing ubsan preset would be an undefined-symbol link
    // error. implicit-conversion + nullability-arg come in with
    // `-fsanitize=integer,nullability`.
    // ---------------------------------------------------------------

    void __ubsan_handle_float_cast_overflow(void* data, u64)
    {
        Emit("float-cast-overflow", &reinterpret_cast<FloatCastOverflowData*>(data)->loc);
    }
    void __ubsan_handle_missing_return(void* data)
    {
        // Control fell off the end of a value-returning function —
        // the caller is about to use a garbage return value. Always
        // a real bug (UB), never a false positive.
        Emit("missing-return", &reinterpret_cast<UnreachableData*>(data)->loc);
    }
    void __ubsan_handle_vla_bound_not_positive(void* data, u64)
    {
        Emit("vla-bound-not-positive", &reinterpret_cast<VLABoundData*>(data)->loc);
    }
    void __ubsan_handle_implicit_conversion(void* data, u64, u64)
    {
        Emit("implicit-conversion", &reinterpret_cast<ImplicitConversionData*>(data)->loc);
    }
    void __ubsan_handle_nullability_arg(void* data)
    {
        Emit("nullability-arg", &reinterpret_cast<NonNullArgData*>(data)->loc);
    }
    // returns-nonnull / nullability-return: the source location is
    // the SECOND argument (the NonNullReturnData only carries the
    // attribute's location), so pass `loc` straight through.
    void __ubsan_handle_nonnull_return_v1(void*, void* loc)
    {
        Emit("nonnull-return-violated", reinterpret_cast<::duetos::diag::SourceLocation*>(loc));
    }
    void __ubsan_handle_nullability_return_v1(void*, void* loc)
    {
        Emit("nullability-return", reinterpret_cast<::duetos::diag::SourceLocation*>(loc));
    }

} // extern "C"
