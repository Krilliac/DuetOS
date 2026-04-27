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
#include "util/types.h"

namespace duetos::diag
{

namespace
{

constinit u64 g_reports = 0;

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
// runtime checker can ask "any UB since boot?" in O(1).
void Report(const char* kind, const SourceLocation* loc)
{
    ++g_reports;
    if (loc == nullptr || loc->filename == nullptr)
    {
        KLOG_WARN_S("ubsan", "incident", "kind", kind);
        return;
    }
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

} // namespace

u64 UbsanReportsEmitted()
{
    return g_reports;
}

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
