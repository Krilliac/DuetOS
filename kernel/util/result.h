#pragma once

#include "util/debug_assert.h"
#include "util/types.h"

/*
 * DuetOS — Result<T, E> + ErrorCode — v0 exception-handling primitive.
 *
 * CLAUDE.md mandates: "No RTTI, no exceptions in kernel code —
 * results go through an explicit Result<T, E> type." This file is
 * that type. C++ exceptions are off globally via -fno-exceptions;
 * every fallible operation should return `Result<T>` (or
 * `Result<void>` for status-only) and every call site either
 * propagates via RESULT_TRY / RESULT_TRY_ASSIGN or handles the
 * error branch explicitly.
 *
 * Design constraints:
 *   - Header-only. Freestanding kernel link doesn't pull in any
 *     of <expected> / <variant> / <optional>, so we roll our own
 *     — tiny, trivial-destructor, trivially-copyable.
 *   - T and E must be trivially copyable. Covers pointers,
 *     integers, POD structs, our `Handle` / `u*` / small records.
 *     If you reach for a Result<SomethingNonTrivial>, either make
 *     it trivial or split the lifecycle manually.
 *   - Cheap by design: Result<T> is `{bool, union{T,E}, [loc]}`
 *     which in practice is one or two cachelines. No heap, no
 *     vtable. The `[loc]` is the optional source-location tag
 *     (see DUETOS_RESULT_LOC below).
 *
 * Ergonomics:
 *
 *   Result<u64> ReadCount() {
 *       if (...)
 *           return ::duetos::core::Err{ErrorCode::IoError};
 *       return 42;
 *   }
 *
 *   Result<void> Foo() {
 *       RESULT_TRY_ASSIGN(u64 n, ReadCount());  // early-return on error
 *       (void)n;
 *       return {};                                // success for Result<void>
 *   }
 *
 *   Result<Thing> Bar() {
 *       RESULT_TRY(Foo());
 *       return Thing{};
 *   }
 *
 * The `Err{code}` helper uses class-template argument deduction
 * so any Result<T, E> function can `return Err{code};` without
 * spelling out the type. The implicit converting constructor on
 * Result picks it up.
 *
 * Source-location capture (gated by DUETOS_RESULT_LOC):
 *   When enabled (the default), every `Err{code}` site silently
 *   captures `__FILE__:__LINE__` via compiler builtins and carries
 *   it on the Result's error path. `RESULT_TRY` propagates that
 *   origin unchanged so the location surfaces at the eventual
 *   `RESULT_EXPECT` / `RESULT_LOG_AND_DROP` / panic site (which
 *   includes the throw site in the log, not the unwind site).
 *   Define `DUETOS_RESULT_LOC=0` to drop the capture entirely —
 *   Result and Err shrink back to the legacy minimum size.
 *
 * Per-subsystem error enums:
 *   The default `E` is `ErrorCode` (the kernel-wide enum below),
 *   but the template accepts any trivially-copyable type. A
 *   subsystem with a richer failure taxonomy can define its own
 *   enum and use `Result<T, fs::Error>` — the `Err{fs::Error::X}`
 *   syntax still works via CTAD, and `RESULT_TRY` propagates the
 *   typed error through chained calls in the same E family. Mix
 *   E types deliberately: a `Result<T, fs::Error>`-returning
 *   function whose body wants to propagate a `Result<U, ErrorCode>`
 *   must translate explicitly (typically via a small `MapErr`
 *   helper at the boundary), since `RESULT_TRY` won't auto-coerce
 *   between E types.
 *
 * Context: usable in kernel and userland code alike. Arch-neutral.
 */

// Gate: capture file/func/line at every Err{} construction site,
// carry it on the error path of Result<T,E>, surface it at the
// log/panic site via RESULT_LOG_AND_DROP / RESULT_EXPECT. Defaults
// ON; set to 0 via the build system to shrink Result back to the
// legacy {bool, union{T,E}} layout (saves ~24 bytes per Result
// instance on x86_64, at the cost of losing origin attribution).
#ifndef DUETOS_RESULT_LOC
#define DUETOS_RESULT_LOC 1
#endif

namespace duetos::core
{

enum class ErrorCode : u8
{
    Ok = 0,           // sentinel; never appears in Result::error() on a non-value result
    OutOfMemory,      // frame allocator / kheap / fixed pool exhausted
    InvalidArgument,  // caller-supplied value out of the documented range
    NotFound,         // lookup hit a non-existent entry
    AlreadyExists,    // create when the target name was already claimed
    PermissionDenied, // cap check failed / sandbox policy refused
    Timeout,          // polling / wait hit its deadline
    Unsupported,      // operation not implemented in this configuration
    BadState,         // object is not in a state that permits this op
    IoError,          // block device / NIC / xHCI reported a hardware failure
    Truncated,        // read returned fewer bytes than requested
    BufferTooSmall,   // caller-supplied buffer can't hold the result
    Overflow,         // arithmetic or length field exceeded the type
    Corrupt,          // on-disk / on-wire data failed a sanity check
    NotReady,         // device is still initialising
    Busy,             // resource is in use by another owner
    Deadlock,         // acquiring would deadlock the caller (self-held / cycle)
    NoDevice,         // no hardware of the required kind is present
    Unknown,
};

/// Stable human name for log output. Always returns a non-null
/// pointer into .rodata.
const char* ErrorCodeName(ErrorCode c);

/// Origin of an Err{}: where in source the error was raised. When
/// `DUETOS_RESULT_LOC` is on, every Err{code} captures this via
/// __builtin_FILE / __builtin_FUNCTION / __builtin_LINE at the
/// constructor call site. A default-constructed SourceLocation
/// (all-null) is the "unknown / not captured" sentinel.
struct SourceLocation
{
    const char* file = nullptr;
    const char* func = nullptr;
    u32 line = 0;
};

// Helper type the caller uses in a `return` statement to yield
// an error from a `Result<T, E>`-returning function without
// spelling out the type. CTAD deduces E from the argument so
// `return Err{ErrorCode::NotFound};` just works.
#if DUETOS_RESULT_LOC

template <typename E> struct Err
{
    E value;
    SourceLocation loc;

    // Capture-at-call-site constructor. The defaulted __builtin_*
    // arguments are evaluated where the constructor is INVOKED,
    // not where it's declared, so every `Err{code}` site silently
    // stamps its own file/func/line into the loc.
    constexpr Err(E v, const char* file = __builtin_FILE(), const char* func = __builtin_FUNCTION(),
                  u32 line = __builtin_LINE())
        : value(v), loc{file, func, line}
    {
    }

    // Propagation constructor — used by RESULT_TRY to forward an
    // inner Result's error WITHOUT recapturing the location at the
    // propagation site. Keeps the original throw site visible all
    // the way up the call chain.
    constexpr Err(E v, SourceLocation l) : value(v), loc(l) {}
};

#else

template <typename E> struct Err
{
    E value;

    constexpr Err(E v) : value(v) {}

    // Accept-and-discard the SourceLocation argument so RESULT_TRY
    // can use a single macro shape in both gating modes.
    constexpr Err(E v, SourceLocation /*unused*/) : value(v) {}
};

#endif

// Explicit CTAD guides — cover both `Err{code}` and `Err{code, loc}`
// in either gating mode.
template <typename E> Err(E) -> Err<E>;
template <typename E> Err(E, SourceLocation) -> Err<E>;

template <typename T, typename E = ErrorCode> class [[nodiscard]] Result
{
    static_assert(__is_trivially_copyable(T), "Result<T,E>: T must be trivially copyable in the freestanding kernel");
    static_assert(__is_trivially_copyable(E), "Result<T,E>: E must be trivially copyable");

  public:
    // Success path.
    Result(T v) : has_value_(true) { storage_.value = v; }

    // Error path — implicit conversion from Err<E>.
    Result(Err<E> e) : has_value_(false)
    {
        storage_.error = e.value;
#if DUETOS_RESULT_LOC
        loc_ = e.loc;
#endif
    }

    Result() = delete;

    bool has_value() const { return has_value_; }
    explicit operator bool() const { return has_value_; }

    // value() on an error-state Result returns the union's value
    // field — which was never constructed, so reads are UB. The
    // DEBUG_ASSERT catches misuse during development with zero
    // release-build cost. Existing call sites that follow the
    // `if (!r.has_value()) return Err{r.error()};` pattern stay
    // correct; only sites that call value() on an unchecked Result
    // trip the assertion.
    const T& value() const
    {
        DEBUG_ASSERT(has_value_, "util/result", "Result::value() on error state");
        return storage_.value;
    }
    T& value()
    {
        DEBUG_ASSERT(has_value_, "util/result", "Result::value() on error state");
        return storage_.value;
    }

    E error() const { return has_value_ ? E{} : storage_.error; }

    // Origin of the error, when DUETOS_RESULT_LOC is on. Returns a
    // default-constructed (all-null) SourceLocation on the success
    // path or when capture is gated off — callers should treat
    // `location().file == nullptr` as "no origin info available".
    SourceLocation location() const
    {
#if DUETOS_RESULT_LOC
        return has_value_ ? SourceLocation{} : loc_;
#else
        return SourceLocation{};
#endif
    }

    // Move-like "consume the value" — for callers that take
    // ownership (the Result instance is typically a temporary
    // inside RESULT_TRY_ASSIGN).
    T take()
    {
        DEBUG_ASSERT(has_value_, "util/result", "Result::take() on error state");
        return storage_.value;
    }

  private:
    bool has_value_;
    union Storage
    {
        T value;
        E error;
    } storage_;
#if DUETOS_RESULT_LOC
    SourceLocation loc_;
#endif
};

// Status-only specialisation — success carries no payload, just a
// "did it work" flag.
template <typename E> class [[nodiscard]] Result<void, E>
{
    static_assert(__is_trivially_copyable(E), "Result<void,E>: E must be trivially copyable");

  public:
    Result() : has_value_(true), error_{} {}
    Result(Err<E> e)
        : has_value_(false), error_(e.value)
#if DUETOS_RESULT_LOC
          ,
          loc_(e.loc)
#endif
    {
    }

    bool has_value() const { return has_value_; }
    explicit operator bool() const { return has_value_; }

    E error() const { return error_; }

    SourceLocation location() const
    {
#if DUETOS_RESULT_LOC
        return has_value_ ? SourceLocation{} : loc_;
#else
        return SourceLocation{};
#endif
    }

  private:
    bool has_value_;
    E error_;
#if DUETOS_RESULT_LOC
    SourceLocation loc_;
#endif
};

// Run the self-test. Exercises every constructor / move / error-
// code name / TRY macro pair. Panics on mismatch; prints a PASS
// line on COM1 otherwise.
void ResultSelfTest();

} // namespace duetos::core

// -------------------------------------------------------------------
// Early-return helpers. Must live at the call site so they can use
// the caller's return-type — a helper function can't early-return
// on behalf of its caller.
// -------------------------------------------------------------------

// `RESULT_TRY(expr)` — evaluates `expr`, returns its error up one
// stack frame if present, discards the value otherwise. Use when
// the callee is `Result<void>` or when we don't need the value.
// Propagates the inner Result's source location unchanged so the
// throw site survives the unwind.
#define RESULT_TRY(expr)                                                                                               \
    do                                                                                                                 \
    {                                                                                                                  \
        auto _res_try = (expr);                                                                                        \
        if (!_res_try)                                                                                                 \
            return ::duetos::core::Err{_res_try.error(), _res_try.location()};                                         \
    } while (0)

// `RESULT_TRY_ASSIGN(decl, expr)` — evaluates `expr`, returns its
// error up one frame on failure, binds the value to `decl` on
// success. `decl` is a full declaration ("u64 n", "auto x", etc.).
// The _Pragma suppresses shadowing warnings from nested TRY uses
// in the same function. Propagates the inner location like
// RESULT_TRY does.
#define RESULT_TRY_ASSIGN(decl, expr)                                                                                  \
    auto _resta_##__LINE__ = (expr);                                                                                   \
    if (!_resta_##__LINE__)                                                                                            \
        return ::duetos::core::Err{_resta_##__LINE__.error(), _resta_##__LINE__.location()};                           \
    /* `decl` is a declarator ("u64 n", "auto x"), not an expression — it cannot be parenthesized. */                \
    decl = _resta_##__LINE__.take() // NOLINT(bugprone-macro-parentheses)
