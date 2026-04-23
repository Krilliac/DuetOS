#pragma once

#include "types.h"

/*
 * CustomOS — Result<T, E> + ErrorCode — v0 exception-handling primitive.
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
 *   - Zero overhead vs. bare T: Result<T> is `{bool, union{T,E}}`
 *     which in practice is one cacheline or less. No heap, no vtable.
 *
 * Ergonomics:
 *
 *   Result<u64> ReadCount() {
 *       if (...)
 *           return ::customos::core::Err{ErrorCode::IoError};
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
 * Context: usable in kernel and userland code alike. Arch-neutral.
 */

namespace customos::core
{

enum class ErrorCode : u32
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
    NoDevice,         // no hardware of the required kind is present
    Unknown,
};

/// Stable human name for log output. Always returns a non-null
/// pointer into .rodata.
const char* ErrorCodeName(ErrorCode c);

// Helper type the caller uses in a `return` statement to yield
// an error from a `Result<T, E>`-returning function without
// spelling out the type. CTAD deduces E from the argument so
// `return Err{ErrorCode::NotFound};` just works.
template <typename E> struct Err
{
    E value;
};
template <typename E> Err(E) -> Err<E>;

template <typename T, typename E = ErrorCode> class Result
{
    static_assert(__is_trivially_copyable(T), "Result<T,E>: T must be trivially copyable in the freestanding kernel");
    static_assert(__is_trivially_copyable(E), "Result<T,E>: E must be trivially copyable");

  public:
    // Success path.
    Result(T v) : has_value_(true) { storage_.value = v; }

    // Error path — implicit conversion from Err<E>.
    Result(Err<E> e) : has_value_(false) { storage_.error = e.value; }

    Result() = delete;

    bool has_value() const { return has_value_; }
    explicit operator bool() const { return has_value_; }

    const T& value() const { return storage_.value; }
    T& value() { return storage_.value; }

    E error() const { return has_value_ ? E{} : storage_.error; }

    // Move-like "consume the value" — for callers that take
    // ownership (the Result instance is typically a temporary
    // inside RESULT_TRY_ASSIGN).
    T take() { return storage_.value; }

  private:
    bool has_value_;
    union Storage
    {
        T value;
        E error;
    } storage_;
};

// Status-only specialisation — success carries no payload, just a
// "did it work" flag.
template <typename E> class Result<void, E>
{
    static_assert(__is_trivially_copyable(E), "Result<void,E>: E must be trivially copyable");

  public:
    Result() : has_value_(true), error_{} {}
    Result(Err<E> e) : has_value_(false), error_(e.value) {}

    bool has_value() const { return has_value_; }
    explicit operator bool() const { return has_value_; }

    E error() const { return error_; }

  private:
    bool has_value_;
    E error_;
};

// Run the self-test. Exercises every constructor / move / error-
// code name / TRY macro pair. Panics on mismatch; prints a PASS
// line on COM1 otherwise.
void ResultSelfTest();

} // namespace customos::core

// -------------------------------------------------------------------
// Early-return helpers. Must live at the call site so they can use
// the caller's return-type — a helper function can't early-return
// on behalf of its caller.
// -------------------------------------------------------------------

// `RESULT_TRY(expr)` — evaluates `expr`, returns its error up one
// stack frame if present, discards the value otherwise. Use when
// the callee is `Result<void>` or when we don't need the value.
#define RESULT_TRY(expr)                                                                                               \
    do                                                                                                                 \
    {                                                                                                                  \
        auto _res_try = (expr);                                                                                        \
        if (!_res_try)                                                                                                 \
            return ::customos::core::Err{_res_try.error()};                                                            \
    } while (0)

// `RESULT_TRY_ASSIGN(decl, expr)` — evaluates `expr`, returns its
// error up one frame on failure, binds the value to `decl` on
// success. `decl` is a full declaration ("u64 n", "auto x", etc.).
// The _Pragma suppresses shadowing warnings from nested TRY uses
// in the same function.
#define RESULT_TRY_ASSIGN(decl, expr)                                                                                  \
    auto _resta_##__LINE__ = (expr);                                                                                   \
    if (!_resta_##__LINE__)                                                                                            \
        return ::customos::core::Err{_resta_##__LINE__.error()};                                                       \
    decl = _resta_##__LINE__.take()
