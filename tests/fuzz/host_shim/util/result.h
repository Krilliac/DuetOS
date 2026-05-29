#pragma once

#include "util/types.h"

namespace duetos::core
{

enum class ErrorCode : u32
{
    Ok = 0,
    OutOfMemory,
    InvalidArgument,
    NotFound,
    AlreadyExists,
    PermissionDenied,
    Timeout,
    Unsupported,
    BadState,
    IoError,
    Truncated,
    BufferTooSmall,
    Overflow,
    Corrupt,
    NotReady,
    Busy,
    NoDevice,
    Unknown,
};

template <typename E> struct Err
{
    E value;
    explicit Err(E v) : value(v) {}
};

template <typename T = void, typename E = ErrorCode> class Result
{
  public:
    Result() : has_value_(true), value_{} {}
    Result(const T& v) : has_value_(true), value_(v) {}
    Result(Err<E> e) : has_value_(false), error_(e.value) {}
    bool has_value() const { return has_value_; }
    explicit operator bool() const { return has_value_; }
    const T& value() const { return value_; }
    T value_or(T fallback) const { return has_value_ ? value_ : fallback; }
    E error() const { return error_; }

  private:
    bool has_value_;
    T value_;
    E error_ = E{};
};

template <typename E> class Result<void, E>
{
  public:
    Result() : has_value_(true) {}
    Result(Err<E> e) : has_value_(false), error_(e.value) {}
    bool has_value() const { return has_value_; }
    explicit operator bool() const { return has_value_; }
    E error() const { return error_; }

  private:
    bool has_value_;
    E error_ = E{};
};

// Mirrors kernel/util/result.h's ErrorCodeName. Only used by
// diagnostic/self-test paths in the fuzzed TUs; a single label
// is enough — the fuzzer never inspects the string.
inline const char* ErrorCodeName(ErrorCode)
{
    return "<err>";
}

} // namespace duetos::core

// Shim-adapted RESULT_TRY / RESULT_TRY_ASSIGN. The real kernel macros
// (kernel/util/result.h) propagate a source location through a 2-arg
// Err; this shim's Result carries no location, so the macros drop it.
// Fuzzers only care that the error/success branch is taken correctly,
// not where the error originated. Kept here so the migrated codec TUs
// (deflate/jpeg/... use RESULT_TRY) compile against the shim.
#define RESULT_TRY(expr)                                                                                               \
    do                                                                                                                 \
    {                                                                                                                  \
        auto _res_try = (expr);                                                                                        \
        if (!_res_try)                                                                                                 \
            return ::duetos::core::Err{_res_try.error()};                                                              \
    } while (0)

#define RESULT_TRY_ASSIGN(decl, expr)                                                                                  \
    auto _resta_##__LINE__ = (expr);                                                                                   \
    if (!_resta_##__LINE__)                                                                                            \
        return ::duetos::core::Err{_resta_##__LINE__.error()};                                                         \
    decl = _resta_##__LINE__.value() // NOLINT(bugprone-macro-parentheses)
