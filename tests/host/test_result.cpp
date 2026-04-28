// tests/host/test_result.cpp
//
// Hosted unit tests for kernel/util/result.h — the Result<T, E>
// exception-handling primitive. Verifies:
//
//   - Success path: Result<T> constructed from a T evaluates true,
//     value() returns the T, error() returns Ok.
//   - Error path: Result<T> constructed from Err{code} evaluates
//     false, error() returns the code.
//   - Result<void, E> status-only specialisation: success vs.
//     error semantics + has_value()/explicit-bool.
//   - Err{} CTAD: `return Err{ErrorCode::Foo}` deduces Err<ErrorCode>
//     without spelling the type.
//   - take() consumes the value (used by RESULT_TRY_ASSIGN).
//
// The kernel implementation includes `arch/x86_64/serial.h` etc.
// in result.cpp for the ErrorCodeName function — we don't link
// that here. result.h is header-only and freestanding-clean, so
// every test below is template instantiation only.

#include "host_test_helper.h"
#include "util/result.h"

using duetos::u32;
using duetos::u64;
using duetos::core::Err;
using duetos::core::ErrorCode;
using duetos::core::Result;

static Result<u64> ProduceValue(u64 v)
{
    return v;
}

static Result<u64> ProduceError()
{
    return Err{ErrorCode::NotFound};
}

static Result<void> ProduceVoidOk()
{
    return {};
}

static Result<void> ProduceVoidErr()
{
    return Err{ErrorCode::Timeout};
}

int main()
{
    // Success path round-trip.
    {
        Result<u64> r = ProduceValue(42);
        EXPECT_TRUE(r.has_value());
        EXPECT_TRUE(static_cast<bool>(r));
        EXPECT_EQ(r.value(), 42u);
        // error() on a success result returns the zero-init E
        // (ErrorCode::Ok). The contract is that callers check
        // has_value() first; we just verify the documented
        // fallback.
        EXPECT_EQ(r.error(), ErrorCode::Ok);
    }

    // Error path round-trip.
    {
        Result<u64> r = ProduceError();
        EXPECT_FALSE(r.has_value());
        EXPECT_FALSE(static_cast<bool>(r));
        EXPECT_EQ(r.error(), ErrorCode::NotFound);
    }

    // take() — consumes the value (Result is otherwise copy-only).
    {
        Result<u64> r = ProduceValue(99);
        ASSERT_TRUE(r.has_value());
        EXPECT_EQ(r.take(), 99u);
    }

    // Result<void> success.
    {
        Result<void> r = ProduceVoidOk();
        EXPECT_TRUE(r.has_value());
        EXPECT_TRUE(static_cast<bool>(r));
    }

    // Result<void> error.
    {
        Result<void> r = ProduceVoidErr();
        EXPECT_FALSE(r.has_value());
        EXPECT_FALSE(static_cast<bool>(r));
        EXPECT_EQ(r.error(), ErrorCode::Timeout);
    }

    // Custom error type — CTAD on Err{} should pick it up cleanly.
    {
        struct MyError
        {
            u32 code;
            bool operator==(const MyError& o) const { return code == o.code; }
        };
        Result<u64, MyError> r = Err{MyError{42}};
        EXPECT_FALSE(r.has_value());
        EXPECT_TRUE(r.error() == MyError{42});
    }

    return duetos_host_test::finish_main("test_result");
}
