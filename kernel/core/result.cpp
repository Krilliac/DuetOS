#include "result.h"

#include "../arch/x86_64/serial.h"
#include "klog.h"
#include "panic.h"

namespace duetos::core
{

const char* ErrorCodeName(ErrorCode c)
{
    switch (c)
    {
    case ErrorCode::Ok:
        return "Ok";
    case ErrorCode::OutOfMemory:
        return "OutOfMemory";
    case ErrorCode::InvalidArgument:
        return "InvalidArgument";
    case ErrorCode::NotFound:
        return "NotFound";
    case ErrorCode::AlreadyExists:
        return "AlreadyExists";
    case ErrorCode::PermissionDenied:
        return "PermissionDenied";
    case ErrorCode::Timeout:
        return "Timeout";
    case ErrorCode::Unsupported:
        return "Unsupported";
    case ErrorCode::BadState:
        return "BadState";
    case ErrorCode::IoError:
        return "IoError";
    case ErrorCode::Truncated:
        return "Truncated";
    case ErrorCode::BufferTooSmall:
        return "BufferTooSmall";
    case ErrorCode::Overflow:
        return "Overflow";
    case ErrorCode::Corrupt:
        return "Corrupt";
    case ErrorCode::NotReady:
        return "NotReady";
    case ErrorCode::Busy:
        return "Busy";
    case ErrorCode::NoDevice:
        return "NoDevice";
    case ErrorCode::Unknown:
        return "Unknown";
    }
    return "?";
}

namespace
{

// Small helpers exercised by the self-test. Keep them file-local
// so the tests double as canonical usage examples.

Result<u64> ReadCount(bool succeed)
{
    if (!succeed)
        return Err{ErrorCode::IoError};
    return u64{42};
}

Result<void> Validate(u64 n)
{
    if (n == 0)
        return Err{ErrorCode::InvalidArgument};
    return {};
}

// Two-step: read + validate. Exercises both TRY macros.
Result<u64> ReadAndValidate(bool succeed)
{
    RESULT_TRY_ASSIGN(u64 n, ReadCount(succeed));
    RESULT_TRY(Validate(n));
    return n;
}

void Expect(bool cond, const char* what)
{
    if (cond)
        return;
    arch::SerialWrite("[result-selftest] FAIL ");
    arch::SerialWrite(what);
    arch::SerialWrite("\n");
    PanicWithValue("core/result", "Result self-test failed", 0);
}

} // namespace

void ResultSelfTest()
{
    KLOG_TRACE_SCOPE("core/result", "ResultSelfTest");

    // Direct Result<T> construction: Ok + Error paths.
    {
        Result<u64> ok(7);
        Expect(ok.has_value(), "Result<u64>(7).has_value()");
        Expect(bool(ok), "Result<u64>(7) truthy");
        Expect(ok.value() == 7, "Result<u64>(7).value()==7");
    }
    {
        Result<u64> bad(Err{ErrorCode::NotFound});
        Expect(!bad.has_value(), "Result<u64>(Err).has_value()==false");
        Expect(!bool(bad), "Result<u64>(Err) falsy");
        Expect(bad.error() == ErrorCode::NotFound, "Result<u64>(Err).error()==NotFound");
    }

    // Result<void> Ok + error.
    {
        Result<void> ok;
        Expect(ok.has_value(), "Result<void>() has_value");
    }
    {
        Result<void> bad(Err{ErrorCode::Busy});
        Expect(!bad.has_value(), "Result<void>(Err).has_value()==false");
        Expect(bad.error() == ErrorCode::Busy, "Result<void>(Err).error()==Busy");
    }

    // TRY chain — success.
    {
        Result<u64> r = ReadAndValidate(true);
        Expect(r.has_value(), "TRY chain success: has_value");
        Expect(r.value() == 42, "TRY chain success: value==42");
    }
    // TRY chain — failure propagates IoError.
    {
        Result<u64> r = ReadAndValidate(false);
        Expect(!r.has_value(), "TRY chain failure: has_value==false");
        Expect(r.error() == ErrorCode::IoError, "TRY chain failure: error==IoError");
    }

    // ErrorCodeName covers every enumerator (catches "added a new
    // code, forgot to update the name switch").
    const ErrorCode kAll[] = {
        ErrorCode::Ok,       ErrorCode::OutOfMemory,   ErrorCode::InvalidArgument,
        ErrorCode::NotFound, ErrorCode::AlreadyExists, ErrorCode::PermissionDenied,
        ErrorCode::Timeout,  ErrorCode::Unsupported,   ErrorCode::BadState,
        ErrorCode::IoError,  ErrorCode::Truncated,     ErrorCode::BufferTooSmall,
        ErrorCode::Overflow, ErrorCode::Corrupt,       ErrorCode::NotReady,
        ErrorCode::Busy,     ErrorCode::NoDevice,      ErrorCode::Unknown,
    };
    for (ErrorCode c : kAll)
    {
        const char* n = ErrorCodeName(c);
        Expect(n != nullptr, "ErrorCodeName non-null");
        Expect(n[0] != '?', "ErrorCodeName not the unnamed sentinel");
    }

    arch::SerialWrite("[result-selftest] PASS (Result<T> + Result<void> + TRY + ErrorCodeName)\n");
}

} // namespace duetos::core
