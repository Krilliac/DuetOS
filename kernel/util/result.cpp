#include "util/result.h"

#include "arch/x86_64/serial.h"
#include "log/klog.h"
#include "core/panic.h"

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
    case ErrorCode::Deadlock:
        return "Deadlock";
    case ErrorCode::NoDevice:
        return "NoDevice";
    case ErrorCode::Unknown:
        return "Unknown";
    default:
        // New enumerator added without a name? Log once so the gap
        // is visible without panicking; the "?" sentinel below is
        // the safe fallback the self-test treats as a failure.
        KLOG_ONCE_WARN("core/result", "ErrorCodeName: unrecognised ErrorCode");
        return "?";
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

#if DUETOS_RESULT_LOC
    // Source-location capture: an Err{} construction site stamps its
    // own file/func/line into the Result. Verify the captured loc
    // round-trips through Err -> Result -> Err -> Result (the TRY
    // propagation path) without being recaptured at the propagation
    // site.
    {
        // line_of_err is the line of the `Err{...}` expression below;
        // capture it via __LINE__ adjacent to the construction so the
        // expected/actual values stay locked to the same source row.
        const u32 line_of_err = __LINE__ + 1;
        Result<u64> bad = []() -> Result<u64> { return Err{ErrorCode::NotFound}; }();
        const SourceLocation loc = bad.location();
        Expect(loc.file != nullptr, "location.file captured (file)");
        Expect(loc.line == line_of_err, "location.line captured (matches expected line)");
        Expect(loc.func != nullptr, "location.func captured");
    }
    {
        // Propagation: the inner Err{} site's loc must survive a
        // RESULT_TRY through an outer frame. The outer Result's loc
        // is the INNER throw line, not the line of RESULT_TRY.
        const u32 inner_line = __LINE__ + 3;
        auto outer = []() -> Result<u64>
        {
            auto inner = []() -> Result<u64> { return Err{ErrorCode::Busy}; };
            RESULT_TRY_ASSIGN(u64 n, inner());
            return n;
        }();
        Expect(!outer.has_value(), "RESULT_TRY propagation: outer is error");
        Expect(outer.location().line == inner_line, "RESULT_TRY: outer.loc == inner throw line");
    }
    {
        // Result<void> path: location survives through Result<void>(Err{})
        // construction and the Result<void> error accessor.
        const u32 line_of_err = __LINE__ + 1;
        Result<void> bad = []() -> Result<void> { return Err{ErrorCode::Timeout}; }();
        Expect(bad.location().line == line_of_err, "Result<void> location.line captured");
        Expect(bad.error() == ErrorCode::Timeout, "Result<void> error preserved alongside loc");
    }
#endif

    arch::SerialWrite("[result-selftest] PASS (Result<T> + Result<void> + TRY + ErrorCodeName"
#if DUETOS_RESULT_LOC
                      " + SourceLocation"
#endif
                      ")\n");
}

} // namespace duetos::core
