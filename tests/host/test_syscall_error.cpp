// tests/host/test_syscall_error.cpp
//
// Hosted unit tests for kernel/syscall/error.{h,cpp}. Verifies that
// internal kernel ErrorCode values propagate out through the native
// syscall ABI as stable negative errno payloads instead of collapsing
// to a generic -1.

#include "host_test_helper.h"
#include "syscall/error.h"

using duetos::core::ErrorCode;
using duetos::core::ErrorCodeToNativeErrno;
using duetos::core::ErrorCodeToNativeSyscallReturn;
using duetos::core::kSysErrnoEACCES;
using duetos::core::kSysErrnoEAGAIN;
using duetos::core::kSysErrnoEBUSY;
using duetos::core::kSysErrnoEEXIST;
using duetos::core::kSysErrnoEINVAL;
using duetos::core::kSysErrnoEIO;
using duetos::core::kSysErrnoENOMEM;
using duetos::core::kSysErrnoENOENT;
using duetos::core::kSysErrnoENODEV;
using duetos::core::kSysErrnoEOPNOTSUPP;
using duetos::core::kSysErrnoEOVERFLOW;
using duetos::core::kSysErrnoERANGE;
using duetos::core::kSysErrnoETIMEDOUT;

int main()
{
    EXPECT_EQ(ErrorCodeToNativeErrno(ErrorCode::Ok), 0);
    EXPECT_EQ(ErrorCodeToNativeErrno(ErrorCode::OutOfMemory), kSysErrnoENOMEM);
    EXPECT_EQ(ErrorCodeToNativeErrno(ErrorCode::InvalidArgument), kSysErrnoEINVAL);
    EXPECT_EQ(ErrorCodeToNativeErrno(ErrorCode::NotFound), kSysErrnoENOENT);
    EXPECT_EQ(ErrorCodeToNativeErrno(ErrorCode::AlreadyExists), kSysErrnoEEXIST);
    EXPECT_EQ(ErrorCodeToNativeErrno(ErrorCode::PermissionDenied), kSysErrnoEACCES);
    EXPECT_EQ(ErrorCodeToNativeErrno(ErrorCode::Timeout), kSysErrnoETIMEDOUT);
    EXPECT_EQ(ErrorCodeToNativeErrno(ErrorCode::Unsupported), kSysErrnoEOPNOTSUPP);
    EXPECT_EQ(ErrorCodeToNativeErrno(ErrorCode::BadState), kSysErrnoEINVAL);
    EXPECT_EQ(ErrorCodeToNativeErrno(ErrorCode::IoError), kSysErrnoEIO);
    EXPECT_EQ(ErrorCodeToNativeErrno(ErrorCode::Truncated), kSysErrnoEIO);
    EXPECT_EQ(ErrorCodeToNativeErrno(ErrorCode::BufferTooSmall), kSysErrnoERANGE);
    EXPECT_EQ(ErrorCodeToNativeErrno(ErrorCode::Overflow), kSysErrnoEOVERFLOW);
    EXPECT_EQ(ErrorCodeToNativeErrno(ErrorCode::Corrupt), kSysErrnoEIO);
    EXPECT_EQ(ErrorCodeToNativeErrno(ErrorCode::NotReady), kSysErrnoEAGAIN);
    EXPECT_EQ(ErrorCodeToNativeErrno(ErrorCode::Busy), kSysErrnoEBUSY);
    EXPECT_EQ(ErrorCodeToNativeErrno(ErrorCode::NoDevice), kSysErrnoENODEV);
    EXPECT_EQ(ErrorCodeToNativeErrno(ErrorCode::Unknown), kSysErrnoEIO);

    EXPECT_EQ(ErrorCodeToNativeSyscallReturn(ErrorCode::PermissionDenied),
              static_cast<duetos::u64>(kSysErrnoEACCES));

    return duetos_host_test::finish_main("test_syscall_error");
}
