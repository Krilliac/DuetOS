#include "syscall/error.h"

namespace duetos::core
{

i64 ErrorCodeToNativeErrno(ErrorCode code)
{
    switch (code)
    {
    case ErrorCode::Ok:
        return 0;
    case ErrorCode::OutOfMemory:
        return kSysErrnoENOMEM;
    case ErrorCode::InvalidArgument:
        return kSysErrnoEINVAL;
    case ErrorCode::NotFound:
        return kSysErrnoENOENT;
    case ErrorCode::AlreadyExists:
        return kSysErrnoEEXIST;
    case ErrorCode::PermissionDenied:
        return kSysErrnoEACCES;
    case ErrorCode::Timeout:
        return kSysErrnoETIMEDOUT;
    case ErrorCode::Unsupported:
        return kSysErrnoEOPNOTSUPP;
    case ErrorCode::BadState:
        return kSysErrnoEINVAL;
    case ErrorCode::IoError:
        return kSysErrnoEIO;
    case ErrorCode::Truncated:
        return kSysErrnoEIO;
    case ErrorCode::BufferTooSmall:
        return kSysErrnoERANGE;
    case ErrorCode::Overflow:
        return kSysErrnoEOVERFLOW;
    case ErrorCode::Corrupt:
        return kSysErrnoEIO;
    case ErrorCode::NotReady:
        return kSysErrnoEAGAIN;
    case ErrorCode::Busy:
        return kSysErrnoEBUSY;
    case ErrorCode::Deadlock:
        return kSysErrnoEDEADLK;
    case ErrorCode::NoDevice:
        return kSysErrnoENODEV;
    case ErrorCode::Unknown:
        return kSysErrnoEIO;
    }

    return kSysErrnoEIO;
}

u64 ErrorCodeToNativeSyscallReturn(ErrorCode code)
{
    return static_cast<u64>(ErrorCodeToNativeErrno(code));
}

} // namespace duetos::core
