#pragma once

#include "util/result.h"
#include "util/types.h"

/*
 * DuetOS — native syscall error propagation helpers.
 *
 * Kernel subsystems report failures with core::ErrorCode. The native
 * int-0x80 ABI reports failures to user mode as negative POSIX-style
 * errno values in rax, matching the convention documented for native
 * and Linux-compatible callers. Keep that translation centralized so
 * syscall handlers don't collapse distinct kernel failures into a
 * generic -1.
 */

namespace duetos::core
{

// Native syscall ABI errno constants. Values intentionally match the
// Linux/POSIX numbers where they overlap so userland thunks can share
// the common "negative errno in rax" machinery.
inline constexpr i64 kSysErrnoEPERM = -1;
inline constexpr i64 kSysErrnoENOENT = -2;
inline constexpr i64 kSysErrnoEIO = -5;
inline constexpr i64 kSysErrnoEBADF = -9;
inline constexpr i64 kSysErrnoEAGAIN = -11;
inline constexpr i64 kSysErrnoENOMEM = -12;
inline constexpr i64 kSysErrnoEACCES = -13;
inline constexpr i64 kSysErrnoEFAULT = -14;
inline constexpr i64 kSysErrnoEBUSY = -16;
inline constexpr i64 kSysErrnoEEXIST = -17;
inline constexpr i64 kSysErrnoENODEV = -19;
inline constexpr i64 kSysErrnoEINVAL = -22;
inline constexpr i64 kSysErrnoERANGE = -34;
inline constexpr i64 kSysErrnoENOSYS = -38;
inline constexpr i64 kSysErrnoEOVERFLOW = -75;
inline constexpr i64 kSysErrnoEOPNOTSUPP = -95;
inline constexpr i64 kSysErrnoETIMEDOUT = -110;

/// Convert an internal ErrorCode into the stable native syscall ABI's
/// negative errno payload. ErrorCode::Ok maps to 0 for defensive use
/// at generic call sites; real failure paths should only pass errors.
i64 ErrorCodeToNativeErrno(ErrorCode code);

/// Same mapping, pre-cast for writing directly into TrapFrame::rax.
u64 ErrorCodeToNativeSyscallReturn(ErrorCode code);

} // namespace duetos::core
