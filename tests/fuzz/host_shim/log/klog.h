#pragma once

#include "util/types.h"

// klog macros are no-ops on the fuzz harness — their compile-time
// scope tracking has zero value at fuzz time. Defined variadically
// so a kernel-side arity change can never re-rot this shim and
// silently drop a parser out of fuzz coverage again. Keep this
// list a superset of every KLOG_* macro the real
// kernel/log/klog.h defines:
//   git grep -hoE 'define KLOG_[A-Z_0-9]+' kernel/log/klog.h | sort -u
#define KLOG_TRACE_SCOPE(...) ((void)0)
#define KLOG_TRACE_SCOPE_IMPL(...) ((void)0)
#define KLOG_TRACE_SCOPE_IMPL2(...) ((void)0)
#define KLOG_TRACE(...) ((void)0)
#define KLOG_TRACE_A(...) ((void)0)
#define KLOG_TRACE_V(...) ((void)0)
#define KLOG_TRACE_AV(...) ((void)0)
#define KLOG_TRACE_S(...) ((void)0)
#define KLOG_TRACE_AS(...) ((void)0)
#define KLOG_DEBUG(...) ((void)0)
#define KLOG_DEBUG_A(...) ((void)0)
#define KLOG_DEBUG_V(...) ((void)0)
#define KLOG_DEBUG_AV(...) ((void)0)
#define KLOG_DEBUG_S(...) ((void)0)
#define KLOG_DEBUG_AS(...) ((void)0)
#define KLOG_INFO(...) ((void)0)
#define KLOG_INFO_A(...) ((void)0)
#define KLOG_INFO_V(...) ((void)0)
#define KLOG_INFO_AV(...) ((void)0)
#define KLOG_INFO_S(...) ((void)0)
#define KLOG_INFO_AS(...) ((void)0)
#define KLOG_INFO_2V(...) ((void)0)
#define KLOG_INFO_A2V(...) ((void)0)
#define KLOG_WARN(...) ((void)0)
#define KLOG_WARN_A(...) ((void)0)
#define KLOG_WARN_V(...) ((void)0)
#define KLOG_WARN_AV(...) ((void)0)
#define KLOG_WARN_S(...) ((void)0)
#define KLOG_WARN_AS(...) ((void)0)
#define KLOG_WARN_2V(...) ((void)0)
#define KLOG_ERROR(...) ((void)0)
#define KLOG_ERROR_A(...) ((void)0)
#define KLOG_ERROR_V(...) ((void)0)
#define KLOG_ERROR_AV(...) ((void)0)
#define KLOG_ERROR_S(...) ((void)0)
#define KLOG_ERROR_AS(...) ((void)0)
#define KLOG_ERROR_2V(...) ((void)0)
#define KLOG_CRITICAL(...) ((void)0)
#define KLOG_CRITICAL_A(...) ((void)0)
#define KLOG_CRITICAL_V(...) ((void)0)
#define KLOG_CRITICAL_AV(...) ((void)0)
#define KLOG_CRITICAL_S(...) ((void)0)
#define KLOG_CRITICAL_AS(...) ((void)0)
#define KLOG_ONCE_INFO(...) ((void)0)
#define KLOG_ONCE_WARN(...) ((void)0)
#define KLOG_ONCE_WARN_V(...) ((void)0)
#define KLOG_METRICS(...) ((void)0)

namespace duetos::core
{
// Mirror of the real LogLevel enum. Only the names matter here —
// the values are never inspected by the no-op sinks.
enum class LogLevel : u8
{
    Trace = 0,
    Debug,
    Info,
    Warn,
    Error,
    Critical
};

enum class LogArea : u32
{
    None = 0,
    General = 1u << 0,
    Boot = 1u << 1,
    Memory = 1u << 2,
    Sched = 1u << 3,
    Process = 1u << 4,
    Syscall = 1u << 5,
    Loader = 1u << 6,
    FS = 1u << 7,
    Net = 1u << 8,
    Storage = 1u << 9,
    USB = 1u << 10,
    GPU = 1u << 11,
    Input = 1u << 12,
    Audio = 1u << 13,
    IPC = 1u << 14,
    Win32 = 1u << 15,
    Linux = 1u << 16,
    Time = 1u << 17,
    Power = 1u << 18,
    Security = 1u << 19,
    Diag = 1u << 20,
    Ring3 = 1u << 21,
    App = 1u << 22,
    Driver = 1u << 23,
    ACPI = 1u << 24,
    PCI = 1u << 25,
    Wireless = 1u << 26,
    Graphics = 1u << 27,
    Test = 1u << 28,
    Arith = 1u << 29,
    All = 0xFFFFFFFFu,
};

// Escape-hatch loggers called directly (not via KLOG_* macros) by
// some parsers, e.g. pe_loader.cpp's import resolver. No-op sinks.
inline void Log(LogLevel, const char*, const char*, const char* = nullptr, u32 = 0) {}
inline void LogWithValue(LogLevel, const char*, const char*, u64, const char* = nullptr, u32 = 0) {}
inline void LogWithString(LogLevel, const char*, const char*, const char*, const char*, const char* = nullptr,
                          u32 = 0)
{
}
inline void LogWith2Values(LogLevel, const char*, const char*, const char*, u64, const char*, u64,
                           const char* = nullptr, u32 = 0)
{
}
inline void SetLogThreshold(LogLevel) {}
} // namespace duetos::core
