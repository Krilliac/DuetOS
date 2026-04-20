#include "klog.h"

#include "../arch/x86_64/serial.h"

namespace customos::core
{

namespace
{

inline const char* LevelTag(LogLevel level)
{
    switch (level)
    {
    case LogLevel::Debug:
        return "[D] ";
    case LogLevel::Info:
        return "[I] ";
    case LogLevel::Warn:
        return "[W] ";
    case LogLevel::Error:
        return "[E] ";
    }
    return "[?] ";
}

inline bool LevelEnabled(LogLevel level)
{
    return static_cast<u8>(level) >= static_cast<u8>(kKlogMinLevel);
}

} // namespace

void Log(LogLevel level, const char* subsystem, const char* message)
{
    if (!LevelEnabled(level))
    {
        return;
    }
    arch::SerialWrite(LevelTag(level));
    arch::SerialWrite(subsystem);
    arch::SerialWrite(" : ");
    arch::SerialWrite(message);
    arch::SerialWrite("\n");
}

void LogWithValue(LogLevel level, const char* subsystem, const char* message, u64 value)
{
    if (!LevelEnabled(level))
    {
        return;
    }
    arch::SerialWrite(LevelTag(level));
    arch::SerialWrite(subsystem);
    arch::SerialWrite(" : ");
    arch::SerialWrite(message);
    arch::SerialWrite("   val=");
    arch::SerialWriteHex(value);
    arch::SerialWrite("\n");
}

void KLogSelfTest()
{
    KLOG_DEBUG("core/klog", "debug-level sanity line");
    KLOG_INFO("core/klog", "info-level sanity line");
    KLOG_WARN("core/klog", "warn-level sanity line");
    KLOG_ERROR("core/klog", "error-level sanity line");
    KLOG_INFO_V("core/klog", "value-form sanity line", 0xCAFEBABE);
}

} // namespace customos::core
