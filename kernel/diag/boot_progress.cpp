#include "diag/boot_progress.h"

#include "arch/x86_64/serial.h"

namespace duetos::diag
{

namespace
{

// First BootProgress() call's TSC. `total` deltas are computed
// against this so a reader can sequence markers from "kernel
// boot" rather than from "previous marker".
constinit u64 g_first_tsc = 0;

// Most recent BootProgress() call's TSC + tag. The next call
// reports `delta = now - last_tsc` plus the previous tag, so the
// log line bracketing two calls names which step the delta
// covers.
constinit u64 g_last_tsc = 0;
constinit const char* g_last_tag = nullptr;

inline u64 ReadTsc()
{
    u32 lo;
    u32 hi;
    asm volatile("rdtsc" : "=a"(lo), "=d"(hi));
    return (static_cast<u64>(hi) << 32) | lo;
}

} // namespace

void BootProgress(const char* tag)
{
    using arch::SerialWrite;
    using arch::SerialWriteHex;

    const u64 now = ReadTsc();
    const bool first = (g_first_tsc == 0);
    if (first)
    {
        g_first_tsc = now;
        g_last_tsc = now;
    }

    const u64 delta = first ? 0 : (now - g_last_tsc);
    const u64 total = now - g_first_tsc;

    SerialWrite("[progress] tag=\"");
    SerialWrite(tag != nullptr ? tag : "(null)");
    SerialWrite("\" prev=\"");
    SerialWrite(g_last_tag != nullptr ? g_last_tag : "(none)");
    SerialWrite("\" delta=");
    SerialWriteHex(delta);
    SerialWrite(" total=");
    SerialWriteHex(total);
    SerialWrite("\n");

    g_last_tsc = now;
    g_last_tag = tag;
}

} // namespace duetos::diag
