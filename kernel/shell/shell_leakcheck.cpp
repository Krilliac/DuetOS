// Resource-leak inspection shell command (`leakcheck`).
// Split out of shell_debug.cpp to keep TUs within the
// project size guideline; behaviour is unchanged.

#include "shell/shell_internal.h"

#include "arch/x86_64/serial.h"
#include "arch/x86_64/traps.h"
#include "debug/breakpoints.h"
#include "debug/inspect.h"
#include "debug/probes.h"
#include "debug/syscall_scan.h"
#include "debug/tripwire.h"
#include "debug/watch.h"
#include "drivers/video/console.h"
#include "mm/kheap.h"
#include "mm/paging.h"
#include "sched/sched.h"
#include "core/init.h"
#include "diag/event_trace.h"
#include "diag/fault_inject.h"
#include "diag/fault_react.h"
#include "diag/gdb_server.h"
#include "diag/leak_detector.h"
#include "ipc/kobject.h"
#include "util/random.h"
#include "diag/hexdump.h"
#include "diag/kdbg.h"
#include "diag/perf_profile.h"
#include "diag/soft_lockup.h"
#include "diag/ubsan.h"
#include "mm/zone.h"
#include "security/cap_audit.h"
#include "security/domain_dump.h"
#include "security/driver_domain.h"
#include "security/fault_domain.h"
#include "security/module.h"
#include "sync/lockdep.h"
#include "sync/rcu.h"
#include "time/tick.h"
#include "time/timekeeper.h"
#include "log/klog.h"
#include "diag/runtime_checker.h"
#include "sync/lockdep.h"
#include "syscall/cap_gate.h"
#include "syscall/syscall_names.h"
#include "util/symbols.h"

namespace duetos::core::shell::internal
{

namespace
{

using duetos::drivers::video::ConsoleWrite;
using duetos::drivers::video::ConsoleWriteChar;
using duetos::drivers::video::ConsoleWriteln;

void PrintLeakRow(const duetos::diag::ClassSnapshot& s)
{
    // Two-column layout: name left-padded to 16, then outstanding,
    // peak, byte_cost. Column widths sized for typical decimal
    // values; the line stays within 80 cols even at 64-bit max.
    ConsoleWrite("  ");
    ConsoleWrite(s.name);
    // Pad to a 16-char name column.
    for (u32 pad = 0; pad < 16; ++pad)
    {
        const char c = s.name[pad];
        if (c == '\0')
        {
            for (u32 fill = pad; fill < 16; ++fill)
                ConsoleWriteChar(' ');
            break;
        }
    }
    ConsoleWrite(" out=");
    WriteU64Dec(s.outstanding);
    ConsoleWrite(" peak=");
    WriteU64Dec(s.peak);
    ConsoleWrite(" bytes=");
    WriteU64Dec(s.byte_cost);
    ConsoleWriteChar('\n');
}

void PrintLeakCheckSummary()
{
    duetos::diag::ClassSnapshot rows[u32(duetos::diag::ResourceClass::kCount)];
    duetos::diag::LeakDetectorSnapshotAll(rows);
    ConsoleWriteln("LEAKCHECK: UNIFIED RESOURCE SCAN");
    for (u32 i = 0; i < u32(duetos::diag::ResourceClass::kCount); ++i)
    {
        PrintLeakRow(rows[i]);
    }
    // Plus the heap top-N RIP ranking (the only class that has
    // per-allocation-site detail today). Cheap; piggybacks on the
    // existing `heap leaks` walk.
    duetos::mm::HeapLeakEntry heap_rows[8];
    const u32 n = duetos::diag::LeakDetectorTopHeapByRip(heap_rows, 8);
    if (n > 0)
    {
        ConsoleWriteln("HEAP TOP RIPS (bytes outstanding):");
        for (u32 i = 0; i < n; ++i)
        {
            ConsoleWrite("  rip=");
            WriteU64Hex(heap_rows[i].caller_rip, 16);
            ConsoleWrite(" bytes=");
            WriteU64Dec(heap_rows[i].bytes);
            ConsoleWrite(" count=");
            WriteU64Dec(heap_rows[i].count);
            ConsoleWriteChar('\n');
        }
    }
}

void PrintLeakCheckClass(duetos::diag::ResourceClass cls)
{
    if (cls == duetos::diag::ResourceClass::kCount)
    {
        ConsoleWriteln("LEAKCHECK: unknown class");
        return;
    }
    duetos::diag::ClassSnapshot rows[u32(duetos::diag::ResourceClass::kCount)];
    duetos::diag::LeakDetectorSnapshotAll(rows);
    PrintLeakRow(rows[u32(cls)]);
    if (cls == duetos::diag::ResourceClass::kHeap)
    {
        duetos::mm::HeapLeakEntry heap_rows[16];
        const u32 n = duetos::diag::LeakDetectorTopHeapByRip(heap_rows, 16);
        ConsoleWrite("HEAP TOP ");
        WriteU64Dec(n);
        ConsoleWriteln(" RIPS:");
        for (u32 i = 0; i < n; ++i)
        {
            ConsoleWrite("  rip=");
            WriteU64Hex(heap_rows[i].caller_rip, 16);
            ConsoleWrite(" bytes=");
            WriteU64Dec(heap_rows[i].bytes);
            ConsoleWrite(" count=");
            WriteU64Dec(heap_rows[i].count);
            ConsoleWriteChar('\n');
        }
    }
    if (cls == duetos::diag::ResourceClass::kGpuContext || cls == duetos::diag::ResourceClass::kGpuSurface ||
        cls == duetos::diag::ResourceClass::kGpuCmdBuffer || cls == duetos::diag::ResourceClass::kGpuMemory)
    {
        ConsoleWriteln("  (GAP: filled in by GPU driver as resource tables land)");
    }
    if (cls == duetos::diag::ResourceClass::kGdiObject)
    {
        ConsoleWriteln("  (GAP: per-process GDI ownership not tracked yet — totals are system-wide)");
    }
}

bool ParseDecU64(const char* s, u64* out)
{
    if (s == nullptr || s[0] == '\0')
        return false;
    u64 v = 0;
    for (u32 i = 0; s[i] != '\0'; ++i)
    {
        if (s[i] < '0' || s[i] > '9')
            return false;
        v = v * 10 + u64(s[i] - '0');
    }
    *out = v;
    return true;
}

void PrintLeakCheckPid(u64 pid)
{
    duetos::diag::ClassSnapshot rows[u32(duetos::diag::ResourceClass::kCount)];
    if (!duetos::diag::LeakDetectorSnapshotPid(pid, rows))
    {
        ConsoleWrite("LEAKCHECK: NO LIVE PROCESS WITH PID ");
        WriteU64Dec(pid);
        ConsoleWriteChar('\n');
        return;
    }
    ConsoleWrite("LEAKCHECK: PID ");
    WriteU64Dec(pid);
    ConsoleWriteln(" ATTRIBUTABLE RESIDUE");
    for (u32 i = 0; i < u32(duetos::diag::ResourceClass::kCount); ++i)
    {
        // Only print classes the per-PID accessor populated (skip
        // pure-zero rows that are global-only by design — heap,
        // socket, gdi, gpu).
        if (rows[i].outstanding == 0 && rows[i].byte_cost == 0)
            continue;
        PrintLeakRow(rows[i]);
    }
}

} // namespace

void CmdLeakCheck(u32 argc, char** argv)
{
    if (argc < 2)
    {
        PrintLeakCheckSummary();
        return;
    }
    if (StrEq(argv[1], "class"))
    {
        if (argc < 3)
        {
            ConsoleWriteln("LEAKCHECK CLASS: usage: leakcheck class <name>");
            return;
        }
        const auto cls = duetos::diag::LeakDetectorClassByName(argv[2]);
        PrintLeakCheckClass(cls);
        return;
    }
    if (StrEq(argv[1], "pid"))
    {
        u64 pid = 0;
        if (argc < 3 || !ParseDecU64(argv[2], &pid))
        {
            ConsoleWriteln("LEAKCHECK PID: usage: leakcheck pid <decimal_pid>");
            return;
        }
        PrintLeakCheckPid(pid);
        return;
    }
    if (StrEq(argv[1], "heap"))
    {
        PrintLeakCheckClass(duetos::diag::ResourceClass::kHeap);
        return;
    }
    // Bare class name (e.g. `leakcheck frame`) is also accepted.
    const auto cls = duetos::diag::LeakDetectorClassByName(argv[1]);
    if (cls != duetos::diag::ResourceClass::kCount)
    {
        PrintLeakCheckClass(cls);
        return;
    }
    ConsoleWriteln("LEAKCHECK: usage: leakcheck [class <name> | pid <n> | <class>]");
}

} // namespace duetos::core::shell::internal
