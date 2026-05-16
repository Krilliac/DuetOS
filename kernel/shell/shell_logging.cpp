// Logging / diagnostics shell commands (loglevel, logarea,
// logcolor, logclock, kdbg, metrics, faultinject). Split out
// of shell_debug.cpp to keep TUs within the size guideline;
// behaviour is unchanged.

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

} // namespace

void CmdLoglevel(u32 argc, char** argv)
{
    if (argc < 2)
    {
        const auto cur = duetos::core::GetLogThreshold();
        ConsoleWrite("LOG THRESHOLD: ");
        switch (cur)
        {
        case duetos::core::LogLevel::Trace:
            ConsoleWriteln("TRACE (fn enter/exit + timing)");
            break;
        case duetos::core::LogLevel::Debug:
            ConsoleWriteln("DEBUG (show everything)");
            break;
        case duetos::core::LogLevel::Info:
            ConsoleWriteln("INFO");
            break;
        case duetos::core::LogLevel::Warn:
            ConsoleWriteln("WARN");
            break;
        case duetos::core::LogLevel::Error:
            ConsoleWriteln("ERROR (show only errors)");
            break;
        case duetos::core::LogLevel::Critical:
            ConsoleWriteln("CRITICAL (only catastrophic events)");
            break;
        default:
            ConsoleWriteln("?");
            break;
        }
        ConsoleWriteln("USAGE: LOGLEVEL [T|D|I|W|E|C]");
        ConsoleWriteln("       LOGLEVEL <area-name> [T|D|I|W|E|C]   (per-area override)");
        ConsoleWriteln("RUN `LOGAREA` TO LIST AREAS.");
        return;
    }
    // Two-arg form: per-area level. Parse the first as an area
    // name; if it matches, treat the second as the level. Allows
    // operators to e.g. "loglevel net w" to silence everything
    // below Warn from the Net area while leaving other areas alone.
    if (argc >= 3)
    {
        const auto area = duetos::core::LogAreaFromName(argv[1]);
        if (area != duetos::core::LogArea::None && area != duetos::core::LogArea::All)
        {
            const char c2 = argv[2][0];
            duetos::core::LogLevel lvl2 = duetos::core::LogLevel::Trace;
            switch (c2)
            {
            case 't':
            case 'T':
                lvl2 = duetos::core::LogLevel::Trace;
                break;
            case 'd':
            case 'D':
                lvl2 = duetos::core::LogLevel::Debug;
                break;
            case 'i':
            case 'I':
                lvl2 = duetos::core::LogLevel::Info;
                break;
            case 'w':
            case 'W':
                lvl2 = duetos::core::LogLevel::Warn;
                break;
            case 'e':
            case 'E':
                lvl2 = duetos::core::LogLevel::Error;
                break;
            case 'c':
            case 'C':
                lvl2 = duetos::core::LogLevel::Critical;
                break;
            default:
                ConsoleWriteln("LOGLEVEL: USE T / D / I / W / E / C");
                return;
            }
            duetos::core::SetLogAreaLevel(area, lvl2);
            ConsoleWriteln("PER-AREA LEVEL UPDATED");
            return;
        }
    }
    const char c = argv[1][0];
    duetos::core::LogLevel lvl = duetos::core::LogLevel::Info;
    switch (c)
    {
    case 't':
    case 'T':
        lvl = duetos::core::LogLevel::Trace;
        break;
    case 'd':
    case 'D':
        lvl = duetos::core::LogLevel::Debug;
        break;
    case 'i':
    case 'I':
        lvl = duetos::core::LogLevel::Info;
        break;
    case 'w':
    case 'W':
        lvl = duetos::core::LogLevel::Warn;
        break;
    case 'e':
    case 'E':
        lvl = duetos::core::LogLevel::Error;
        break;
    case 'c':
    case 'C':
        lvl = duetos::core::LogLevel::Critical;
        break;
    default:
        ConsoleWriteln("LOGLEVEL: USE T / D / I / W / E / C");
        return;
    }
    duetos::core::SetLogThreshold(lvl);
    ConsoleWriteln("LOG THRESHOLD UPDATED");
}

// LOGAREA — list / toggle log-area mask.
//   LOGAREA              — print current mask + per-area names
//   LOGAREA ALL ON       — enable every area
//   LOGAREA ALL OFF      — disable every area (only general remains)
//   LOGAREA <name> ON    — enable single area
//   LOGAREA <name> OFF   — disable single area
//
// Areas: general boot memory sched process syscall loader fs net
// storage usb gpu input audio ipc win32 linux time power security
// diag ring3 app driver acpi pci wireless graphics test arith.
void CmdLogarea(u32 argc, char** argv)
{
    if (argc < 2)
    {
        const u32 mask = duetos::core::GetLogAreaMask();
        ConsoleWrite("LOG AREA MASK: 0x");
        char hex[9];
        const char* h = "0123456789abcdef";
        for (int i = 7; i >= 0; --i)
            hex[7 - i] = h[(mask >> (i * 4)) & 0xF];
        hex[8] = '\0';
        ConsoleWriteln(hex);
        ConsoleWriteln("ENABLED AREAS:");
        constexpr duetos::core::LogArea kSingles[] = {
            duetos::core::LogArea::General,  duetos::core::LogArea::Boot,     duetos::core::LogArea::Memory,
            duetos::core::LogArea::Sched,    duetos::core::LogArea::Process,  duetos::core::LogArea::Syscall,
            duetos::core::LogArea::Loader,   duetos::core::LogArea::FS,       duetos::core::LogArea::Net,
            duetos::core::LogArea::Storage,  duetos::core::LogArea::USB,      duetos::core::LogArea::GPU,
            duetos::core::LogArea::Input,    duetos::core::LogArea::Audio,    duetos::core::LogArea::IPC,
            duetos::core::LogArea::Win32,    duetos::core::LogArea::Linux,    duetos::core::LogArea::Time,
            duetos::core::LogArea::Power,    duetos::core::LogArea::Security, duetos::core::LogArea::Diag,
            duetos::core::LogArea::Ring3,    duetos::core::LogArea::App,      duetos::core::LogArea::Driver,
            duetos::core::LogArea::ACPI,     duetos::core::LogArea::PCI,      duetos::core::LogArea::Wireless,
            duetos::core::LogArea::Graphics, duetos::core::LogArea::Test,     duetos::core::LogArea::Arith,
        };
        for (auto a : kSingles)
        {
            ConsoleWrite(" ");
            ConsoleWrite(duetos::core::LogAreaName(a));
            ConsoleWrite(" ");
            ConsoleWriteln(duetos::core::IsLogAreaEnabled(a) ? "[on]" : "[off]");
        }
        ConsoleWriteln("USAGE: LOGAREA [<name> ON|OFF]   (or  LOGAREA ALL ON|OFF)");
        return;
    }
    const auto area = duetos::core::LogAreaFromName(argv[1]);
    if (area == duetos::core::LogArea::None)
    {
        ConsoleWrite("LOGAREA: UNKNOWN AREA \"");
        ConsoleWrite(argv[1]);
        ConsoleWriteln("\". RUN `LOGAREA` FOR THE FULL LIST.");
        return;
    }
    if (argc < 3)
    {
        ConsoleWrite(duetos::core::LogAreaName(area));
        ConsoleWriteln(duetos::core::IsLogAreaEnabled(area) ? " ON" : " OFF");
        return;
    }
    const char c = argv[2][0];
    const bool turn_on = (c == 'o' || c == 'O') ? (argv[2][1] == 'n' || argv[2][1] == 'N') : false;
    if (turn_on)
        duetos::core::EnableLogArea(area);
    else
        duetos::core::DisableLogArea(area);
    ConsoleWriteln("LOG AREA UPDATED");
}

void CmdLogcolor(u32 argc, char** argv)
{
    if (argc < 2)
    {
        const bool cur = duetos::core::GetLogColor();
        ConsoleWrite("SERIAL LOG COLOUR: ");
        ConsoleWriteln(cur ? "ON" : "OFF");
        ConsoleWriteln("USAGE: LOGCOLOR ON|OFF");
        return;
    }
    const char c = argv[1][0];
    const bool want = (c == 'o' || c == 'O') ? (argv[1][1] == 'n' || argv[1][1] == 'N') : false;
    duetos::core::SetLogColor(want);
    ConsoleWrite("SERIAL LOG COLOUR: ");
    ConsoleWriteln(want ? "ON" : "OFF");
}

void CmdLogclock(u32 argc, char** argv)
{
    if (argc < 2)
    {
        const bool cur = duetos::core::GetLogWallClock();
        ConsoleWrite("LOG WALL-CLOCK PREFIX: ");
        ConsoleWriteln(cur ? "ON" : "OFF");
        ConsoleWriteln("USAGE: LOGCLOCK ON|OFF");
        return;
    }
    const char c = argv[1][0];
    const bool want = (c == 'o' || c == 'O') ? (argv[1][1] == 'n' || argv[1][1] == 'N') : false;
    duetos::core::SetLogWallClock(want);
    ConsoleWrite("LOG WALL-CLOCK PREFIX: ");
    ConsoleWriteln(want ? "ON" : "OFF");
}

void CmdKdbg(u32 argc, char** argv)
{
    if (argc < 2)
    {
        ConsoleWriteln("KDBG: USAGE");
        ConsoleWriteln("  KDBG LIST");
        ConsoleWriteln("  KDBG ON <CHANNEL>");
        ConsoleWriteln("  KDBG OFF <CHANNEL>");
        ConsoleWriteln("  KDBG MASK 0x<HEX>");
        ConsoleWriteln("  KDBG ON ALL  /  KDBG OFF ALL");
        return;
    }
    const char* sub = argv[1];
    if (StrEq(sub, "list"))
    {
        duetos::core::DbgListChannels();
        return;
    }
    if (StrEq(sub, "on"))
    {
        if (argc < 3)
        {
            ConsoleWriteln("KDBG ON: USE A CHANNEL NAME (OR \"ALL\")");
            return;
        }
        const auto ch = duetos::core::DbgChannelByName(argv[2]);
        if (ch == duetos::core::DbgChannel::None)
        {
            ConsoleWriteln("KDBG: UNKNOWN CHANNEL");
            return;
        }
        duetos::core::DbgEnable(static_cast<u32>(ch));
        ConsoleWriteln("KDBG: ENABLED");
        return;
    }
    if (StrEq(sub, "off"))
    {
        if (argc < 3)
        {
            ConsoleWriteln("KDBG OFF: USE A CHANNEL NAME (OR \"ALL\")");
            return;
        }
        const auto ch = duetos::core::DbgChannelByName(argv[2]);
        if (ch == duetos::core::DbgChannel::None)
        {
            ConsoleWriteln("KDBG: UNKNOWN CHANNEL");
            return;
        }
        duetos::core::DbgDisable(static_cast<u32>(ch));
        ConsoleWriteln("KDBG: DISABLED");
        return;
    }
    if (StrEq(sub, "mask"))
    {
        if (argc < 3)
        {
            ConsoleWriteln("KDBG MASK: USE 0x<HEX>");
            return;
        }
        u64 v = 0;
        if (!ParseU64Str(argv[2], &v))
        {
            ConsoleWriteln("KDBG MASK: BAD HEX");
            return;
        }
        duetos::core::DbgSet(static_cast<u32>(v));
        ConsoleWriteln("KDBG: MASK SET");
        return;
    }
    ConsoleWriteln("KDBG: UNKNOWN SUBCOMMAND");
}

void CmdMetrics()
{
    duetos::core::LogMetrics(duetos::core::LogLevel::Info, "shell", "user-requested");
    ConsoleWriteln("(also logged to kernel ring at INFO)");
}

void CmdFaultInject(u32 argc, char** argv)
{
    if (argc < 2)
    {
        ConsoleWriteln("FAULT-INJECT: USAGE:");
        ConsoleWriteln("    FAULT-INJECT NULL-DEREF   KERNEL #PF FROM AN UNMAPPED VA");
        ConsoleWriteln("    FAULT-INJECT PANIC        DELIBERATE KERNEL PANIC");
        ConsoleWriteln("    FAULT-INJECT OOM-SLAB     DRAIN A SLAB TO SlabAlloc==nullptr");
        return;
    }
    const char* arg = argv[1];
    using ::duetos::diag::fault_inject::FaultClass;
    FaultClass fc;
    if (StrEq(arg, "null-deref"))
    {
        fc = FaultClass::NullDeref;
    }
    else if (StrEq(arg, "panic"))
    {
        fc = FaultClass::Panic;
    }
    else if (StrEq(arg, "oom-slab"))
    {
        fc = FaultClass::OomSlab;
    }
    else
    {
        ConsoleWrite("FAULT-INJECT: UNKNOWN CLASS ");
        ConsoleWriteln(arg);
        ShellSetExit(1);
        return;
    }
    const auto r = ::duetos::diag::fault_inject::Trigger(fc);
    // Only OomSlab returns; NullDeref and Panic transferred control
    // to the trap or panic path before reaching this point.
    if (r.has_value())
    {
        ConsoleWriteln("FAULT-INJECT: OOM-SLAB OK (RECOVERED FROM SlabAlloc==nullptr)");
        return;
    }
    ConsoleWrite("FAULT-INJECT: ERROR ");
    ConsoleWriteln(::duetos::core::ErrorCodeName(r.error()));
    ShellSetExit(1);
}


} // namespace duetos::core::shell::internal
