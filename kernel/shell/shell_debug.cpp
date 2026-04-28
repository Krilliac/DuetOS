/*
 * DuetOS — kernel shell: debug + introspection commands.
 *
 * Sibling TU of shell.cpp. Houses the operator-facing windows
 * onto the kernel's debug machinery: arbitrary memory dump,
 * software / hardware breakpoint interface, runtime probe
 * arming, instruction-byte decode, symbol resolver, the
 * RE / triage `inspect` umbrella, global state snapshot, and
 * the trace log-threshold toggle.
 *
 * TU-private helpers (BpKindName, BpErrName, TakeSuspendFlag,
 * PrintBpRegs, ProbeArmName, CmdInspectHelp/Syscalls/Opcodes/Arm)
 * stay in this file's anon namespace — they're only called from
 * within this TU and shouldn't pollute shell_internal.h.
 */

#include "shell/shell_internal.h"

#include "arch/x86_64/serial.h"
#include "arch/x86_64/traps.h"
#include "debug/breakpoints.h"
#include "debug/inspect.h"
#include "debug/probes.h"
#include "debug/syscall_scan.h"
#include "drivers/video/console.h"
#include "mm/kheap.h"
#include "mm/paging.h"
#include "sched/sched.h"
#include "core/init.h"
#include "diag/event_trace.h"
#include "diag/gdb_stub.h"
#include "ipc/kobject.h"
#include "util/random.h"
#include "diag/hexdump.h"
#include "diag/kdbg.h"
#include "diag/perf_profile.h"
#include "diag/soft_lockup.h"
#include "diag/ubsan.h"
#include "mm/zone.h"
#include "security/driver_domain.h"
#include "security/fault_domain.h"
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

const char* BpKindName(duetos::debug::BpKind k)
{
    switch (k)
    {
    case duetos::debug::BpKind::Software:
        return "SW";
    case duetos::debug::BpKind::HwExecute:
        return "HW-X";
    case duetos::debug::BpKind::HwWrite:
        return "HW-W";
    case duetos::debug::BpKind::HwReadWrite:
        return "HW-RW";
    default:
        return "?";
    }
}

const char* BpErrName(duetos::debug::BpError e)
{
    switch (e)
    {
    case duetos::debug::BpError::None:
        return "OK";
    case duetos::debug::BpError::InvalidAddress:
        return "INVALID-ADDRESS";
    case duetos::debug::BpError::TableFull:
        return "TABLE-FULL";
    case duetos::debug::BpError::NoHwSlot:
        return "NO-HW-SLOT";
    case duetos::debug::BpError::BadKind:
        return "BAD-KIND";
    case duetos::debug::BpError::NotInstalled:
        return "NOT-INSTALLED";
    case duetos::debug::BpError::SmpUnsupported:
        return "SMP-UNSUPPORTED";
    default:
        return "?";
    }
}

// Consume a leading `--suspend` / `-s` flag from argv starting at
// `start`. If present, set *suspend and slide argv left by one so
// the remaining args are positional. Returns the new argc.
u32 TakeSuspendFlag(u32 argc, char** argv, u32 start, bool* suspend)
{
    if (argc <= start || argv[start] == nullptr)
        return argc;
    if (StrEq(argv[start], "--suspend") || StrEq(argv[start], "-s"))
    {
        *suspend = true;
        for (u32 i = start; i + 1 < argc; ++i)
            argv[i] = argv[i + 1];
        return argc - 1;
    }
    return argc;
}

void PrintBpRegs(const duetos::arch::TrapFrame& f)
{
    ConsoleWrite("  rip=");
    WriteU64Hex(f.rip, 16);
    ConsoleWrite(" cs=");
    WriteU64Hex(f.cs, 4);
    ConsoleWrite(" flags=");
    WriteU64Hex(f.rflags, 16);
    ConsoleWriteChar('\n');
    ConsoleWrite("  rsp=");
    WriteU64Hex(f.rsp, 16);
    ConsoleWrite(" ss=");
    WriteU64Hex(f.ss, 4);
    ConsoleWriteChar('\n');
    ConsoleWrite("  rax=");
    WriteU64Hex(f.rax, 16);
    ConsoleWrite(" rbx=");
    WriteU64Hex(f.rbx, 16);
    ConsoleWriteChar('\n');
    ConsoleWrite("  rcx=");
    WriteU64Hex(f.rcx, 16);
    ConsoleWrite(" rdx=");
    WriteU64Hex(f.rdx, 16);
    ConsoleWriteChar('\n');
    ConsoleWrite("  rsi=");
    WriteU64Hex(f.rsi, 16);
    ConsoleWrite(" rdi=");
    WriteU64Hex(f.rdi, 16);
    ConsoleWriteChar('\n');
    ConsoleWrite("  rbp=");
    WriteU64Hex(f.rbp, 16);
    ConsoleWrite(" r8 =");
    WriteU64Hex(f.r8, 16);
    ConsoleWriteChar('\n');
    ConsoleWrite("  r9 =");
    WriteU64Hex(f.r9, 16);
    ConsoleWrite(" r10=");
    WriteU64Hex(f.r10, 16);
    ConsoleWriteChar('\n');
    ConsoleWrite("  r11=");
    WriteU64Hex(f.r11, 16);
    ConsoleWrite(" r12=");
    WriteU64Hex(f.r12, 16);
    ConsoleWriteChar('\n');
    ConsoleWrite("  r13=");
    WriteU64Hex(f.r13, 16);
    ConsoleWrite(" r14=");
    WriteU64Hex(f.r14, 16);
    ConsoleWriteChar('\n');
    ConsoleWrite("  r15=");
    WriteU64Hex(f.r15, 16);
    ConsoleWrite(" vec=");
    WriteU64Hex(f.vector, 2);
    ConsoleWriteChar('\n');
}

const char* ProbeArmName(duetos::debug::ProbeArm a)
{
    switch (a)
    {
    case duetos::debug::ProbeArm::Disarmed:
        return "DISARMED";
    case duetos::debug::ProbeArm::ArmedLog:
        return "ARMED-LOG";
    case duetos::debug::ProbeArm::ArmedSuspend:
        return "ARMED-SUSPEND";
    default:
        return "?";
    }
}

void CmdInspectHelp()
{
    ConsoleWriteln("INSPECT: RE / TRIAGE UMBRELLA (SEE COM1 FOR REPORTS)");
    ConsoleWriteln("  INSPECT SYSCALLS KERNEL | <PATH>  FIND SYSCALL SITES + COVERAGE");
    ConsoleWriteln("  INSPECT SYSCALLS CAPS             DUMP CAP-TABLE: REQUIRED CAP PER SYSCALL");
    ConsoleWriteln("  INSPECT OPCODES <PATH>            FIRST-BYTE HISTOGRAM + CLASS TALLY");
    ConsoleWriteln("  INSPECT ARM ON|OFF|STATUS         ONE-SHOT OPCODES SCAN ON NEXT SPAWN");
    ConsoleWriteln("  INSPECT LOCKDEP                   LOCKDEP COUNTERS + REGISTERED CLASSES");
    ConsoleWriteln("  INSPECT DOMAINS                   FAULT DOMAINS (DRIVER + HAND-REGISTERED)");
    ConsoleWriteln("  INSPECT ZONES                     PER-ZONE ALLOCATOR STATS");
    ConsoleWriteln("  INSPECT THREADS                   TASK ROSTER");
    ConsoleWriteln("  INSPECT TRACER-STATS              EVENT TRACER COUNTERS (NO DUMP)");
    ConsoleWriteln("  INSPECT GDB                       GDB STUB COUNTERS");
    ConsoleWriteln("  INSPECT RCU                       RCU QUEUED/COMPLETED");
    ConsoleWriteln("  INSPECT UPTIME                    TICK + MONOTONIC NS");
    ConsoleWriteln("  INSPECT COUNTERS                  ALL-SUBSYSTEM COUNTER ROLLUP");
    ConsoleWriteln("  INSPECT IPC                       KNOWN KOBJECT TYPES");
    ConsoleWriteln("  INSPECT SECURITY                  FAULT-DOMAIN + INITCALL COUNTS");
    ConsoleWriteln("  INSPECT ENTROPY                   ENTROPY TIER + COUNTERS");
    ConsoleWriteln("  INSPECT HELP                      THIS LIST");
}

// Dump lockdep-lite state: total inversions detected since boot,
// total edges recorded, and the canonical class IDs registered via
// `LockdepRegisterCanonicalClasses()`. Output goes to COM1
// (machine-greppable) plus a one-line summary on the console.
//
// Inversions=0 is the green-path expectation; any non-zero count
// is a triage hit. Edges-recorded grows monotonically as the kernel
// exercises new acquire pairs — useful as a "graph stabilised yet?"
// signal for the future inversion-warn-to-panic promotion knob.
// `inspect ipc` — list every known KObjectType + reachable
// global counters. v0 doesn't enumerate per-process handle
// tables (that needs a process-walker first); the registry of
// types + the type-name mapping is the audit surface that's
// reachable today.
void CmdInspectIpc()
{
    ConsoleWriteln("INSPECT IPC: known KObject types (id name)");
    static constexpr duetos::ipc::KObjectType kTypes[] = {
        duetos::ipc::KObjectType::Mutex,   duetos::ipc::KObjectType::Event,    duetos::ipc::KObjectType::Semaphore,
        duetos::ipc::KObjectType::Mailbox, duetos::ipc::KObjectType::Waitable, duetos::ipc::KObjectType::File,
    };
    for (auto t : kTypes)
    {
        ConsoleWrite("  ");
        WriteU64Dec(static_cast<u64>(t));
        ConsoleWrite(" ");
        ConsoleWriteln(duetos::ipc::KObjectTypeName(t));
    }
}

// `inspect security` — fault-domain count + driver-domain
// count + total registered initcalls. Single-screen rollup of
// the security-shaped surfaces.
void CmdInspectSecurity()
{
    ConsoleWrite("INSPECT SECURITY: fault-domains=");
    WriteU64Dec(duetos::core::FaultDomainCount());
    ConsoleWrite(" driver-tagged=");
    WriteU64Dec(duetos::security::DriverDomainCount());
    ConsoleWrite(" initcalls=");
    WriteU64Dec(duetos::core::InitcallCount());
    ConsoleWriteChar('\n');
}

// `inspect entropy` — current tier + per-source counters.
void CmdInspectEntropy()
{
    const auto s = duetos::core::RandomStatsRead();
    const auto tier = duetos::core::RandomCurrentTier();
    static const char* tier_name[] = {"Splitmix", "Rdrand", "Rdseed"};
    ConsoleWrite("INSPECT ENTROPY: tier=");
    ConsoleWrite(tier_name[static_cast<u8>(tier)]);
    ConsoleWrite(" rdseed=");
    WriteU64Dec(s.rdseed_successes);
    ConsoleWriteChar('/');
    WriteU64Dec(s.rdseed_calls);
    ConsoleWrite(" rdrand=");
    WriteU64Dec(s.rdrand_successes);
    ConsoleWriteChar('/');
    WriteU64Dec(s.rdrand_calls);
    ConsoleWrite(" splitmix=");
    WriteU64Dec(s.splitmix_calls);
    ConsoleWrite(" bytes=");
    WriteU64Dec(s.bytes_produced);
    ConsoleWriteChar('\n');
}

// `inspect rcu` — RCU subsystem counters (queued / completed
// / inversions / current tick). Cheap; pairs with `domain
// restart rcu` (no such domain today) for diagnostic flow.
void CmdInspectRcu()
{
    const u64 q = duetos::sync::RcuCallsQueued();
    const u64 c = duetos::sync::RcuCallsCompleted();
    ConsoleWrite("INSPECT RCU: queued=");
    WriteU64Dec(q);
    ConsoleWrite(" completed=");
    WriteU64Dec(c);
    ConsoleWrite(" pending=");
    WriteU64Dec(q - c);
    ConsoleWriteChar('\n');
}

// `inspect uptime` — boot uptime in scheduler ticks +
// nanoseconds (via the time:: facade). Cheap diagnostic.
void CmdInspectUptime()
{
    const u64 ticks = duetos::time::TickCount();
    const u64 ns = duetos::time::MonotonicNs();
    ConsoleWrite("INSPECT UPTIME: ticks=");
    WriteU64Dec(ticks);
    ConsoleWrite(" monotonic_ns=");
    WriteU64Dec(ns);
    ConsoleWrite(" tick_hz=");
    WriteU64Dec(duetos::time::TickHz());
    ConsoleWriteChar('\n');
}

// `inspect counters` — single-screen rollup of every subsystem
// counter that has a cheap accessor. Lockdep / soft-lockup /
// event-trace / GDB stub / RCU all in one place.
void CmdInspectCounters()
{
    using duetos::arch::SerialWrite;
    SerialWrite("[inspect-counters] one-line per subsystem\n");
    ConsoleWrite("INSPECT COUNTERS:\n");
    ConsoleWrite("  lockdep     inversions=");
    WriteU64Dec(duetos::sync::LockdepInversionsDetected());
    ConsoleWrite(" edges=");
    WriteU64Dec(duetos::sync::LockdepEdgesRecorded());
    ConsoleWriteChar('\n');
    ConsoleWrite("  soft-lockup warnings=");
    WriteU64Dec(duetos::diag::SoftLockupWarningsEmitted());
    ConsoleWriteChar('\n');
    ConsoleWrite("  rcu         queued=");
    WriteU64Dec(duetos::sync::RcuCallsQueued());
    ConsoleWrite(" completed=");
    WriteU64Dec(duetos::sync::RcuCallsCompleted());
    ConsoleWriteChar('\n');
    ConsoleWrite("  event-trace live=");
    WriteU64Dec(duetos::diag::EventTraceLiveCount());
    ConsoleWrite(" total=");
    WriteU64Dec(duetos::diag::EventTraceTotalRecords());
    ConsoleWriteChar('\n');
    ConsoleWrite("  perf        live=");
    WriteU64Dec(duetos::diag::PerfLiveCount());
    ConsoleWrite(" total=");
    WriteU64Dec(duetos::diag::PerfTotalSamples());
    ConsoleWriteChar('\n');
    ConsoleWrite("  gdb-stub    received=");
    WriteU64Dec(duetos::diag::gdb::GdbStubPacketsReceived());
    ConsoleWrite(" handled=");
    WriteU64Dec(duetos::diag::gdb::GdbStubPacketsHandled());
    ConsoleWrite(" bad-csum=");
    WriteU64Dec(duetos::diag::gdb::GdbStubPacketsBadChecksum());
    ConsoleWriteChar('\n');
    ConsoleWrite("  ubsan       reports=");
    WriteU64Dec(duetos::diag::UbsanReportsEmitted());
    ConsoleWriteChar('\n');
}

// `inspect threads` — list every known scheduler task with its
// id / name / state / cumulative ticks. Walks SchedEnumerate
// under CLI so the snapshot is consistent.
void CmdInspectThreads()
{
    static constexpr const char* kStateName[] = {"Ready", "Running", "Sleeping", "Blocked", "Dead"};
    struct Cookie
    {
        u32 count;
    } cookie = {0};
    auto cb = [](const duetos::sched::SchedTaskInfo& info, void* c)
    {
        auto* ck = static_cast<Cookie*>(c);
        ++ck->count;
        ConsoleWrite("  tid=");
        WriteU64Dec(info.id);
        ConsoleWrite(" name=");
        ConsoleWrite(info.name != nullptr ? info.name : "<null>");
        ConsoleWrite(" state=");
        ConsoleWrite((info.state < 5) ? kStateName[info.state] : "?");
        if (info.is_running)
            ConsoleWrite(" *running*");
        ConsoleWrite(" ticks=");
        WriteU64Dec(info.ticks_run);
        ConsoleWriteChar('\n');
    };
    ConsoleWriteln("INSPECT THREADS:");
    duetos::sched::SchedEnumerate(cb, &cookie);
    ConsoleWrite("INSPECT THREADS: total=");
    WriteU64Dec(cookie.count);
    ConsoleWriteChar('\n');
}

// `inspect tracer-stats` — read-only event-tracer counters
// without dumping the ring. Cheap; pairs with `tracer dump`
// for "is the ring growing?" diagnostics.
void CmdInspectTracerStats()
{
    const u32 live = duetos::diag::EventTraceLiveCount();
    const u64 total = duetos::diag::EventTraceTotalRecords();
    ConsoleWrite("INSPECT TRACER: live=");
    WriteU64Dec(live);
    ConsoleWrite(" total-since-boot=");
    WriteU64Dec(total);
    ConsoleWrite(" capacity=");
    WriteU64Dec(duetos::diag::kEventRingCapacity);
    ConsoleWriteChar('\n');
}

// `inspect gdb` — GDB stub packet counters (received,
// bad-checksum, handled). Confirms the stub is alive without
// requiring a real GDB attach.
void CmdInspectGdb()
{
    ConsoleWrite("INSPECT GDB: received=");
    WriteU64Dec(duetos::diag::gdb::GdbStubPacketsReceived());
    ConsoleWrite(" handled=");
    WriteU64Dec(duetos::diag::gdb::GdbStubPacketsHandled());
    ConsoleWrite(" bad-csum=");
    WriteU64Dec(duetos::diag::gdb::GdbStubPacketsBadChecksum());
    ConsoleWriteChar('\n');
}

// `inspect domains` — list every registered fault domain
// (driver-domain wrapper or hand-registered). Shows name +
// restart count + alive flag. Read-only audit surface for
// "what subsystems can the operator restart from the shell".
void CmdInspectDomains()
{
    using duetos::arch::SerialWrite;
    const u32 driver_count = duetos::security::DriverDomainCount();
    const u32 total_count = duetos::core::FaultDomainCount();
    SerialWrite("[inspect-domains] driver-tagged=");
    duetos::arch::SerialWriteHex(driver_count);
    SerialWrite(" total=");
    duetos::arch::SerialWriteHex(total_count);
    SerialWrite("\n");
    for (u32 i = 0; i < total_count; ++i)
    {
        const auto* d = duetos::core::FaultDomainGet(i);
        if (d == nullptr || d->name == nullptr)
            continue;
        SerialWrite("[inspect-domains] id=");
        duetos::arch::SerialWriteHex(i);
        SerialWrite(" name=");
        SerialWrite(d->name);
        SerialWrite(" restarts=");
        duetos::arch::SerialWriteHex(d->restart_count);
        SerialWrite(d->alive ? " alive" : " dead");
        SerialWrite("\n");
    }
    ConsoleWrite("INSPECT DOMAINS: total=");
    WriteU64Dec(total_count);
    ConsoleWrite(" driver-tagged=");
    WriteU64Dec(driver_count);
    ConsoleWriteln(" (DETAILS ON COM1)");
}

// `inspect zones` — print per-zone allocate/free/oom counts.
// Diagnostic surface for "is anyone hitting DMA-zone OOM".
void CmdInspectZones()
{
    using duetos::arch::SerialWrite;
    SerialWrite("[inspect-zones] per-zone allocator stats\n");
    for (u32 i = 0; i < static_cast<u32>(duetos::mm::Zone::Count); ++i)
    {
        const auto z = static_cast<duetos::mm::Zone>(i);
        const auto s = duetos::mm::ZoneStatsRead(z);
        SerialWrite("  ");
        SerialWrite(duetos::mm::ZoneName(z));
        SerialWrite(" allocs=");
        duetos::arch::SerialWriteHex(s.allocs);
        SerialWrite(" frees=");
        duetos::arch::SerialWriteHex(s.frees);
        SerialWrite(" oom=");
        duetos::arch::SerialWriteHex(s.oom);
        SerialWrite("\n");
    }
    ConsoleWriteln("INSPECT ZONES: per-zone counts on COM1");
}

void CmdInspectLockdep()
{
    using duetos::arch::SerialWrite;
    using duetos::arch::SerialWriteHex;

    const u64 inversions = ::duetos::sync::LockdepInversionsDetected();
    const u64 edges = ::duetos::sync::LockdepEdgesRecorded();

    const bool panic_on_invert = ::duetos::sync::LockdepPromoteToPanic();

    SerialWrite("[inspect-lockdep] inversions=");
    SerialWriteHex(inversions);
    SerialWrite(" edges=");
    SerialWriteHex(edges);
    SerialWrite(" panic-on-invert=");
    SerialWrite(panic_on_invert ? "on" : "off");
    SerialWrite("\n");

    // Walk the canonical class-ID range (0x01..0x3F per the
    // `lockdep.h` convention). Print each class's name + ID.
    // Unregistered IDs in that range come back as "?" from
    // `LockdepClassName`; skip them.
    for (u32 id = 1; id <= 0x3F; ++id)
    {
        const char* name = ::duetos::sync::LockdepClassName(static_cast<::duetos::sync::LockClass>(id));
        if (name == nullptr || name[0] == '?')
        {
            continue;
        }
        SerialWrite("[inspect-lockdep] class id=");
        SerialWriteHex(id);
        SerialWrite(" name=");
        SerialWrite(name);
        SerialWrite("\n");
    }

    ConsoleWrite("INSPECT LOCKDEP: inversions=");
    WriteU64Dec(inversions);
    ConsoleWrite(" edges=");
    WriteU64Dec(edges);
    ConsoleWrite(" panic-on-invert=");
    ConsoleWrite(panic_on_invert ? "ON" : "OFF");
    ConsoleWriteln(" (CLASS LIST ON COM1)");
}

// Walk every row of `kSyscallCapTable` and print, for each:
//   - the syscall number (decimal + hex),
//   - its `SYS_FOO` identifier (via `SyscallNumberName`),
//   - the first cap bit set in the required mask, resolved through
//     `CapName`,
//   - the raw mask in hex.
//
// Output goes to COM1 in machine-greppable shape (`[inspect-sc-caps]
// row ...`) so a future audit tool can diff the table across boots.
// A summary line at the end records the row count, mirroring the
// existing `inspect syscalls` site report.
void CmdInspectSyscallsCaps()
{
    using duetos::arch::SerialWrite;
    using duetos::arch::SerialWriteHex;

    ConsoleWriteln("INSPECT SYSCALLS CAPS: DUMPING CAP TABLE (SEE COM1)");

    SerialWrite("[inspect-sc-caps] start rows=");
    SerialWriteHex(::duetos::core::kSyscallCapTableCount);
    SerialWrite("\n");

    for (u32 i = 0; i < ::duetos::core::kSyscallCapTableCount; ++i)
    {
        const auto& row = ::duetos::core::kSyscallCapTable[i];
        const char* sys_name = ::duetos::core::SyscallNumberName(row.nr);
        if (sys_name == nullptr)
            sys_name = "<unknown>";

        // First cap bit set in the mask. Mirrors the gate's
        // `FirstMissingCap` so audit output matches denial logs.
        ::duetos::core::Cap first = ::duetos::core::kCapNone;
        for (u32 c = 1; c < static_cast<u32>(::duetos::core::kCapCount); ++c)
        {
            if ((row.required_mask & (1ULL << c)) != 0)
            {
                first = static_cast<::duetos::core::Cap>(c);
                break;
            }
        }
        const char* cap_name = (first == ::duetos::core::kCapNone) ? "<none>" : ::duetos::core::CapName(first);

        SerialWrite("[inspect-sc-caps] row nr=");
        SerialWriteHex(row.nr);
        SerialWrite(" name=");
        SerialWrite(sys_name);
        SerialWrite(" cap=");
        SerialWrite(cap_name);
        SerialWrite(" mask=");
        SerialWriteHex(row.required_mask);
        SerialWrite("\n");
    }

    SerialWrite("[inspect-sc-caps] summary rows=");
    SerialWriteHex(::duetos::core::kSyscallCapTableCount);
    SerialWrite("\n");

    ConsoleWriteln("INSPECT SYSCALLS CAPS: DONE");
}

void CmdInspectSyscalls(u32 argc, char** argv)
{
    if (argc < 3)
    {
        ConsoleWriteln("INSPECT SYSCALLS: USAGE: INSPECT SYSCALLS KERNEL | CAPS | <PATH>");
        return;
    }
    if (StrEq(argv[2], "kernel"))
    {
        ConsoleWriteln("INSPECT SYSCALLS: SCANNING KERNEL .TEXT (SEE COM1)");
        (void)duetos::debug::SyscallScanKernelText();
        ConsoleWriteln("INSPECT SYSCALLS: DONE");
        return;
    }
    if (StrEq(argv[2], "caps"))
    {
        CmdInspectSyscallsCaps();
        return;
    }
    ConsoleWrite("INSPECT SYSCALLS: SCANNING FILE \"");
    ConsoleWrite(argv[2]);
    ConsoleWriteln("\" (SEE COM1)");
    (void)duetos::debug::SyscallScanFile(argv[2]);
    ConsoleWriteln("INSPECT SYSCALLS: DONE");
}

void CmdInspectOpcodes(u32 argc, char** argv)
{
    if (argc < 3)
    {
        ConsoleWriteln("INSPECT OPCODES: USAGE: INSPECT OPCODES <PATH>");
        return;
    }
    ConsoleWrite("INSPECT OPCODES: SCANNING FILE \"");
    ConsoleWrite(argv[2]);
    ConsoleWriteln("\" (SEE COM1)");
    duetos::debug::OpcodeScanFile(argv[2]);
    ConsoleWriteln("INSPECT OPCODES: DONE");
}

void CmdInspectArm(u32 argc, char** argv)
{
    if (argc < 3)
    {
        ConsoleWriteln("INSPECT ARM: USAGE: INSPECT ARM ON|OFF|STATUS");
        return;
    }
    if (StrEq(argv[2], "on"))
    {
        duetos::debug::InspectArmSet(true);
        ConsoleWriteln("INSPECT ARM: ARMED - OPCODES SCAN WILL FIRE ON NEXT SPAWN");
        return;
    }
    if (StrEq(argv[2], "off"))
    {
        duetos::debug::InspectArmSet(false);
        ConsoleWriteln("INSPECT ARM: DISARMED");
        return;
    }
    if (StrEq(argv[2], "status"))
    {
        ConsoleWriteln(duetos::debug::InspectArmActive() ? "INSPECT ARM: STATE=ON (ONE-SHOT)" //
                                                         : "INSPECT ARM: STATE=OFF");
        return;
    }
    ConsoleWriteln("INSPECT ARM: UNKNOWN MODE (USE ON/OFF/STATUS)");
}

} // namespace

void CmdMemDump(u32 argc, char** argv)
{
    // memdump <hex-addr> [len] — dump arbitrary kernel memory.
    // Uses the SAFE variant: any line whose page is outside the
    // known-mapped kernel ranges emits "<unreadable>" instead of
    // faulting. Output goes to COM1 (too wide for the 80-col fb).
    if (argc < 2)
    {
        ConsoleWriteln("MEMDUMP: USAGE: MEMDUMP <HEX-ADDR> [LEN-BYTES]");
        ConsoleWriteln("         OUTPUT GOES TO COM1 (SERIAL LOG)");
        return;
    }
    u64 addr = 0;
    if (!ParseU64Str(argv[1], &addr))
    {
        ConsoleWriteln("MEMDUMP: BAD ADDRESS");
        return;
    }
    u64 len = 64;
    if (argc >= 3 && !ParseU64Str(argv[2], &len))
    {
        ConsoleWriteln("MEMDUMP: BAD LENGTH");
        return;
    }
    if (len == 0)
    {
        ConsoleWriteln("MEMDUMP: ZERO LENGTH");
        return;
    }
    duetos::core::DumpHexRegionSafe("memdump", addr, static_cast<u32>(len), 0);
    ConsoleWriteln("MEMDUMP: WROTE TO COM1");
}

void CmdInstr(u32 argc, char** argv)
{
    if (argc < 2)
    {
        ConsoleWriteln("INSTR: USAGE: INSTR <HEX-ADDR> [LEN-BYTES]");
        ConsoleWriteln("       OUTPUT GOES TO COM1 (SERIAL LOG)");
        return;
    }
    u64 addr = 0;
    if (!ParseU64Str(argv[1], &addr))
    {
        ConsoleWriteln("INSTR: BAD ADDRESS");
        return;
    }
    u64 len = 16;
    if (argc >= 3 && !ParseU64Str(argv[2], &len))
    {
        ConsoleWriteln("INSTR: BAD LENGTH");
        return;
    }
    duetos::core::DumpInstructionBytes("instr", addr, static_cast<u32>(len));
    ConsoleWriteln("INSTR: WROTE TO COM1");
}

void CmdAddr2Sym(u32 argc, char** argv)
{
    if (argc < 2)
    {
        ConsoleWriteln("ADDR2SYM: USAGE: ADDR2SYM <HEX-ADDR>");
        ConsoleWriteln("         RESOLVE A KERNEL VA TO FN+OFFSET (FILE:LINE)");
        return;
    }
    u64 addr = 0;
    if (!ParseU64Str(argv[1], &addr))
    {
        ConsoleWriteln("ADDR2SYM: BAD ADDRESS");
        return;
    }
    duetos::arch::SerialWrite("[addr2sym] ");
    duetos::core::WriteAddressWithSymbol(addr);
    duetos::arch::SerialWrite("\n");

    duetos::core::SymbolResolution res{};
    if (!duetos::core::ResolveAddress(addr, &res) || res.entry == nullptr)
    {
        ConsoleWriteln("ADDR2SYM: <UNRESOLVED>");
        return;
    }
    char line[96];
    u32 i = 0;
    auto put = [&](const char* s)
    {
        for (u32 k = 0; s[k] != '\0' && i + 1 < sizeof(line); ++k)
            line[i++] = s[k];
    };
    auto put_hex = [&](u64 v)
    {
        char buf[18];
        buf[0] = '0';
        buf[1] = 'x';
        for (u32 d = 0; d < 16; ++d)
        {
            const u32 nib = static_cast<u32>((v >> ((15 - d) * 4)) & 0xF);
            buf[2 + d] = static_cast<char>(nib < 10 ? '0' + nib : 'a' + (nib - 10));
        }
        for (u32 k = 0; k < 18 && i + 1 < sizeof(line); ++k)
            line[i++] = buf[k];
    };
    put("ADDR2SYM ");
    put_hex(addr);
    put(" -> ");
    put(res.entry->name);
    put("+");
    put_hex(res.offset);
    line[i] = '\0';
    ConsoleWriteln(line);
}

// `domain restart <name>` — kick a registered fault domain
// (driver-tagged or hand-registered) through teardown + init
// without rebooting. Admin-gated through the dispatcher; the
// caller's shell session needs admin or the command refuses.
void CmdDomainRestart(u32 argc, char** argv)
{
    if (argc < 3)
    {
        ConsoleWriteln("DOMAIN RESTART: USAGE: DOMAIN RESTART <NAME>");
        return;
    }
    const char* name = argv[2];
    auto r = duetos::security::RestartDriverDomain(name);
    if (!r.has_value())
    {
        ConsoleWrite("DOMAIN RESTART: NOT FOUND \"");
        ConsoleWrite(name);
        ConsoleWriteln("\"");
        return;
    }
    ConsoleWrite("DOMAIN RESTART: \"");
    ConsoleWrite(name);
    ConsoleWriteln("\" OK");
}

void CmdDomain(u32 argc, char** argv)
{
    if (argc >= 2 && StrEq(argv[1], "restart"))
    {
        CmdDomainRestart(argc, argv);
        return;
    }
    if (argc >= 2 && StrEq(argv[1], "list"))
    {
        CmdInspectDomains();
        return;
    }
    ConsoleWriteln("DOMAIN: USAGE: DOMAIN LIST | DOMAIN RESTART <NAME>");
}

// `lockdep panic on|off` — flip the inversion-promote-to-panic
// knob (plan D1-followup). Default off so a boot under
// instrumentation can complete with a noisy graph; flip ON once
// the operator has triaged the existing inversions and wants
// any new one to fail-stop. Idempotent. External linkage so the
// dispatcher (in shell_dispatch.cpp) can call it directly.
// (2026-04-28.)
void CmdLockdepPanic(u32 argc, char** argv)
{
    if (argc < 3)
    {
        ConsoleWriteln("LOCKDEP PANIC: USAGE: LOCKDEP PANIC ON|OFF");
        return;
    }
    if (StrEq(argv[2], "on"))
    {
        ::duetos::sync::LockdepSetPromoteToPanic(true);
        ConsoleWriteln("LOCKDEP: panic-on-invert ENABLED");
        return;
    }
    if (StrEq(argv[2], "off"))
    {
        ::duetos::sync::LockdepSetPromoteToPanic(false);
        ConsoleWriteln("LOCKDEP: panic-on-invert DISABLED");
        return;
    }
    ConsoleWriteln("LOCKDEP PANIC: ARG MUST BE ON OR OFF");
}

// `tracer dump` — print the dynamic event trace ring oldest-
// first (plan D2-followup). Walks via EventTraceSnapshot into a
// scratch heap buffer; prints one row per event. No filter
// arguments in v0; a `tracer kind <K>` knob lands when an
// investigation needs it. (2026-04-28.)
void CmdTracerDump()
{
    constexpr u32 kBatch = 64;
    duetos::diag::EventRecord buf[kBatch];
    const u32 live = duetos::diag::EventTraceLiveCount();
    const u64 total = duetos::diag::EventTraceTotalRecords();
    ConsoleWrite("EVENT TRACE: live=");
    WriteU64Dec(live);
    ConsoleWrite(" total-since-boot=");
    WriteU64Dec(total);
    ConsoleWriteChar('\n');
    if (live == 0)
    {
        ConsoleWriteln("(empty)");
        return;
    }
    duetos::diag::EventRecord all[duetos::diag::kEventRingCapacity];
    const u32 got = duetos::diag::EventTraceSnapshot(all, live);
    for (u32 i = 0; i < got; ++i)
    {
        const auto& r = all[i];
        ConsoleWrite("  tick=");
        WriteU64Dec(r.tick);
        ConsoleWrite(" kind=");
        ConsoleWrite(duetos::diag::EventKindName(r.kind));
        ConsoleWrite(" arg0=");
        WriteU64Hex(r.arg0, 16);
        ConsoleWrite(" arg1=");
        WriteU64Hex(r.arg1, 16);
        ConsoleWriteChar('\n');
    }
    (void)buf;
}

// Filter helper for `tracer kind <K>` — matches a kind name
// against the canonical set. Returns the matched kind or 0
// (kEventNone) for "no match".
u32 ParseTracerKind(const char* s)
{
    using namespace duetos::diag;
    if (StrEq(s, "syscall-enter"))
        return kEventSyscallEnter;
    if (StrEq(s, "syscall-exit"))
        return kEventSyscallExit;
    if (StrEq(s, "sched-switch"))
        return kEventSchedSwitch;
    if (StrEq(s, "irq"))
        return kEventIrq;
    if (StrEq(s, "page-fault"))
        return kEventPageFault;
    if (StrEq(s, "mutex-acquire"))
        return kEventMutexAcquire;
    if (StrEq(s, "mutex-release"))
        return kEventMutexRelease;
    if (StrEq(s, "custom"))
        return kEventCustom;
    return duetos::diag::kEventNone;
}

// `tracer kind <name>` — dump only events whose kind matches.
// (D2-followup, 2026-04-28.)
void CmdTracerKind(const char* name)
{
    const u32 want = ParseTracerKind(name);
    if (want == duetos::diag::kEventNone)
    {
        ConsoleWrite("TRACER KIND: UNKNOWN KIND ");
        ConsoleWriteln(name);
        return;
    }
    duetos::diag::EventRecord all[duetos::diag::kEventRingCapacity];
    const u32 got = duetos::diag::EventTraceSnapshot(all, duetos::diag::kEventRingCapacity);
    u32 shown = 0;
    for (u32 i = 0; i < got; ++i)
    {
        if (all[i].kind != want)
            continue;
        const auto& r = all[i];
        ConsoleWrite("  tick=");
        WriteU64Dec(r.tick);
        ConsoleWrite(" arg0=");
        WriteU64Hex(r.arg0, 16);
        ConsoleWrite(" arg1=");
        WriteU64Hex(r.arg1, 16);
        ConsoleWriteChar('\n');
        ++shown;
    }
    ConsoleWrite("TRACER KIND: matched=");
    WriteU64Dec(shown);
    ConsoleWriteChar('\n');
}

void CmdTracer(u32 argc, char** argv)
{
    if (argc >= 2 && StrEq(argv[1], "dump"))
    {
        CmdTracerDump();
        return;
    }
    if (argc >= 3 && StrEq(argv[1], "kind"))
    {
        CmdTracerKind(argv[2]);
        return;
    }
    if (argc >= 2 && StrEq(argv[1], "reset"))
    {
        duetos::diag::EventTraceReset();
        ConsoleWriteln("TRACER: RING RESET");
        return;
    }
    ConsoleWriteln("TRACER: USAGE: TRACER DUMP | TRACER KIND <NAME> | TRACER RESET");
}

// `perf dump` — walk PerfSnapshot, resolve each RIP through
// the embedded symbol table (same shape as `heap leaks`).
// (D3-followup, 2026-04-28.)
void CmdPerfDump()
{
    const u32 live = duetos::diag::PerfLiveCount();
    const u64 total = duetos::diag::PerfTotalSamples();
    ConsoleWrite("PERF: live=");
    WriteU64Dec(live);
    ConsoleWrite(" total-since-boot=");
    WriteU64Dec(total);
    ConsoleWriteChar('\n');
    if (live == 0)
    {
        ConsoleWriteln("(no samples; PMU NMI sampling not yet wired)");
        return;
    }
    duetos::diag::PerfSample buf[duetos::diag::kPerfRingCapacity];
    const u32 got = duetos::diag::PerfSnapshot(buf, duetos::diag::kPerfRingCapacity);
    for (u32 i = 0; i < got; ++i)
    {
        const auto& s = buf[i];
        ConsoleWrite("  tick=");
        WriteU64Dec(s.tick);
        ConsoleWrite(" rip=");
        WriteU64Hex(s.rip, 16);
        ConsoleWrite("  ");
        duetos::core::SymbolResolution res{};
        if (duetos::core::ResolveAddress(s.rip, &res) && res.entry != nullptr)
        {
            ConsoleWrite(res.entry->name);
            ConsoleWrite("+0x");
            WriteU64Hex(res.offset, 0);
        }
        else
        {
            ConsoleWrite("<unresolved>");
        }
        ConsoleWriteChar('\n');
    }
}

void CmdPerf(u32 argc, char** argv)
{
    if (argc >= 2 && StrEq(argv[1], "dump"))
    {
        CmdPerfDump();
        return;
    }
    ConsoleWriteln("PERF: USAGE: PERF DUMP");
}

void CmdInspect(u32 argc, char** argv)
{
    if (argc < 2)
    {
        CmdInspectHelp();
        return;
    }
    if (StrEq(argv[1], "syscalls"))
    {
        CmdInspectSyscalls(argc, argv);
        return;
    }
    if (StrEq(argv[1], "opcodes"))
    {
        CmdInspectOpcodes(argc, argv);
        return;
    }
    if (StrEq(argv[1], "arm"))
    {
        CmdInspectArm(argc, argv);
        return;
    }
    if (StrEq(argv[1], "lockdep"))
    {
        CmdInspectLockdep();
        return;
    }
    if (StrEq(argv[1], "domains"))
    {
        CmdInspectDomains();
        return;
    }
    if (StrEq(argv[1], "zones"))
    {
        CmdInspectZones();
        return;
    }
    if (StrEq(argv[1], "threads"))
    {
        CmdInspectThreads();
        return;
    }
    if (StrEq(argv[1], "tracer-stats"))
    {
        CmdInspectTracerStats();
        return;
    }
    if (StrEq(argv[1], "gdb"))
    {
        CmdInspectGdb();
        return;
    }
    if (StrEq(argv[1], "rcu"))
    {
        CmdInspectRcu();
        return;
    }
    if (StrEq(argv[1], "uptime"))
    {
        CmdInspectUptime();
        return;
    }
    if (StrEq(argv[1], "counters"))
    {
        CmdInspectCounters();
        return;
    }
    if (StrEq(argv[1], "ipc"))
    {
        CmdInspectIpc();
        return;
    }
    if (StrEq(argv[1], "security"))
    {
        CmdInspectSecurity();
        return;
    }
    if (StrEq(argv[1], "entropy"))
    {
        CmdInspectEntropy();
        return;
    }
    if (StrEq(argv[1], "help"))
    {
        CmdInspectHelp();
        return;
    }
    ConsoleWrite("INSPECT: UNKNOWN SUBCOMMAND \"");
    ConsoleWrite(argv[1]);
    ConsoleWriteln("\"");
    CmdInspectHelp();
}

void CmdTrace(u32 argc, char** argv)
{
    if (argc < 2)
    {
        const auto cur = duetos::core::GetLogThreshold();
        ConsoleWrite("TRACE THRESHOLD: ");
        ConsoleWriteln(cur == duetos::core::LogLevel::Trace ? "ON" : "OFF");
        ConsoleWriteln("(IN-FLIGHT SCOPES LOGGED TO SERIAL BELOW)");
        duetos::core::DumpInflightScopes();
        ConsoleWriteln("USAGE: TRACE [ON|OFF]");
        return;
    }
    if (argv[1][0] == 'o' && (argv[1][1] == 'n' || argv[1][1] == 'N'))
    {
        duetos::core::SetLogThreshold(duetos::core::LogLevel::Trace);
        ConsoleWriteln("TRACE ON (threshold = TRACE)");
    }
    else if (argv[1][0] == 'o' && (argv[1][1] == 'f' || argv[1][1] == 'F'))
    {
        duetos::core::SetLogThreshold(duetos::core::LogLevel::Info);
        ConsoleWriteln("TRACE OFF (threshold = INFO)");
    }
    else
    {
        ConsoleWriteln("TRACE: USE ON|OFF");
    }
}

void CmdDumpState()
{
    // Single-shot snapshot of every major kernel subsystem's
    // counters. Captures heap / paging / scheduler / runtime
    // checker into one log entry, useful for before/after
    // bisects. Output goes to COM1.
    duetos::arch::SerialWrite("\n=== DUETOS DUMPSTATE ===\n");

    {
        const auto s = duetos::mm::KernelHeapStatsRead();
        duetos::arch::SerialWrite("[heap] pool=");
        duetos::arch::SerialWriteHex(s.pool_bytes);
        duetos::arch::SerialWrite(" used=");
        duetos::arch::SerialWriteHex(s.used_bytes);
        duetos::arch::SerialWrite(" free=");
        duetos::arch::SerialWriteHex(s.free_bytes);
        duetos::arch::SerialWrite("\n[heap] alloc_count=");
        duetos::arch::SerialWriteHex(s.alloc_count);
        duetos::arch::SerialWrite(" free_count=");
        duetos::arch::SerialWriteHex(s.free_count);
        duetos::arch::SerialWrite(" largest_run=");
        duetos::arch::SerialWriteHex(s.largest_free_run);
        duetos::arch::SerialWrite(" free_chunks=");
        duetos::arch::SerialWriteHex(s.free_chunk_count);
        duetos::arch::SerialWrite("\n");
    }

    {
        const auto s = duetos::mm::PagingStatsRead();
        duetos::arch::SerialWrite("[paging] page_tables=");
        duetos::arch::SerialWriteHex(s.page_tables_allocated);
        duetos::arch::SerialWrite(" mapped=");
        duetos::arch::SerialWriteHex(s.mappings_installed);
        duetos::arch::SerialWrite(" unmapped=");
        duetos::arch::SerialWriteHex(s.mappings_removed);
        duetos::arch::SerialWrite(" mmio_used=");
        duetos::arch::SerialWriteHex(s.mmio_arena_used_bytes);
        duetos::arch::SerialWrite("\n");
    }

    {
        const auto s = duetos::sched::SchedStatsRead();
        duetos::arch::SerialWrite("[sched] ctx_switches=");
        duetos::arch::SerialWriteHex(s.context_switches);
        duetos::arch::SerialWrite(" live=");
        duetos::arch::SerialWriteHex(s.tasks_live);
        duetos::arch::SerialWrite(" sleeping=");
        duetos::arch::SerialWriteHex(s.tasks_sleeping);
        duetos::arch::SerialWrite(" blocked=");
        duetos::arch::SerialWriteHex(s.tasks_blocked);
        duetos::arch::SerialWrite("\n[sched] created=");
        duetos::arch::SerialWriteHex(s.tasks_created);
        duetos::arch::SerialWrite(" exited=");
        duetos::arch::SerialWriteHex(s.tasks_exited);
        duetos::arch::SerialWrite(" reaped=");
        duetos::arch::SerialWriteHex(s.tasks_reaped);
        duetos::arch::SerialWrite(" total_ticks=");
        duetos::arch::SerialWriteHex(s.total_ticks);
        duetos::arch::SerialWrite(" idle_ticks=");
        duetos::arch::SerialWriteHex(s.idle_ticks);
        duetos::arch::SerialWrite("\n");
    }

    {
        const auto& h = duetos::core::RuntimeCheckerStatusRead();
        duetos::arch::SerialWrite("[health] scans=");
        duetos::arch::SerialWriteHex(h.scans_run);
        duetos::arch::SerialWrite(" issues_total=");
        duetos::arch::SerialWriteHex(h.issues_found_total);
        duetos::arch::SerialWrite(" last_scan=");
        duetos::arch::SerialWriteHex(h.last_scan_issues);
        duetos::arch::SerialWrite(" baseline=");
        duetos::arch::SerialWrite(h.baseline_captured ? "yes" : "no");
        duetos::arch::SerialWrite("\n");
    }

    duetos::arch::SerialWrite("=== END DUMPSTATE ===\n");
    ConsoleWriteln("DUMPSTATE: WROTE TO COM1");
}

void CmdBp(u32 argc, char** argv)
{
    if (argc < 2)
    {
        ConsoleWriteln("BP: USAGE:");
        ConsoleWriteln("    BP LIST");
        ConsoleWriteln("    BP SET    [--SUSPEND] <HEX-ADDR>               (SOFTWARE)");
        ConsoleWriteln("    BP HW     [--SUSPEND] <HEX-ADDR> [X|W|RW] [LEN] (HARDWARE)");
        ConsoleWriteln("    BP CLEAR  <ID>                                  (REMOVE)");
        ConsoleWriteln("    BP TEST                                         (SELF-TEST)");
        ConsoleWriteln("    BP STOPPED                                      (LIST SUSPENDED)");
        ConsoleWriteln("    BP REGS   <ID>                                  (DUMP REGS)");
        ConsoleWriteln("    BP MEM    <ID> <HEX-ADDR> [LEN]                 (DUMP USER MEM)");
        ConsoleWriteln("    BP RESUME <ID>                                  (WAKE STOPPED)");
        ConsoleWriteln("    BP STEP   <ID>                                  (STEP + RE-SUSPEND)");
        return;
    }

    const char* sub = argv[1];

    if (StrEq(sub, "list"))
    {
        duetos::debug::BpInfo infos[32];
        const usize n = duetos::debug::BpList(infos, 32);
        if (n == 0)
        {
            ConsoleWriteln("BP: NONE INSTALLED");
            return;
        }
        ConsoleWriteln("BP: ID KIND   ADDR              HITS  STATE");
        for (usize i = 0; i < n; ++i)
        {
            ConsoleWrite("  ");
            WriteU64Dec(infos[i].id.value);
            ConsoleWrite("  ");
            ConsoleWrite(BpKindName(infos[i].kind));
            ConsoleWrite("  ");
            WriteU64Hex(infos[i].address, 16);
            ConsoleWrite("  ");
            WriteU64Dec(infos[i].hit_count);
            ConsoleWrite("  ");
            if (infos[i].is_stopped)
            {
                ConsoleWrite("STOPPED(task=");
                WriteU64Dec(infos[i].stopped_task_id);
                ConsoleWriteChar(')');
            }
            else if (infos[i].suspend_on_hit)
            {
                ConsoleWrite("ARMED-SUSPEND");
            }
            else
            {
                ConsoleWrite("ARMED-LOG");
            }
            ConsoleWriteChar('\n');
        }
        return;
    }

    if (StrEq(sub, "set"))
    {
        bool suspend = false;
        argc = TakeSuspendFlag(argc, argv, 2, &suspend);
        if (argc < 3)
        {
            ConsoleWriteln("BP SET: NEED <HEX-ADDR>");
            return;
        }
        u64 addr = 0;
        if (!ParseU64Str(argv[2], &addr))
        {
            ConsoleWriteln("BP SET: BAD ADDRESS");
            return;
        }
        duetos::debug::BpError err = duetos::debug::BpError::None;
        const duetos::debug::BreakpointId id = duetos::debug::BpInstallSoftware(addr, suspend, &err);
        if (err != duetos::debug::BpError::None)
        {
            ConsoleWrite("BP SET: ");
            ConsoleWriteln(BpErrName(err));
            return;
        }
        ConsoleWrite("BP SET: OK ID=");
        WriteU64Dec(id.value);
        ConsoleWriteln(suspend ? " (SUSPEND-ON-HIT)" : "");
        return;
    }

    if (StrEq(sub, "hw"))
    {
        bool suspend = false;
        argc = TakeSuspendFlag(argc, argv, 2, &suspend);
        if (argc < 3)
        {
            ConsoleWriteln("BP HW: NEED <HEX-ADDR> [X|W|RW] [LEN]");
            return;
        }
        u64 addr = 0;
        if (!ParseU64Str(argv[2], &addr))
        {
            ConsoleWriteln("BP HW: BAD ADDRESS");
            return;
        }
        duetos::debug::BpKind kind = duetos::debug::BpKind::HwExecute;
        duetos::debug::BpLen len = duetos::debug::BpLen::One;
        if (argc >= 4)
        {
            if (StrEq(argv[3], "x"))
                kind = duetos::debug::BpKind::HwExecute;
            else if (StrEq(argv[3], "w"))
                kind = duetos::debug::BpKind::HwWrite;
            else if (StrEq(argv[3], "rw"))
                kind = duetos::debug::BpKind::HwReadWrite;
            else
            {
                ConsoleWriteln("BP HW: BAD KIND (USE X|W|RW)");
                return;
            }
        }
        if (argc >= 5 && kind != duetos::debug::BpKind::HwExecute)
        {
            u64 ln = 0;
            if (!ParseU64Str(argv[4], &ln))
            {
                ConsoleWriteln("BP HW: BAD LEN");
                return;
            }
            switch (ln)
            {
            case 1:
                len = duetos::debug::BpLen::One;
                break;
            case 2:
                len = duetos::debug::BpLen::Two;
                break;
            case 4:
                len = duetos::debug::BpLen::Four;
                break;
            case 8:
                len = duetos::debug::BpLen::Eight;
                break;
            default:
                ConsoleWriteln("BP HW: LEN MUST BE 1/2/4/8");
                return;
            }
        }
        duetos::debug::BpError err = duetos::debug::BpError::None;
        const duetos::debug::BreakpointId id =
            duetos::debug::BpInstallHardware(addr, kind, len, /*owner_pid=*/0, suspend, &err);
        if (err != duetos::debug::BpError::None)
        {
            ConsoleWrite("BP HW: ");
            ConsoleWriteln(BpErrName(err));
            return;
        }
        ConsoleWrite("BP HW: OK ID=");
        WriteU64Dec(id.value);
        ConsoleWriteln(suspend ? " (SUSPEND-ON-HIT)" : "");
        return;
    }

    if (StrEq(sub, "clear") || StrEq(sub, "rm"))
    {
        if (argc < 3)
        {
            ConsoleWriteln("BP CLEAR: NEED <ID>");
            return;
        }
        u64 id_val = 0;
        if (!ParseU64Str(argv[2], &id_val))
        {
            ConsoleWriteln("BP CLEAR: BAD ID");
            return;
        }
        const duetos::debug::BpError err = duetos::debug::BpRemove({static_cast<u32>(id_val)}, /*requester_pid=*/0);
        ConsoleWrite("BP CLEAR: ");
        ConsoleWriteln(BpErrName(err));
        return;
    }

    if (StrEq(sub, "test"))
    {
        const bool ok = duetos::debug::BpSelfTest();
        ConsoleWriteln(ok ? "BP TEST: OK" : "BP TEST: FAILED (SEE SERIAL LOG)");
        return;
    }

    if (StrEq(sub, "stopped"))
    {
        duetos::debug::BpInfo infos[32];
        const usize n = duetos::debug::BpList(infos, 32);
        usize any = 0;
        for (usize i = 0; i < n; ++i)
        {
            if (!infos[i].is_stopped)
                continue;
            if (any == 0)
                ConsoleWriteln("BP STOPPED: BP-ID  TASK  ADDR");
            ConsoleWrite("  ");
            WriteU64Dec(infos[i].id.value);
            ConsoleWrite("    ");
            WriteU64Dec(infos[i].stopped_task_id);
            ConsoleWrite("    ");
            WriteU64Hex(infos[i].address, 16);
            ConsoleWriteChar('\n');
            ++any;
        }
        if (any == 0)
            ConsoleWriteln("BP STOPPED: NONE");
        return;
    }

    if (StrEq(sub, "regs"))
    {
        if (argc < 3)
        {
            ConsoleWriteln("BP REGS: NEED <ID>");
            return;
        }
        u64 id_val = 0;
        if (!ParseU64Str(argv[2], &id_val))
        {
            ConsoleWriteln("BP REGS: BAD ID");
            return;
        }
        duetos::arch::TrapFrame f;
        if (!duetos::debug::BpReadRegs({static_cast<u32>(id_val)}, &f))
        {
            ConsoleWriteln("BP REGS: NO TASK STOPPED ON THAT ID");
            return;
        }
        ConsoleWrite("BP REGS ID=");
        WriteU64Dec(id_val);
        ConsoleWriteln(":");
        PrintBpRegs(f);
        return;
    }

    if (StrEq(sub, "mem"))
    {
        if (argc < 4)
        {
            ConsoleWriteln("BP MEM: NEED <ID> <HEX-ADDR> [LEN]");
            return;
        }
        u64 id_val = 0;
        u64 addr = 0;
        if (!ParseU64Str(argv[2], &id_val) || !ParseU64Str(argv[3], &addr))
        {
            ConsoleWriteln("BP MEM: BAD ARGS");
            return;
        }
        u64 len = 64;
        if (argc >= 5)
        {
            if (!ParseU64Str(argv[4], &len))
            {
                ConsoleWriteln("BP MEM: BAD LEN");
                return;
            }
        }
        if (len > 256)
            len = 256;
        u8 buf[256];
        const u64 got = duetos::debug::BpReadMem({static_cast<u32>(id_val)}, addr, buf, len);
        if (got == 0)
        {
            ConsoleWriteln("BP MEM: UNREADABLE (UNMAPPED OR NO STOPPED TASK)");
            return;
        }
        for (u64 off = 0; off < got; off += 16)
        {
            WriteU64Hex(addr + off, 16);
            ConsoleWrite(": ");
            for (u64 i = 0; i < 16; ++i)
            {
                if (off + i < got)
                {
                    const u8 b = buf[off + i];
                    const char hi = static_cast<char>("0123456789abcdef"[(b >> 4) & 0xF]);
                    const char lo = static_cast<char>("0123456789abcdef"[b & 0xF]);
                    ConsoleWriteChar(hi);
                    ConsoleWriteChar(lo);
                }
                else
                {
                    ConsoleWrite("  ");
                }
                ConsoleWriteChar(' ');
            }
            ConsoleWriteChar(' ');
            for (u64 i = 0; i < 16 && off + i < got; ++i)
            {
                const u8 b = buf[off + i];
                ConsoleWriteChar((b >= 0x20 && b < 0x7F) ? static_cast<char>(b) : '.');
            }
            ConsoleWriteChar('\n');
        }
        return;
    }

    if (StrEq(sub, "resume"))
    {
        if (argc < 3)
        {
            ConsoleWriteln("BP RESUME: NEED <ID>");
            return;
        }
        u64 id_val = 0;
        if (!ParseU64Str(argv[2], &id_val))
        {
            ConsoleWriteln("BP RESUME: BAD ID");
            return;
        }
        const duetos::debug::BpError err = duetos::debug::BpResume({static_cast<u32>(id_val)});
        ConsoleWrite("BP RESUME: ");
        ConsoleWriteln(BpErrName(err));
        return;
    }

    if (StrEq(sub, "step"))
    {
        if (argc < 3)
        {
            ConsoleWriteln("BP STEP: NEED <ID>");
            return;
        }
        u64 id_val = 0;
        if (!ParseU64Str(argv[2], &id_val))
        {
            ConsoleWriteln("BP STEP: BAD ID");
            return;
        }
        const duetos::debug::BpError err = duetos::debug::BpStep({static_cast<u32>(id_val)});
        ConsoleWrite("BP STEP: ");
        ConsoleWriteln(BpErrName(err));
        return;
    }

    ConsoleWriteln("BP: UNKNOWN SUBCOMMAND (HELP: BP WITHOUT ARGS)");
}

void CmdProbe(u32 argc, char** argv)
{
    if (argc < 2)
    {
        ConsoleWriteln("PROBE: USAGE:");
        ConsoleWriteln("    PROBE LIST                         LIST + COUNTS + ARM STATE");
        ConsoleWriteln("    PROBE ARM <NAME> [--SUSPEND]       ARM ONE PROBE");
        ConsoleWriteln("    PROBE DISARM <NAME>                DISARM ONE PROBE");
        ConsoleWriteln("    PROBE ARM-ALL                      ARM-LOG EVERY PROBE (NOISY)");
        ConsoleWriteln("    PROBE DISARM-ALL                   DISARM EVERYTHING");
        return;
    }
    const char* sub = argv[1];
    if (StrEq(sub, "list"))
    {
        duetos::debug::ProbeInfo infos[16];
        const u64 n = duetos::debug::ProbeList(infos, 16);
        if (n == 0)
        {
            ConsoleWriteln("PROBE: NONE REGISTERED");
            return;
        }
        ConsoleWriteln("PROBE: NAME                     ARM            FIRES");
        for (u64 i = 0; i < n; ++i)
        {
            ConsoleWrite("  ");
            ConsoleWrite(infos[i].name);
            for (u64 pad = 0; pad + 0 < 24; ++pad)
            {
                const char* p = infos[i].name;
                u64 len = 0;
                while (p[len] != 0)
                    ++len;
                if (pad + len >= 24)
                    break;
                if (pad + len < 24)
                {
                    ConsoleWriteChar(' ');
                }
                if (pad + len + 1 >= 24)
                    break;
            }
            ConsoleWrite(ProbeArmName(infos[i].arm));
            ConsoleWrite("  ");
            WriteU64Dec(infos[i].fire_count);
            ConsoleWriteChar('\n');
        }
        return;
    }
    if (StrEq(sub, "arm") || StrEq(sub, "disarm"))
    {
        if (argc < 3)
        {
            ConsoleWriteln("PROBE: NEED <NAME>");
            return;
        }
        const duetos::debug::ProbeId id = duetos::debug::ProbeByName(argv[2]);
        if (id == duetos::debug::ProbeId::kCount)
        {
            ConsoleWriteln("PROBE: UNKNOWN NAME (SEE `PROBE LIST`)");
            return;
        }
        duetos::debug::ProbeArm arm = duetos::debug::ProbeArm::Disarmed;
        if (StrEq(sub, "arm"))
        {
            arm = duetos::debug::ProbeArm::ArmedLog;
            if (argc >= 4 && (StrEq(argv[3], "--suspend") || StrEq(argv[3], "-s")))
                arm = duetos::debug::ProbeArm::ArmedSuspend;
        }
        duetos::debug::ProbeSetArm(id, arm);
        ConsoleWrite("PROBE ");
        ConsoleWrite(argv[2]);
        ConsoleWrite(": ");
        ConsoleWriteln(ProbeArmName(arm));
        return;
    }
    if (StrEq(sub, "arm-all"))
    {
        for (u32 i = 0; i < static_cast<u32>(duetos::debug::ProbeId::kCount); ++i)
            duetos::debug::ProbeSetArm(static_cast<duetos::debug::ProbeId>(i), duetos::debug::ProbeArm::ArmedLog);
        ConsoleWriteln("PROBE: ALL ARMED-LOG (MAY FLOOD LOG)");
        return;
    }
    if (StrEq(sub, "disarm-all"))
    {
        for (u32 i = 0; i < static_cast<u32>(duetos::debug::ProbeId::kCount); ++i)
            duetos::debug::ProbeSetArm(static_cast<duetos::debug::ProbeId>(i), duetos::debug::ProbeArm::Disarmed);
        ConsoleWriteln("PROBE: ALL DISARMED");
        return;
    }
    ConsoleWriteln("PROBE: UNKNOWN SUBCOMMAND");
}

void CmdHealth(u32 argc, char** argv)
{
    // Run a fresh scan (so the report reflects the current
    // moment, not the last heartbeat), then print the full
    // report: each issue kind with its cumulative count plus
    // this-scan and total-since-boot summaries.
    const u64 this_scan = duetos::core::RuntimeCheckerScan();
    const auto& h = duetos::core::RuntimeCheckerStatusRead();
    (void)argc;
    (void)argv;
    ConsoleWrite("SCANS RUN:        ");
    WriteU64Dec(h.scans_run);
    ConsoleWriteChar('\n');
    ConsoleWrite("THIS SCAN:        ");
    WriteU64Dec(this_scan);
    ConsoleWriteln(this_scan == 0 ? " issues (CLEAN)" : " issues");
    ConsoleWrite("TOTAL ISSUES:     ");
    WriteU64Dec(h.issues_found_total);
    ConsoleWriteChar('\n');
    ConsoleWrite("BASELINE CAPTURED:");
    ConsoleWriteln(h.baseline_captured ? " YES" : " NO");
    if (h.issues_found_total > 0)
    {
        ConsoleWriteln("PER-ISSUE BREAKDOWN:");
        for (u32 i = 1; i < u32(duetos::core::HealthIssue::Count); ++i)
        {
            const u64 c = h.per_issue_count[i];
            if (c == 0)
                continue;
            ConsoleWrite("  ");
            WriteU64Dec(c);
            ConsoleWrite(" x ");
            ConsoleWriteln(duetos::core::HealthIssueName(duetos::core::HealthIssue(i)));
        }
    }
}

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
        default:
            ConsoleWriteln("?");
            break;
        }
        ConsoleWriteln("USAGE: LOGLEVEL [T|D|I|W|E]");
        return;
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
    default:
        ConsoleWriteln("LOGLEVEL: USE T / D / I / W / E");
        return;
    }
    duetos::core::SetLogThreshold(lvl);
    ConsoleWriteln("LOG THRESHOLD UPDATED");
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

} // namespace duetos::core::shell::internal
