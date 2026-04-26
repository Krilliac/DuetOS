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

#include "shell_internal.h"

#include "../arch/x86_64/serial.h"
#include "../arch/x86_64/traps.h"
#include "../debug/breakpoints.h"
#include "../debug/inspect.h"
#include "../debug/probes.h"
#include "../debug/syscall_scan.h"
#include "../drivers/video/console.h"
#include "../mm/kheap.h"
#include "../mm/paging.h"
#include "../sched/sched.h"
#include "hexdump.h"
#include "klog.h"
#include "runtime_checker.h"
#include "symbols.h"

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
    }
    return "?";
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
    }
    return "?";
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
    }
    return "?";
}

void CmdInspectHelp()
{
    ConsoleWriteln("INSPECT: RE / TRIAGE UMBRELLA (SEE COM1 FOR REPORTS)");
    ConsoleWriteln("  INSPECT SYSCALLS KERNEL | <PATH>  FIND SYSCALL SITES + COVERAGE");
    ConsoleWriteln("  INSPECT OPCODES <PATH>            FIRST-BYTE HISTOGRAM + CLASS TALLY");
    ConsoleWriteln("  INSPECT ARM ON|OFF|STATUS         ONE-SHOT OPCODES SCAN ON NEXT SPAWN");
    ConsoleWriteln("  INSPECT HELP                      THIS LIST");
}

void CmdInspectSyscalls(u32 argc, char** argv)
{
    if (argc < 3)
    {
        ConsoleWriteln("INSPECT SYSCALLS: USAGE: INSPECT SYSCALLS KERNEL | <PATH>");
        return;
    }
    if (StrEq(argv[2], "kernel"))
    {
        ConsoleWriteln("INSPECT SYSCALLS: SCANNING KERNEL .TEXT (SEE COM1)");
        (void)duetos::debug::SyscallScanKernelText();
        ConsoleWriteln("INSPECT SYSCALLS: DONE");
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
        const duetos::debug::BpError err =
            duetos::debug::BpRemove({static_cast<u32>(id_val)}, /*requester_pid=*/0);
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

} // namespace duetos::core::shell::internal
