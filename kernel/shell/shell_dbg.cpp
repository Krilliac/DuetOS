#include "apps/dbg_core.h"
#include "arch/x86_64/traps.h"
#include "debug/breakpoints.h"
#include "debug/disasm.h"
#include "drivers/video/console.h"
#include "shell/shell_internal.h"
#include "util/types.h"

using duetos::drivers::video::ConsoleWrite;
using duetos::drivers::video::ConsoleWriteln;

/*
 * DuetOS — `dbg` shell command.
 *
 * Subcommand reference:
 *
 *   dbg ps                                  list every live process
 *   dbg mem    <pid> <addr> [len]           hex+ASCII dump (default 64 B)
 *   dbg dis    <pid> <addr> [rows]          disassembly (default 16 rows)
 *   dbg bp     list                         enumerate every BP
 *   dbg bp     add <addr> <kind> <len> [s]  install BP (kind=hwx|hww|hwrw|sw)
 *   dbg bp     rm <id>                      remove BP
 *   dbg bp     resume <id>                  resume a parked task
 *   dbg bp     step <id>                    single-step a parked task
 *   dbg regs   <bp_id>                      print the saved trap frame
 *   dbg watch  add <pid> <addr> <type> <name>   add a watch row
 *   dbg watch  list                         enumerate the watchlist
 *   dbg watch  rm <slot>                    remove a watch row
 *   dbg scan   <pid> <hexbytes>             first-pass byte-pattern scan
 *
 * Every mutating subcommand (bp add/rm/resume/step, watch add/rm)
 * delegates to its dbg_core counterpart. The cap gate lives in the
 * core helpers' callers when ring-3 wrappers land — this command
 * runs as the kernel shell which is implicitly trusted.
 */

namespace duetos::core::shell::internal
{

namespace
{

namespace dc = duetos::apps::dbg::core;

void Usage()
{
    ConsoleWriteln("DBG: SUBCOMMANDS");
    ConsoleWriteln("  PS | THREADS | SYSINFO | SYMS [FILTER]");
    ConsoleWriteln("  MEM <PID|KERNEL> <ADDR> [LEN] | DIS <PID|KERNEL> <ADDR> [ROWS]");
    ConsoleWriteln("  BP {LIST | ADD <ADDR> <KIND> <LEN> [SUSPEND] | RM <ID> | RESUME <ID> | STEP <ID>}");
    ConsoleWriteln("  REGS <BP_ID>");
    ConsoleWriteln("  WATCH {ADD <PID|KERNEL> <ADDR> <TYPE> <NAME> | LIST | RM <SLOT>}");
    ConsoleWriteln("  SCAN <PID|KERNEL> <HEXBYTES>");
}

// `pid` arg accepts a numeric value or the literal `kernel` (case-
// insensitive `k`/`K` prefix). Returns true on success.
bool ParsePidArg(const char* s, u64* out)
{
    if (s == nullptr || out == nullptr)
        return false;
    if (StrEq(s, "kernel") || StrEq(s, "KERNEL") || StrEq(s, "k") || StrEq(s, "K"))
    {
        *out = dc::kKernelPid;
        return true;
    }
    return ParseU64Str(s, out);
}

// Parse a hex-byte literal like "deadbeef" or "de ad be ef" into
// at most `cap` bytes. Returns the number written.
usize ParseHexBytes(const char* s, u8* out, usize cap)
{
    usize n = 0;
    u8 nibble = 0;
    bool have_nibble = false;
    while (*s != 0 && n < cap)
    {
        const char c = *s++;
        if (c == ' ' || c == '_')
            continue;
        u8 d = 0;
        if (c >= '0' && c <= '9')
            d = (u8)(c - '0');
        else if (c >= 'a' && c <= 'f')
            d = (u8)(10 + c - 'a');
        else if (c >= 'A' && c <= 'F')
            d = (u8)(10 + c - 'A');
        else
            return 0;
        if (!have_nibble)
        {
            nibble = d;
            have_nibble = true;
        }
        else
        {
            out[n++] = (u8)((nibble << 4) | d);
            have_nibble = false;
        }
    }
    return n;
}

void DoPs()
{
    dc::ProcInfo rows[64];
    const usize n = dc::EnumerateProcesses(rows, 64);
    ConsoleWriteln("PID    STATE   TICKS         NAME");
    for (usize i = 0; i < n; ++i)
    {
        WriteU64Dec(rows[i].pid);
        ConsoleWrite("    ");
        ConsoleWrite(rows[i].state == 3 ? "ZOMB    " : "RUN     ");
        WriteU64Dec(rows[i].ticks_used);
        ConsoleWrite("    ");
        ConsoleWriteln(rows[i].name);
    }
}

void DoMem(u32 argc, char** argv)
{
    if (argc < 4)
    {
        ConsoleWriteln("DBG MEM: USAGE: DBG MEM <PID> <ADDR> [LEN]");
        return;
    }
    u64 pid = 0, addr = 0, len = 64;
    if (!ParsePidArg(argv[2], &pid) || !ParseU64Str(argv[3], &addr))
    {
        ConsoleWriteln("DBG MEM: BAD ARGS");
        return;
    }
    if (argc >= 5 && !ParseU64Str(argv[4], &len))
    {
        ConsoleWriteln("DBG MEM: BAD LEN");
        return;
    }
    if (len == 0 || len > 1024)
        len = 64;
    u8 buf[256];
    if (len > sizeof(buf))
        len = sizeof(buf);
    const u64 got = dc::ReadMem(pid, addr, buf, len);
    if (got == 0)
    {
        ConsoleWriteln("DBG MEM: <UNMAPPED OR DEAD PID>");
        return;
    }
    for (u64 row = 0; row < got; row += 16)
    {
        WriteU64Hex(addr + row, 16);
        ConsoleWrite("  ");
        for (u64 b = row; b < row + 16 && b < got; ++b)
        {
            WriteU64Hex(buf[b], 2);
            ConsoleWrite(" ");
        }
        ConsoleWriteln("");
    }
}

void DoDis(u32 argc, char** argv)
{
    if (argc < 4)
    {
        ConsoleWriteln("DBG DIS: USAGE: DBG DIS <PID> <ADDR> [ROWS]");
        return;
    }
    u64 pid = 0, addr = 0, rows = 16;
    if (!ParsePidArg(argv[2], &pid) || !ParseU64Str(argv[3], &addr))
    {
        ConsoleWriteln("DBG DIS: BAD ARGS");
        return;
    }
    if (argc >= 5 && !ParseU64Str(argv[4], &rows))
    {
        ConsoleWriteln("DBG DIS: BAD ROWS");
        return;
    }
    if (rows == 0 || rows > 32)
        rows = 16;
    duetos::debug::disasm::DecodedInsn out[32];
    const u64 n = dc::DisasmRows(pid, addr, out, rows);
    if (n == 0)
    {
        ConsoleWriteln("DBG DIS: <UNMAPPED OR DEAD PID>");
        return;
    }
    for (u64 i = 0; i < n; ++i)
    {
        WriteU64Hex(out[i].addr, 16);
        ConsoleWrite("  ");
        ConsoleWrite(out[i].mnemonic);
        ConsoleWrite("  ");
        ConsoleWriteln(out[i].operands);
    }
}

duetos::debug::BpKind ParseKind(const char* s)
{
    if (StrEq(s, "sw"))
        return duetos::debug::BpKind::Software;
    if (StrEq(s, "hwx"))
        return duetos::debug::BpKind::HwExecute;
    if (StrEq(s, "hww"))
        return duetos::debug::BpKind::HwWrite;
    return duetos::debug::BpKind::HwReadWrite;
}

void DoBp(u32 argc, char** argv)
{
    if (argc < 3)
    {
        ConsoleWriteln("DBG BP: SUBCOMMANDS LIST | ADD | RM | RESUME | STEP");
        return;
    }
    const char* sub = argv[2];
    if (StrEq(sub, "list"))
    {
        duetos::debug::BpInfo infos[16];
        const usize n = dc::ListBp(infos, 16);
        ConsoleWriteln("ID    KIND   ADDRESS           HITS  STATE");
        for (usize i = 0; i < n; ++i)
        {
            WriteU64Dec(infos[i].id.value);
            ConsoleWrite("    ");
            switch (infos[i].kind)
            {
            case duetos::debug::BpKind::Software:
                ConsoleWrite("SW     ");
                break;
            case duetos::debug::BpKind::HwExecute:
                ConsoleWrite("HWX    ");
                break;
            case duetos::debug::BpKind::HwWrite:
                ConsoleWrite("HWW    ");
                break;
            case duetos::debug::BpKind::HwReadWrite:
                ConsoleWrite("HWRW   ");
                break;
            }
            WriteU64Hex(infos[i].address, 16);
            ConsoleWrite("  ");
            WriteU64Dec(infos[i].hit_count);
            ConsoleWriteln(infos[i].is_stopped ? "  STOP" : "  LIVE");
        }
        return;
    }
    if (StrEq(sub, "add"))
    {
        if (argc < 6)
        {
            ConsoleWriteln("DBG BP ADD: <ADDR> <KIND=SW|HWX|HWW|HWRW> <LEN=1|2|4|8> [SUSPEND] [UNSAFE]");
            return;
        }
        u64 addr = 0, len = 1;
        if (!ParseU64Str(argv[3], &addr) || !ParseU64Str(argv[5], &len))
        {
            ConsoleWriteln("DBG BP ADD: BAD ARGS");
            return;
        }
        const auto kind = ParseKind(argv[4]);
        const auto blen = (len == 8)   ? duetos::debug::BpLen::Eight
                          : (len == 4) ? duetos::debug::BpLen::Four
                          : (len == 2) ? duetos::debug::BpLen::Two
                                       : duetos::debug::BpLen::One;
        bool suspend = false;
        bool unsafe = false;
        for (u32 i = 6; i < argc; ++i)
        {
            if (StrEq(argv[i], "suspend"))
                suspend = true;
            else if (StrEq(argv[i], "unsafe"))
                unsafe = true;
        }
        const auto flags = unsafe ? duetos::debug::BpInstallFlags::AllowUnsafe : duetos::debug::BpInstallFlags::None;
        duetos::debug::BpError err = duetos::debug::BpError::None;
        const auto id = dc::InstallBp(addr, kind, blen, /*owner_pid=*/0, suspend, &err, flags);
        if (id.value == 0)
        {
            if (err == duetos::debug::BpError::UnsafeZone)
                ConsoleWriteln("DBG BP ADD: REFUSED — addr is in an unsafe kernel zone "
                               "(klog/heap/sched/trap/panic). Append 'unsafe' to override.");
            else
                ConsoleWriteln("DBG BP ADD: FAIL");
            return;
        }
        ConsoleWrite("DBG BP ADD: ID=");
        WriteU64Dec(id.value);
        ConsoleWriteln("");
        return;
    }
    if (StrEq(sub, "zones"))
    {
        duetos::debug::BpUnsafeRange ranges[32];
        const usize n = duetos::debug::BpUnsafeRangesList(ranges, 32);
        if (n == 0)
        {
            ConsoleWriteln("DBG BP ZONES: <empty> — stage-1 build, or PopulateUnsafeRanges hasn't run yet.");
            return;
        }
        ConsoleWrite("DBG BP ZONES: COUNT=");
        WriteU64Dec(n);
        ConsoleWriteln("");
        for (usize i = 0; i < n; ++i)
        {
            WriteU64Hex(ranges[i].lo, 16);
            ConsoleWrite("..");
            WriteU64Hex(ranges[i].hi, 16);
            ConsoleWrite("  ");
            ConsoleWriteln(ranges[i].name);
        }
        return;
    }
    if (StrEq(sub, "rm"))
    {
        if (argc < 4)
            return;
        u64 id = 0;
        if (!ParseU64Str(argv[3], &id))
            return;
        const auto rv = dc::RemoveBp({(u32)id}, /*requester_pid=*/0);
        ConsoleWriteln(rv == duetos::debug::BpError::None ? "DBG BP RM: OK" : "DBG BP RM: FAIL");
        return;
    }
    if (StrEq(sub, "resume"))
    {
        if (argc < 4)
            return;
        u64 id = 0;
        if (!ParseU64Str(argv[3], &id))
            return;
        const auto rv = dc::ResumeBp({(u32)id});
        ConsoleWriteln(rv == duetos::debug::BpError::None ? "DBG BP RESUME: OK" : "DBG BP RESUME: FAIL");
        return;
    }
    if (StrEq(sub, "step"))
    {
        if (argc < 4)
            return;
        u64 id = 0;
        if (!ParseU64Str(argv[3], &id))
            return;
        const auto rv = dc::StepBp({(u32)id});
        ConsoleWriteln(rv == duetos::debug::BpError::None ? "DBG BP STEP: OK" : "DBG BP STEP: FAIL");
        return;
    }
}

void DoRegs(u32 argc, char** argv)
{
    if (argc < 3)
    {
        ConsoleWriteln("DBG REGS: USAGE: DBG REGS <BP_ID>");
        return;
    }
    u64 id = 0;
    if (!ParseU64Str(argv[2], &id))
    {
        ConsoleWriteln("DBG REGS: BAD ID");
        return;
    }
    arch::TrapFrame f{};
    if (!dc::RegsRead({(u32)id}, &f))
    {
        ConsoleWriteln("DBG REGS: NO PARKED TASK");
        return;
    }
    ConsoleWrite("RAX=");
    WriteU64Hex(f.rax, 16);
    ConsoleWrite("  RBX=");
    WriteU64Hex(f.rbx, 16);
    ConsoleWriteln("");
    ConsoleWrite("RCX=");
    WriteU64Hex(f.rcx, 16);
    ConsoleWrite("  RDX=");
    WriteU64Hex(f.rdx, 16);
    ConsoleWriteln("");
    ConsoleWrite("RSI=");
    WriteU64Hex(f.rsi, 16);
    ConsoleWrite("  RDI=");
    WriteU64Hex(f.rdi, 16);
    ConsoleWriteln("");
    ConsoleWrite("RBP=");
    WriteU64Hex(f.rbp, 16);
    ConsoleWrite("  RSP=");
    WriteU64Hex(f.rsp, 16);
    ConsoleWriteln("");
    ConsoleWrite("R8 =");
    WriteU64Hex(f.r8, 16);
    ConsoleWrite("  R9 =");
    WriteU64Hex(f.r9, 16);
    ConsoleWriteln("");
    ConsoleWrite("R10=");
    WriteU64Hex(f.r10, 16);
    ConsoleWrite("  R11=");
    WriteU64Hex(f.r11, 16);
    ConsoleWriteln("");
    ConsoleWrite("R12=");
    WriteU64Hex(f.r12, 16);
    ConsoleWrite("  R13=");
    WriteU64Hex(f.r13, 16);
    ConsoleWriteln("");
    ConsoleWrite("R14=");
    WriteU64Hex(f.r14, 16);
    ConsoleWrite("  R15=");
    WriteU64Hex(f.r15, 16);
    ConsoleWriteln("");
    ConsoleWrite("RIP=");
    WriteU64Hex(f.rip, 16);
    ConsoleWrite("  RFL=");
    WriteU64Hex(f.rflags, 16);
    ConsoleWriteln("");
}

dc::WatchType ParseWatchType(const char* s)
{
    if (StrEq(s, "u8"))
        return dc::WatchType::U8;
    if (StrEq(s, "u16"))
        return dc::WatchType::U16;
    if (StrEq(s, "u32"))
        return dc::WatchType::U32;
    if (StrEq(s, "u64"))
        return dc::WatchType::U64;
    if (StrEq(s, "i32"))
        return dc::WatchType::I32;
    if (StrEq(s, "i64"))
        return dc::WatchType::I64;
    return dc::WatchType::Bytes;
}

void DoWatch(u32 argc, char** argv)
{
    if (argc < 3)
    {
        ConsoleWriteln("DBG WATCH: SUBCOMMANDS ADD | LIST | RM");
        return;
    }
    const char* sub = argv[2];
    if (StrEq(sub, "list"))
    {
        dc::WatchRefresh();
        ConsoleWriteln("SLOT  NAME              VALUE");
        for (u32 i = 0; i < dc::kWatchMax; ++i)
        {
            const auto* e = dc::WatchSlot(i);
            if (e == nullptr || !e->used)
                continue;
            WriteU64Dec(i);
            ConsoleWrite("    ");
            ConsoleWrite(e->name);
            ConsoleWrite("    ");
            ConsoleWriteln(e->value);
        }
        return;
    }
    if (StrEq(sub, "add"))
    {
        if (argc < 7)
        {
            ConsoleWriteln("DBG WATCH ADD: <PID> <ADDR> <TYPE=u8|u16|u32|u64|i32|i64|bytes> <NAME>");
            return;
        }
        u64 pid = 0, addr = 0;
        if (!ParsePidArg(argv[3], &pid) || !ParseU64Str(argv[4], &addr))
        {
            ConsoleWriteln("DBG WATCH ADD: BAD ARGS");
            return;
        }
        const auto type = ParseWatchType(argv[5]);
        const u32 slot = dc::WatchAdd(pid, addr, /*len=*/4, type, argv[6]);
        if (slot == 0xFFFFFFFFu)
        {
            ConsoleWriteln("DBG WATCH ADD: TABLE FULL");
            return;
        }
        ConsoleWrite("DBG WATCH ADD: SLOT=");
        WriteU64Dec(slot);
        ConsoleWriteln("");
        return;
    }
    if (StrEq(sub, "rm"))
    {
        if (argc < 4)
            return;
        u64 slot = 0;
        if (!ParseU64Str(argv[3], &slot))
            return;
        ConsoleWriteln(dc::WatchRemove((u32)slot) ? "DBG WATCH RM: OK" : "DBG WATCH RM: FAIL");
        return;
    }
}

void DoSysinfo()
{
    dc::KernelOverview kov{};
    dc::GetKernelOverview(&kov);
    ConsoleWriteln("DBG SYSINFO:");

    ConsoleWrite("  HEAP   POOL=");
    WriteU64Dec(kov.heap_pool_bytes);
    ConsoleWrite("  USED=");
    WriteU64Dec(kov.heap_used_bytes);
    ConsoleWrite("  FREE=");
    WriteU64Dec(kov.heap_free_bytes);
    ConsoleWrite("  ALLOCS=");
    WriteU64Dec(kov.heap_alloc_count);
    ConsoleWrite("  FREES=");
    WriteU64Dec(kov.heap_free_count);
    ConsoleWriteln("");

    ConsoleWrite("  SCHED  CSWCH=");
    WriteU64Dec(kov.sched_context_switches);
    ConsoleWrite("  LIVE=");
    WriteU64Dec(kov.sched_tasks_live);
    ConsoleWrite("  SLEEP=");
    WriteU64Dec(kov.sched_tasks_sleeping);
    ConsoleWrite("  BLOCK=");
    WriteU64Dec(kov.sched_tasks_blocked);
    ConsoleWriteln("");

    ConsoleWrite("  TICKS  TOTAL=");
    WriteU64Dec(kov.sched_total_ticks);
    ConsoleWrite("  IDLE=");
    WriteU64Dec(kov.sched_idle_ticks);
    ConsoleWriteln("");

    ConsoleWrite("  TEXT   ");
    WriteU64Hex(kov.text_start, 16);
    ConsoleWrite("..");
    WriteU64Hex(kov.text_end, 16);
    ConsoleWrite("  SYMS=");
    WriteU64Dec(kov.symbol_count);
    ConsoleWriteln("");
}

void DoSyms(u32 argc, char** argv)
{
    const char* filter = (argc >= 3) ? argv[2] : nullptr;
    dc::SymbolRow rows[32];
    const u64 total = dc::KernelSymbolCount();
    if (total == 0)
    {
        ConsoleWriteln("DBG SYMS: <empty> — kernel built without embedded symbols");
        return;
    }
    ConsoleWrite("DBG SYMS:  TOTAL=");
    WriteU64Dec(total);
    ConsoleWriteln("");
    const u64 n = dc::EnumerateSymbols(rows, 32, 0, filter);
    if (n == 0)
    {
        ConsoleWriteln("  (no matches)");
        return;
    }
    for (u64 i = 0; i < n; ++i)
    {
        WriteU64Hex(rows[i].addr, 16);
        ConsoleWrite("  ");
        ConsoleWriteln(rows[i].name);
    }
    if (n == 32)
    {
        ConsoleWriteln("  (showing first 32; refine the filter to see more)");
    }
}

void DoThreads()
{
    dc::ThreadInfo rows[64];
    const u64 n = dc::EnumerateThreads(rows, 64);
    if (n == 0)
    {
        ConsoleWriteln("DBG THREADS: <empty>");
        return;
    }
    ConsoleWriteln("TID    STATE   PRI  TICKS         NAME");
    for (u64 i = 0; i < n; ++i)
    {
        WriteU64Dec(rows[i].tid);
        ConsoleWrite("    ");
        const char* st = "?";
        switch (rows[i].state)
        {
        case 0:
            st = "READY ";
            break;
        case 1:
            st = "RUN   ";
            break;
        case 2:
            st = "SLEEP ";
            break;
        case 3:
            st = "BLOCK ";
            break;
        case 4:
            st = "DEAD  ";
            break;
        }
        ConsoleWrite(st);
        ConsoleWrite("  ");
        WriteU64Dec(rows[i].priority);
        ConsoleWrite("    ");
        WriteU64Dec(rows[i].ticks_run);
        ConsoleWrite("    ");
        ConsoleWriteln(rows[i].name);
    }
}

void DoScan(u32 argc, char** argv)
{
    if (argc < 4)
    {
        ConsoleWriteln("DBG SCAN: USAGE: DBG SCAN <PID> <HEXBYTES>");
        return;
    }
    u64 pid = 0;
    if (!ParsePidArg(argv[2], &pid))
    {
        ConsoleWriteln("DBG SCAN: BAD PID");
        return;
    }
    u8 needle[16];
    const usize nlen = ParseHexBytes(argv[3], needle, sizeof(needle));
    if (nlen == 0)
    {
        ConsoleWriteln("DBG SCAN: BAD HEXBYTES");
        return;
    }
    u64 hits[64];
    const usize n = dc::ScanBytes(pid, needle, nlen, hits, 64);
    ConsoleWrite("DBG SCAN: HITS=");
    WriteU64Dec(n);
    ConsoleWriteln("");
    for (usize i = 0; i < n; ++i)
    {
        WriteU64Hex(hits[i], 16);
        ConsoleWriteln("");
    }
}

} // namespace

void CmdDbg(u32 argc, char** argv)
{
    if (argc < 2)
    {
        Usage();
        return;
    }
    const char* sub = argv[1];
    if (StrEq(sub, "ps"))
        DoPs();
    else if (StrEq(sub, "mem"))
        DoMem(argc, argv);
    else if (StrEq(sub, "dis"))
        DoDis(argc, argv);
    else if (StrEq(sub, "bp"))
        DoBp(argc, argv);
    else if (StrEq(sub, "regs"))
        DoRegs(argc, argv);
    else if (StrEq(sub, "watch"))
        DoWatch(argc, argv);
    else if (StrEq(sub, "scan"))
        DoScan(argc, argv);
    else if (StrEq(sub, "sysinfo"))
        DoSysinfo();
    else if (StrEq(sub, "syms"))
        DoSyms(argc, argv);
    else if (StrEq(sub, "threads"))
        DoThreads();
    else
        Usage();
}

} // namespace duetos::core::shell::internal
