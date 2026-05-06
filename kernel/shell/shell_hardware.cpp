/*
 * DuetOS — kernel shell: hardware introspection commands.
 *
 * Sibling TU of shell.cpp. Every command in this file is a
 * read-only window onto a piece of x86 / chipset / driver state.
 * No side effects beyond ConsoleWrite — the one exception is
 * CmdVbe's mode-set arm, which programs the BGA registers and
 * rebinds the kernel framebuffer.
 *
 * Commands moved here as one bucket:
 *
 *   cpuid / cr / rflags / tsc / hpet / ticks / msr   raw CPU state
 *   lapic / smp / lspci                              system topology
 *   heap / paging / fb                               kernel memory + display
 *   kbdstats / mousestats                            input drivers
 *   smbios / power / thermal / hwmon                 firmware + sensors
 *   gpu / gfx / vbe                                  GPU + ICD + mode-set
 *
 * CmdTheme stays in shell.cpp because it depends on the
 * shell-private ApplyThemeAndRepaint helper.
 */

#include "shell/shell_internal.h"
#include "shell/shell.h"

#include "arch/x86_64/cet.h"
#include "arch/x86_64/cpu.h"
#include "arch/x86_64/cpu_info.h"
#include "arch/x86_64/cpu_mitigations.h"
#include "arch/x86_64/hpet.h"
#include "arch/x86_64/lapic.h"
#include "arch/x86_64/smbios.h"
#include "arch/x86_64/smp.h"
#include "arch/x86_64/thermal.h"
#include "arch/x86_64/timer.h"
#include "time/tick.h"
#include "drivers/gpu/bochs_vbe.h"
#include "drivers/gpu/cea861.h"
#include "drivers/gpu/cvt.h"
#include "drivers/gpu/edid.h"
#include "drivers/gpu/gpu.h"
#include "drivers/gpu/virtio_gpu.h"
#include "drivers/input/ps2kbd.h"
#include "drivers/input/ps2mouse.h"
#include "drivers/pci/pci.h"
#include "drivers/power/power.h"
#include "drivers/video/console.h"
#include "drivers/video/display_info.h"
#include "drivers/video/framebuffer.h"
#include "drivers/video/render_stats.h"
#include "mm/kheap.h"
#include "mm/paging.h"
#include "sched/sched.h"
#include "subsystems/graphics/graphics.h"
#include "util/symbols.h"

namespace duetos::core::shell::internal
{

namespace
{

using duetos::drivers::video::ConsoleWrite;
using duetos::drivers::video::ConsoleWriteChar;
using duetos::drivers::video::ConsoleWriteln;

// Inline CPUID wrapper. Returns eax/ebx/ecx/edx for the given
// leaf + sub-leaf. The kernel has no <cpuid.h>, so we roll the
// inline asm here.
void CpuidRaw(u32 leaf, u32 subleaf, u32& a, u32& b, u32& c, u32& d)
{
    u32 ra = leaf, rb = 0, rc = subleaf, rd = 0;
    asm volatile("cpuid" : "+a"(ra), "+b"(rb), "+c"(rc), "+d"(rd));
    a = ra;
    b = rb;
    c = rc;
    d = rd;
}

inline u64 ReadRflags()
{
    u64 v;
    asm volatile("pushfq; pop %0" : "=r"(v));
    return v;
}

inline u64 ReadTsc()
{
    u32 lo, hi;
    asm volatile("rdtsc" : "=a"(lo), "=d"(hi));
    return (static_cast<u64>(hi) << 32) | lo;
}

inline u64 ReadMsrRaw(u32 msr)
{
    u32 lo, hi;
    asm volatile("rdmsr" : "=a"(lo), "=d"(hi) : "c"(msr));
    return (static_cast<u64>(hi) << 32) | lo;
}

// Rflags bit positions + names, parallel arrays so the
// initialisers are trivial — a struct-array local would need
// memcpy from .rodata, which the freestanding kernel doesn't
// link.
constexpr u8 kRflagsBitIdx[] = {0, 2, 4, 6, 7, 8, 9, 10, 11, 14, 16, 17, 18, 19, 20, 21};
constexpr const char* kRflagsBitNames[] = {"CF", "PF", "AF", "ZF", "SF", "TF",  "IF",  "DF",
                                           "OF", "NT", "RF", "VM", "AC", "VIF", "VIP", "ID"};

} // namespace

// `cpufeatures` — high-level summary of CPUID + mitigations
// + CET probe state, all in one shell view. Pulls together
// arch::CpuInfoGet + arch::CpuMitigationsGet + arch::CetGet.
void CmdCpuFeatures()
{
    const auto& info = duetos::arch::CpuInfoGet();
    const auto& mit = duetos::arch::CpuMitigationsGet();
    const auto& cet = duetos::arch::CetGet();

    ConsoleWrite("VENDOR:           ");
    ConsoleWriteln(info.vendor);
    ConsoleWrite("BRAND:            ");
    ConsoleWriteln(info.brand);
    ConsoleWrite("FAMILY/MODEL/STEP: ");
    WriteU64Hex(info.family, 0);
    ConsoleWriteChar('/');
    WriteU64Hex(info.model, 0);
    ConsoleWriteChar('/');
    WriteU64Hex(info.stepping, 0);
    ConsoleWriteChar('\n');

    ConsoleWrite("MITIGATIONS:      kpti=");
    ConsoleWrite(mit.needs_kpti ? "needed" : "safe");
    ConsoleWrite(" mds=");
    ConsoleWrite(mit.needs_mds_buf ? "needed" : "safe");
    ConsoleWrite(" ssbd=");
    ConsoleWrite(mit.needs_ssbd ? "needed" : "safe");
    ConsoleWrite(" taa=");
    ConsoleWrite(mit.needs_taa_flush ? "needed" : "safe");
    ConsoleWriteChar('\n');

    ConsoleWrite("CET:              ss=");
    ConsoleWrite(cet.ss_supported ? "supported" : "absent");
    ConsoleWrite(" ibt=");
    ConsoleWrite(cet.ibt_supported ? "supported" : "absent");
    ConsoleWrite(" enabled=");
    ConsoleWrite((cet.ss_enabled || cet.ibt_enabled) ? "yes" : "no");
    ConsoleWriteChar('\n');
}

void CmdCpuid(u32 argc, char** argv)
{
    // Default: print vendor string + feature summary. With a
    // leaf arg, dump the raw eax/ebx/ecx/edx.
    u32 a = 0, b = 0, c = 0, d = 0;
    if (argc >= 2)
    {
        u32 leaf = 0;
        for (u32 i = 0; argv[1][i] != '\0'; ++i)
        {
            const char ch = argv[1][i];
            if (ch == 'x' || ch == 'X')
            {
                leaf = 0;
                continue;
            }
            if (ch >= '0' && ch <= '9')
                leaf = leaf * 16 + (ch - '0');
            else if (ch >= 'a' && ch <= 'f')
                leaf = leaf * 16 + (ch - 'a' + 10);
            else if (ch >= 'A' && ch <= 'F')
                leaf = leaf * 16 + (ch - 'A' + 10);
        }
        CpuidRaw(leaf, 0, a, b, c, d);
        ConsoleWrite("LEAF=");
        WriteU64Hex(leaf, 8);
        ConsoleWrite("  EAX=");
        WriteU64Hex(a, 8);
        ConsoleWrite(" EBX=");
        WriteU64Hex(b, 8);
        ConsoleWrite(" ECX=");
        WriteU64Hex(c, 8);
        ConsoleWrite(" EDX=");
        WriteU64Hex(d, 8);
        ConsoleWriteChar('\n');
        return;
    }
    // Leaf 0 — vendor string in EBX, EDX, ECX (in that order).
    CpuidRaw(0, 0, a, b, c, d);
    const u32 max_leaf = a;
    char vendor[13];
    vendor[0] = static_cast<char>(b & 0xFF);
    vendor[1] = static_cast<char>((b >> 8) & 0xFF);
    vendor[2] = static_cast<char>((b >> 16) & 0xFF);
    vendor[3] = static_cast<char>((b >> 24) & 0xFF);
    vendor[4] = static_cast<char>(d & 0xFF);
    vendor[5] = static_cast<char>((d >> 8) & 0xFF);
    vendor[6] = static_cast<char>((d >> 16) & 0xFF);
    vendor[7] = static_cast<char>((d >> 24) & 0xFF);
    vendor[8] = static_cast<char>(c & 0xFF);
    vendor[9] = static_cast<char>((c >> 8) & 0xFF);
    vendor[10] = static_cast<char>((c >> 16) & 0xFF);
    vendor[11] = static_cast<char>((c >> 24) & 0xFF);
    vendor[12] = '\0';
    ConsoleWrite("VENDOR:    ");
    ConsoleWriteln(vendor);
    ConsoleWrite("MAX LEAF:  ");
    WriteU64Hex(max_leaf, 8);
    ConsoleWriteChar('\n');

    // Leaf 1 — family/model + feature flags.
    CpuidRaw(1, 0, a, b, c, d);
    const u32 stepping = a & 0xF;
    const u32 model = (a >> 4) & 0xF;
    const u32 family = (a >> 8) & 0xF;
    const u32 ext_model = (a >> 16) & 0xF;
    const u32 ext_family = (a >> 20) & 0xFF;
    ConsoleWrite("FAMILY:    ");
    WriteU64Dec(family + (family == 0xF ? ext_family : 0));
    ConsoleWrite("   MODEL: ");
    WriteU64Dec(model | (ext_model << 4));
    ConsoleWrite("   STEP: ");
    WriteU64Dec(stepping);
    ConsoleWriteChar('\n');
    ConsoleWrite("FEAT ECX:  ");
    WriteU64Hex(c, 8);
    ConsoleWrite("   EDX: ");
    WriteU64Hex(d, 8);
    ConsoleWriteChar('\n');

    // Leaf 0x80000000 — max extended leaf + brand string.
    CpuidRaw(0x80000000u, 0, a, b, c, d);
    if (a >= 0x80000004u)
    {
        char brand[49];
        u32 off = 0;
        for (u32 leaf = 0x80000002u; leaf <= 0x80000004u; ++leaf)
        {
            CpuidRaw(leaf, 0, a, b, c, d);
            const u32 r[4] = {a, b, c, d};
            for (u32 k = 0; k < 4; ++k)
            {
                for (u32 m = 0; m < 4 && off + 1 < sizeof(brand); ++m)
                {
                    brand[off++] = static_cast<char>((r[k] >> (m * 8)) & 0xFF);
                }
            }
        }
        brand[off] = '\0';
        // Trim leading spaces (Intel pads the brand string).
        const char* p = brand;
        while (*p == ' ')
            ++p;
        ConsoleWrite("BRAND:     ");
        ConsoleWriteln(p);
    }
}

void CmdCr()
{
    ConsoleWrite("CR0:  ");
    WriteU64Hex(duetos::arch::ReadCr0());
    ConsoleWriteChar('\n');
    ConsoleWrite("CR2:  ");
    WriteU64Hex(duetos::arch::ReadCr2());
    ConsoleWriteChar('\n');
    ConsoleWrite("CR3:  ");
    WriteU64Hex(duetos::arch::ReadCr3());
    ConsoleWriteChar('\n');
    ConsoleWrite("CR4:  ");
    WriteU64Hex(duetos::arch::ReadCr4());
    ConsoleWriteChar('\n');
}

void CmdRflags()
{
    const u64 f = ReadRflags();
    ConsoleWrite("RFLAGS: ");
    WriteU64Hex(f);
    ConsoleWriteChar('\n');
    ConsoleWrite("BITS:  ");
    bool any = false;
    for (u32 i = 0; i < sizeof(kRflagsBitIdx); ++i)
    {
        if ((f >> kRflagsBitIdx[i]) & 1)
        {
            if (any)
                ConsoleWriteChar(' ');
            ConsoleWrite(kRflagsBitNames[i]);
            any = true;
        }
    }
    if (!any)
    {
        ConsoleWrite("(none set)");
    }
    ConsoleWriteChar('\n');
}

void CmdTsc()
{
    ConsoleWrite("TSC:   ");
    WriteU64Hex(ReadTsc());
    ConsoleWriteChar('\n');
}

void CmdHpet()
{
    const u64 v = duetos::arch::HpetReadCounter();
    const u32 p = duetos::arch::HpetPeriodFemtoseconds();
    ConsoleWrite("HPET COUNTER: ");
    WriteU64Hex(v);
    ConsoleWriteChar('\n');
    ConsoleWrite("HPET PERIOD:  ");
    WriteU64Dec(p);
    ConsoleWriteln(" fs/tick");
    if (p > 0)
    {
        // Counter * period (fs) / 1e12 = seconds elapsed.
        const u64 secs = (v / 1'000'000ull) * p / 1'000'000ull;
        ConsoleWrite("APPROX SECS:  ");
        WriteU64Dec(secs);
        ConsoleWriteChar('\n');
    }
}

void CmdTicks()
{
    ConsoleWrite("TIMER TICKS: ");
    WriteU64Dec(::duetos::time::TickCount());
    ConsoleWriteChar('\n');
    ConsoleWrite("SCHED TICKS: ");
    WriteU64Dec(duetos::sched::SchedNowTicks());
    ConsoleWriteChar('\n');
}

void CmdMsr(u32 argc, char** argv)
{
    if (argc < 2)
    {
        ConsoleWriteln("MSR: USAGE: MSR <HEX-INDEX>");
        ConsoleWriteln("   EXAMPLES: MSR C0000080 (EFER)  MSR 1B (APIC BASE)");
        ConsoleWriteln("   ALLOWED: 10 1B C0000080 C0000081 C0000082 C0000084");
        ConsoleWriteln("            C0000100 C0000101 C0000102");
        return;
    }
    u32 idx = 0;
    for (u32 i = 0; argv[1][i] != '\0'; ++i)
    {
        const char ch = argv[1][i];
        if (ch == 'x' || ch == 'X')
            continue;
        if (ch >= '0' && ch <= '9')
            idx = idx * 16 + (ch - '0');
        else if (ch >= 'a' && ch <= 'f')
            idx = idx * 16 + (ch - 'a' + 10);
        else if (ch >= 'A' && ch <= 'F')
            idx = idx * 16 + (ch - 'A' + 10);
        else
        {
            ConsoleWriteln("MSR: BAD HEX");
            return;
        }
    }
    // rdmsr on a reserved / model-specific index raises #GP. Gate
    // reads to the architectural indices the kernel already uses
    // plus a small whitelist; anything outside returns "not allowed"
    // and leaves the CPU alone (a #GP would panic the box).
    static constexpr u32 kMsrWhitelist[] = {
        0x00000010u, 0x0000001Bu, 0xC0000080u, 0xC0000081u, 0xC0000082u,
        0xC0000083u, 0xC0000084u, 0xC0000100u, 0xC0000101u, 0xC0000102u,
    };
    bool allowed = false;
    for (u32 i = 0; i < sizeof(kMsrWhitelist) / sizeof(kMsrWhitelist[0]); ++i)
    {
        if (kMsrWhitelist[i] == idx)
        {
            allowed = true;
            break;
        }
    }
    if (!allowed)
    {
        ConsoleWrite("MSR ");
        WriteU64Hex(idx, 8);
        ConsoleWriteln(":  NOT ALLOWED (reserved index would #GP the kernel)");
        return;
    }
    ConsoleWrite("MSR ");
    WriteU64Hex(idx, 8);
    ConsoleWrite(":  ");
    WriteU64Hex(ReadMsrRaw(idx));
    ConsoleWriteChar('\n');
}

void CmdLapic()
{
    using namespace duetos::arch;
    const u32 id = LapicRead(kLapicRegId);
    const u32 ver = LapicRead(kLapicRegVersion);
    const u32 svr = LapicRead(kLapicRegSvr);
    const u32 lvt = LapicRead(kLapicRegLvtTimer);
    const u32 init = LapicRead(kLapicRegTimerInit);
    const u32 cur = LapicRead(kLapicRegTimerCount);
    ConsoleWrite("LAPIC ID:      ");
    WriteU64Hex(id, 8);
    ConsoleWrite("   (CPU# ");
    WriteU64Dec(id >> 24);
    ConsoleWriteln(")");
    ConsoleWrite("LAPIC VERSION: ");
    WriteU64Hex(ver, 8);
    ConsoleWriteChar('\n');
    ConsoleWrite("SVR:           ");
    WriteU64Hex(svr, 8);
    ConsoleWriteChar('\n');
    ConsoleWrite("LVT TIMER:     ");
    WriteU64Hex(lvt, 8);
    ConsoleWriteChar('\n');
    ConsoleWrite("TIMER INIT:    ");
    WriteU64Hex(init, 8);
    ConsoleWrite("   CUR: ");
    WriteU64Hex(cur, 8);
    ConsoleWriteChar('\n');
}

void CmdSmp()
{
    const u64 n = duetos::arch::SmpCpusOnline();
    ConsoleWrite("CPUS ONLINE:   ");
    WriteU64Dec(n);
    ConsoleWriteChar('\n');
    if (n == 1)
    {
        ConsoleWriteln("(BSP only; AP bring-up deferred — see decision log #021)");
    }
}

void CmdLspci()
{
    const u64 n = duetos::drivers::pci::PciDeviceCount();
    ConsoleWrite("PCI DEVICES:   ");
    WriteU64Dec(n);
    ConsoleWriteChar('\n');
    for (u64 i = 0; i < n; ++i)
    {
        const auto& d = duetos::drivers::pci::PciDevice(i);
        ConsoleWrite("  ");
        WriteU64Hex(d.addr.bus, 2);
        ConsoleWriteChar(':');
        WriteU64Hex(d.addr.device, 2);
        ConsoleWriteChar('.');
        WriteU64Hex(d.addr.function, 1);
        ConsoleWrite("  ");
        WriteU64Hex(d.vendor_id, 4);
        ConsoleWriteChar(':');
        WriteU64Hex(d.device_id, 4);
        ConsoleWrite("  class=");
        WriteU64Hex(d.class_code, 2);
        ConsoleWriteChar('.');
        WriteU64Hex(d.subclass, 2);
        ConsoleWriteChar(' ');
        ConsoleWriteln(duetos::drivers::pci::PciClassName(d.class_code));
    }
}

namespace
{

constexpr u32 kHeapLeakRows = 16;

// Print one row of `bytes count rip=fn+offset` exactly the same
// way the snapshot and watch paths do — extracted into a helper
// so the two callers can't drift in formatting. Callers stamp
// any prefix (delta sign, leading whitespace) before invoking.
void PrintHeapLeakRow(const duetos::mm::HeapLeakEntry& r)
{
    WriteU64Dec(r.bytes);
    ConsoleWrite(" B  ");
    WriteU64Dec(r.count);
    ConsoleWrite(" allocs  rip=");
    WriteU64Hex(r.caller_rip, 16);
    ConsoleWrite("  ");
    duetos::core::SymbolResolution res{};
    if (duetos::core::ResolveAddress(r.caller_rip, &res) && res.entry != nullptr)
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

// Find the row in `prev[0..prev_n)` whose RIP matches `rip`,
// returning its index, or `prev_n` for "not present in the
// previous snapshot". Linear scan; the snapshot is fixed-size
// O(16) so a hash table would be heavier than the comparison.
u32 FindRipInSnapshot(u64 rip, const duetos::mm::HeapLeakEntry* prev, u32 prev_n)
{
    for (u32 i = 0; i < prev_n; ++i)
    {
        if (prev[i].caller_rip == rip)
        {
            return i;
        }
    }
    return prev_n;
}

} // namespace

// Heap leak ranking — top-N caller RIPs by bytes outstanding. Walks
// the heap in chunk-size steps and aggregates live chunks by their
// recorded `caller_rip`. Resolves each top RIP through the embedded
// symbol table (util/symbols.cpp) so the operator sees fn+offset
// instead of raw addresses. Cost: one heap walk + one symbol lookup
// per row; cheap enough to leave callable on demand.
void CmdHeapLeaks()
{
    duetos::mm::HeapLeakEntry rows[kHeapLeakRows];
    const u32 n = duetos::mm::KernelHeapTopAllocators(rows, kHeapLeakRows);
    if (n == 0)
    {
        ConsoleWriteln("HEAP LEAKS: NO LIVE ALLOCATIONS");
        return;
    }
    ConsoleWrite("HEAP LEAKS: TOP ");
    WriteU64Dec(n);
    ConsoleWriteln(" CALLER RIPS BY BYTES OUTSTANDING");
    for (u32 i = 0; i < n; ++i)
    {
        ConsoleWrite("  ");
        PrintHeapLeakRow(rows[i]);
    }
}

// `heap leaks watch <secs>` — snapshot, sleep, snapshot, show
// delta. Useful for spotting leak growth: an allocator whose
// bytes-outstanding rises between samples is the leak suspect.
// Two-snapshot model keeps the implementation single-threaded and
// fits the shell's blocking command shape; spinning forever would
// require a background ticker we don't have. The user can re-run
// the command to keep watching. Ctrl+C aborts the inter-snapshot
// sleep cleanly. (D6-followup, 2026-04-27.)
void CmdHeapLeaksWatch(u32 secs)
{
    if (secs == 0)
    {
        ConsoleWriteln("HEAP LEAKS WATCH: BAD INTERVAL (NEED >0 SECONDS)");
        return;
    }

    duetos::mm::HeapLeakEntry before[kHeapLeakRows];
    duetos::mm::HeapLeakEntry after[kHeapLeakRows];
    const u32 n_before = duetos::mm::KernelHeapTopAllocators(before, kHeapLeakRows);

    ConsoleWrite("HEAP LEAKS WATCH: SNAPSHOT 1 / 2 (");
    WriteU64Dec(n_before);
    ConsoleWriteln(" RIPS); SLEEPING.");
    // 100 Hz scheduler tick (matches CmdSleep's loop). Poll the
    // interrupt flag in 1-second slices so a long watch can be
    // cancelled cleanly.
    for (u32 s = 0; s < secs; ++s)
    {
        if (ShellInterruptRequested())
        {
            ConsoleWriteln("^C");
            return;
        }
        duetos::sched::SchedSleepTicks(100);
    }

    const u32 n_after = duetos::mm::KernelHeapTopAllocators(after, kHeapLeakRows);
    if (n_after == 0)
    {
        ConsoleWriteln("HEAP LEAKS WATCH: NO LIVE ALLOCATIONS IN SNAPSHOT 2");
        return;
    }
    ConsoleWrite("HEAP LEAKS WATCH: DELTA OVER ");
    WriteU64Dec(secs);
    ConsoleWriteln(" SEC (snapshot 2 - snapshot 1)");
    for (u32 i = 0; i < n_after; ++i)
    {
        const auto& r = after[i];
        const u32 prev_idx = FindRipInSnapshot(r.caller_rip, before, n_before);
        // Compose a "delta entry" that re-uses the same row
        // formatter — bytes + count carry the diff, RIP carries
        // the identity. A new RIP (not in snapshot 1) shows full
        // current values prefixed with `+`; a stable or shrinking
        // RIP shows the signed delta.
        if (prev_idx == n_before)
        {
            ConsoleWrite("  +NEW   ");
            PrintHeapLeakRow(r);
            continue;
        }
        const auto& p = before[prev_idx];
        if (r.bytes == p.bytes && r.count == p.count)
        {
            // Stable allocator — print the absolute number with a
            // `=` marker so a quick scan can rule it out.
            ConsoleWrite("  =STBL  ");
            PrintHeapLeakRow(r);
            continue;
        }
        const bool grew = (r.bytes > p.bytes);
        const u64 delta_bytes = grew ? (r.bytes - p.bytes) : (p.bytes - r.bytes);
        const u64 delta_count = (r.count >= p.count) ? (r.count - p.count) : (p.count - r.count);
        ConsoleWrite(grew ? "  +GREW  " : "  -SHRK  ");
        duetos::mm::HeapLeakEntry diff{delta_bytes, delta_count, r.caller_rip};
        PrintHeapLeakRow(diff);
    }
}

void CmdHeap(u32 argc, char** argv)
{
    if (argc >= 2 && StrEq(argv[1], "leaks"))
    {
        if (argc >= 4 && StrEq(argv[2], "watch"))
        {
            // `heap leaks watch <secs>` — parse the seconds arg
            // and call the delta path. Re-using the digit-parse
            // shape from CmdSleep keeps the shell's "small int"
            // surface uniform; reach for a real argv parser only
            // when more than one shell command needs it.
            u32 secs = 0;
            for (u32 i = 0; argv[3][i] != '\0'; ++i)
            {
                if (argv[3][i] < '0' || argv[3][i] > '9')
                {
                    ConsoleWriteln("HEAP LEAKS WATCH: BAD NUMBER");
                    return;
                }
                secs = secs * 10 + static_cast<u32>(argv[3][i] - '0');
            }
            CmdHeapLeaksWatch(secs);
            return;
        }
        CmdHeapLeaks();
        return;
    }

    const auto s = duetos::mm::KernelHeapStatsRead();
    ConsoleWrite("POOL BYTES:       ");
    WriteU64Dec(s.pool_bytes);
    ConsoleWriteChar('\n');
    ConsoleWrite("USED BYTES:       ");
    WriteU64Dec(s.used_bytes);
    ConsoleWriteChar('\n');
    ConsoleWrite("FREE BYTES:       ");
    WriteU64Dec(s.free_bytes);
    ConsoleWriteChar('\n');
    ConsoleWrite("ALLOCATIONS:      ");
    WriteU64Dec(s.alloc_count);
    ConsoleWriteChar('\n');
    ConsoleWrite("FREES:            ");
    WriteU64Dec(s.free_count);
    ConsoleWriteChar('\n');
    ConsoleWrite("LARGEST FREE RUN: ");
    WriteU64Dec(s.largest_free_run);
    ConsoleWriteChar('\n');
    ConsoleWrite("FREE CHUNKS:      ");
    WriteU64Dec(s.free_chunk_count);
    ConsoleWriteChar('\n');
}

void CmdPaging()
{
    const auto s = duetos::mm::PagingStatsRead();
    ConsoleWrite("PAGE TABLES:       ");
    WriteU64Dec(s.page_tables_allocated);
    ConsoleWriteChar('\n');
    ConsoleWrite("MAPPINGS INSTALL:  ");
    WriteU64Dec(s.mappings_installed);
    ConsoleWriteChar('\n');
    ConsoleWrite("MAPPINGS REMOVE:   ");
    WriteU64Dec(s.mappings_removed);
    ConsoleWriteChar('\n');
    ConsoleWrite("MMIO ARENA USED:   ");
    WriteU64Dec(s.mmio_arena_used_bytes);
    ConsoleWriteln(" bytes");
}

void CmdFb()
{
    if (!duetos::drivers::video::FramebufferAvailable())
    {
        ConsoleWriteln("FB: NOT AVAILABLE");
        return;
    }
    const auto info = duetos::drivers::video::FramebufferGet();
    ConsoleWrite("FB PHYS:   ");
    WriteU64Hex(info.phys);
    ConsoleWriteChar('\n');
    ConsoleWrite("FB VIRT:   ");
    WriteU64Hex(reinterpret_cast<u64>(info.virt));
    ConsoleWriteChar('\n');
    ConsoleWrite("FB SIZE:   ");
    WriteU64Dec(info.width);
    ConsoleWrite(" x ");
    WriteU64Dec(info.height);
    ConsoleWrite(" @ ");
    WriteU64Dec(info.bpp);
    ConsoleWrite(" bpp  (pitch ");
    WriteU64Dec(info.pitch);
    ConsoleWriteln(")");
}

void CmdKbdStats()
{
    const auto s = duetos::drivers::input::Ps2KeyboardStats();
    ConsoleWrite("KBD IRQS:      ");
    WriteU64Dec(s.irqs_seen);
    ConsoleWriteChar('\n');
    ConsoleWrite("KBD BUFFERED:  ");
    WriteU64Dec(s.bytes_buffered);
    ConsoleWriteChar('\n');
    ConsoleWrite("KBD DROPPED:   ");
    WriteU64Dec(s.bytes_dropped);
    ConsoleWriteChar('\n');
}

void CmdMouseStats()
{
    const auto s = duetos::drivers::input::Ps2MouseStatsRead();
    ConsoleWrite("MOUSE IRQS:     ");
    WriteU64Dec(s.irqs_seen);
    ConsoleWriteChar('\n');
    ConsoleWrite("MOUSE PACKETS:  ");
    WriteU64Dec(s.packets_decoded);
    ConsoleWriteChar('\n');
    ConsoleWrite("MOUSE DROPPED:  ");
    WriteU64Dec(s.bytes_dropped);
    ConsoleWriteChar('\n');
}

void CmdSmbios()
{
    const auto& s = duetos::arch::SmbiosGet();
    if (!s.present)
    {
        ConsoleWriteln("SMBIOS: (no entry point found)");
        return;
    }
    ConsoleWrite("BIOS:         ");
    ConsoleWrite(s.bios_vendor);
    ConsoleWrite(" ");
    ConsoleWriteln(s.bios_version);
    ConsoleWrite("SYSTEM:       ");
    ConsoleWrite(s.system_manufacturer);
    ConsoleWrite(" ");
    ConsoleWrite(s.system_product);
    ConsoleWrite(" v=");
    ConsoleWriteln(s.system_version);
    ConsoleWrite("CHASSIS:      ");
    ConsoleWrite(duetos::arch::ChassisTypeName(s.chassis_type));
    ConsoleWriteln(duetos::arch::SmbiosIsLaptopChassis() ? " (laptop-like)" : "");
    ConsoleWrite("CPU:          ");
    ConsoleWrite(s.cpu_manufacturer);
    ConsoleWrite(" ");
    ConsoleWriteln(s.cpu_version);
}

void CmdPower()
{
    const auto snap = duetos::drivers::power::PowerSnapshotRead();
    ConsoleWrite("CHASSIS:      ");
    ConsoleWriteln(snap.chassis_is_laptop ? "laptop-like" : "desktop/server");
    ConsoleWrite("AC:           ");
    ConsoleWriteln(duetos::drivers::power::AcStateName(snap.ac));
    ConsoleWrite("BATTERY:      ");
    ConsoleWriteln(duetos::drivers::power::BatteryStateName(snap.battery.state));
    ConsoleWrite("CPU TEMP:     ");
    if (snap.cpu_temp_c != 0)
    {
        WriteU64Dec(snap.cpu_temp_c);
        ConsoleWriteln("C");
    }
    else
    {
        ConsoleWriteln("(not available)");
    }
    ConsoleWrite("PACKAGE TEMP: ");
    if (snap.package_temp_c != 0)
    {
        WriteU64Dec(snap.package_temp_c);
        ConsoleWriteln("C");
    }
    else
    {
        ConsoleWriteln("(not available)");
    }
    ConsoleWrite("TJ MAX:       ");
    WriteU64Dec(snap.tj_max_c);
    ConsoleWriteln("C");
    ConsoleWrite("THROTTLE HIT: ");
    ConsoleWriteln(snap.thermal_throttle_hit ? "YES" : "NO");
    if (snap.backend_is_stub)
    {
        ConsoleWriteln("(backend is a stub — AC/battery need AML interpreter; thermal is real)");
    }
}

void CmdThermal()
{
    const auto r = duetos::arch::ThermalRead();
    if (!r.valid)
    {
        ConsoleWriteln("THERMAL: sensors report invalid (likely emulator)");
        return;
    }
    ConsoleWrite("CORE TEMP:    ");
    WriteU64Dec(r.core_temp_c);
    ConsoleWriteln("C");
    ConsoleWrite("PACKAGE TEMP: ");
    WriteU64Dec(r.package_temp_c);
    ConsoleWriteln("C");
    ConsoleWrite("TJ MAX:       ");
    WriteU64Dec(r.tj_max_c);
    ConsoleWriteln("C");
    ConsoleWrite("THROTTLE:     ");
    ConsoleWriteln(r.thermal_throttle_hit ? "HIT" : "clear");
}

// One-shot hardware-monitor view — aggregates every sensor /
// inventory source we have (SMBIOS, MSR thermal, AC / battery
// stub, ACPI state) so a user can grep one command for the
// whole picture. Mirrors `sensors + dmidecode + upower` on
// Linux at a very rough level.
void CmdHwmon()
{
    const auto snap = duetos::drivers::power::PowerSnapshotRead();
    const auto& smbios = duetos::arch::SmbiosGet();

    ConsoleWriteln("=== HWMON ===");
    ConsoleWrite("CHASSIS:      ");
    ConsoleWriteln(snap.chassis_is_laptop ? "laptop" : "desktop/unknown");
    if (smbios.present)
    {
        ConsoleWrite("SYSTEM:       ");
        ConsoleWrite(smbios.system_manufacturer);
        ConsoleWrite(" / ");
        ConsoleWriteln(smbios.system_product);
        ConsoleWrite("BIOS:         ");
        ConsoleWrite(smbios.bios_vendor);
        ConsoleWrite(" / ");
        ConsoleWriteln(smbios.bios_version);
        ConsoleWrite("CPU BRAND:    ");
        ConsoleWriteln(smbios.cpu_version);
    }
    else
    {
        ConsoleWriteln("SMBIOS:       (not present — boot firmware didn't expose it)");
    }

    ConsoleWriteln("-- thermal --");
    if (snap.cpu_temp_c != 0 || snap.package_temp_c != 0 || snap.tj_max_c != 0)
    {
        ConsoleWrite("CORE TEMP:    ");
        WriteU64Dec(snap.cpu_temp_c);
        ConsoleWrite("C  PKG: ");
        WriteU64Dec(snap.package_temp_c);
        ConsoleWrite("C  TJ_MAX: ");
        WriteU64Dec(snap.tj_max_c);
        ConsoleWriteln("C");
        ConsoleWrite("THROTTLE:     ");
        ConsoleWriteln(snap.thermal_throttle_hit ? "HIT" : "clear");
    }
    else
    {
        ConsoleWriteln("CORE TEMP:    (MSR thermal sensors unavailable — QEMU TCG / old CPU)");
    }

    ConsoleWriteln("-- power --");
    ConsoleWrite("AC STATE:     ");
    ConsoleWriteln(duetos::drivers::power::AcStateName(snap.ac));
    const auto& b = snap.battery;
    if (b.state == duetos::drivers::power::kBatNotPresent)
    {
        ConsoleWriteln("BATTERY:      (not present)");
    }
    else
    {
        ConsoleWrite("BATTERY:      ");
        ConsoleWrite(duetos::drivers::power::BatteryStateName(b.state));
        ConsoleWrite("  ");
        if (b.percent <= 100)
        {
            WriteU64Dec(b.percent);
            ConsoleWrite("%");
        }
        else
        {
            ConsoleWrite("?%");
        }
        if (b.rate_mw != 0)
        {
            ConsoleWrite("  rate=");
            if (b.rate_mw < 0)
            {
                ConsoleWriteChar('-');
                WriteU64Dec(static_cast<u64>(-b.rate_mw));
            }
            else
            {
                WriteU64Dec(static_cast<u64>(b.rate_mw));
            }
            ConsoleWrite("mW");
        }
        ConsoleWriteln("");
    }

    ConsoleWriteln("-- fans --");
    // Fan-speed readback requires either ACPI _FAN evaluation (we
    // have the AML parser but no _FAN caller) or a SuperIO / EC
    // driver for the host's hardware-monitor chip (Winbond /
    // Nuvoton / ITE). Neither is wired today. State the gap
    // explicitly so a boot log confirms the command ran and just
    // has no sensor to read.
    ConsoleWriteln("FAN RPM:      (n/a — ACPI _FAN + SuperIO not implemented)");

    if (snap.backend_is_stub)
    {
        ConsoleWriteln("");
        ConsoleWriteln("NOTE: AC + battery are stubbed until the AML control method");
        ConsoleWriteln("      evaluator lands; thermals come from MSR direct read.");
    }
}

void CmdGpu()
{
    const u64 n = duetos::drivers::gpu::GpuCount();
    if (n == 0)
    {
        ConsoleWriteln("GPU: (none discovered)");
        return;
    }
    bool saw_virtio = false;
    for (u64 i = 0; i < n; ++i)
    {
        const auto& g = duetos::drivers::gpu::Gpu(i);
        ConsoleWrite("GPU ");
        WriteU64Dec(i);
        ConsoleWrite(": vid=");
        WriteU64Hex(g.vendor_id, 4);
        ConsoleWrite(" did=");
        WriteU64Hex(g.device_id, 4);
        ConsoleWrite("  vendor=");
        ConsoleWrite(g.vendor);
        ConsoleWrite(" tier=");
        ConsoleWrite(g.tier);
        if (g.family != nullptr)
        {
            ConsoleWrite(" family=");
            ConsoleWrite(g.family);
        }
        ConsoleWriteChar('\n');
        if (g.mmio_size != 0)
        {
            ConsoleWrite("       BAR0=");
            WriteU64Hex(g.mmio_phys, 0);
            ConsoleWrite("/");
            WriteU64Hex(g.mmio_size, 0);
            if (g.mmio_live)
            {
                ConsoleWrite("  MMIO=LIVE  probe_reg=");
                WriteU64Hex(g.probe_reg, 8);
                if (g.arch != nullptr)
                {
                    ConsoleWrite(" arch=");
                    ConsoleWrite(g.arch);
                }
            }
            else if (g.mmio_virt != nullptr)
            {
                ConsoleWrite("  MMIO=DECODE-FAIL");
            }
            else
            {
                ConsoleWrite("  MMIO=unmapped");
            }
            ConsoleWriteChar('\n');
        }
        if (g.vendor_id == duetos::drivers::gpu::kVendorRedHatVirt && g.device_id == 0x1050)
            saw_virtio = true;
    }

    if (saw_virtio)
    {
        const auto v = duetos::drivers::gpu::VirtioGpuLastLayout();
        if (v.present)
        {
            ConsoleWriteln("virtio-gpu layout:");
            ConsoleWrite("  common_cfg phys=");
            WriteU64Hex(v.common_cfg_phys, 0);
            ConsoleWrite("  num_queues=");
            WriteU64Dec(v.num_queues);
            ConsoleWrite("  device_features_lo=");
            WriteU64Hex(v.device_features_lo, 8);
            ConsoleWrite("  status_after_reset=");
            WriteU64Hex(v.device_status_after_reset, 2);
            ConsoleWriteChar('\n');
        }
        else
        {
            ConsoleWriteln("virtio-gpu: device present but probe incomplete (no common_cfg)");
        }

        const auto& d = duetos::drivers::gpu::VirtioGpuLastDisplayInfo();
        if (d.valid)
        {
            ConsoleWrite("virtio-gpu displays: ");
            WriteU64Dec(d.active_scanouts);
            ConsoleWriteln(" active scanout(s)");
            for (u32 i = 0; i < duetos::drivers::gpu::kVirtioGpuMaxScanouts; ++i)
            {
                if (d.enabled[i] == 0)
                    continue;
                ConsoleWrite("  scanout ");
                WriteU64Dec(i);
                ConsoleWrite(": ");
                WriteU64Dec(d.rects[i].width);
                ConsoleWrite("x");
                WriteU64Dec(d.rects[i].height);
                ConsoleWrite(" @ (");
                WriteU64Dec(d.rects[i].x);
                ConsoleWrite(",");
                WriteU64Dec(d.rects[i].y);
                ConsoleWriteln(")");
            }
        }
        else
        {
            ConsoleWriteln("virtio-gpu displays: GET_DISPLAY_INFO not issued or failed");
        }

        const auto& sc = duetos::drivers::gpu::VirtioGpuScanoutInfo();
        if (sc.ready)
        {
            ConsoleWrite("virtio-gpu scanout ");
            WriteU64Dec(sc.scanout_id);
            ConsoleWrite(": resource=");
            WriteU64Dec(sc.resource_id);
            ConsoleWrite(" ");
            WriteU64Dec(sc.width);
            ConsoleWrite("x");
            WriteU64Dec(sc.height);
            ConsoleWrite("x32 BGRA  backing phys=");
            WriteU64Hex(sc.backing_phys, 0);
            ConsoleWrite(" / ");
            WriteU64Dec(sc.backing_bytes);
            ConsoleWriteln(" B");
        }
    }
}

void CmdGfx(u32 argc, char** argv)
{
    // Subcommands: `gfx reset` clears the render-stats counters
    // so the operator can measure a specific scenario (open the
    // Files app, drag a window, etc.) without prior history. The
    // ICD handle-table counters and the GPU discovery cache are
    // boot-stable and not part of the reset.
    if (argc >= 2 && argv != nullptr && argv[1] != nullptr)
    {
        if (StrEq(argv[1], "reset"))
        {
            duetos::drivers::video::RenderStatsReset();
            ConsoleWriteln("gfx: render stats reset");
            return;
        }
        ConsoleWrite("gfx: unknown subcommand '");
        ConsoleWrite(argv[1]);
        ConsoleWriteln("' (try: gfx, gfx reset)");
        return;
    }

    // Surfaces the graphics ICD handle-table counters. The ICD is
    // a trace-only skeleton today (see subsystems/graphics/graphics.h),
    // so in the steady state all counts are zero unless something
    // has exercised the Vk*/D3D*/DXGI entry points.
    const auto s = duetos::subsystems::graphics::GraphicsStatsRead();
    ConsoleWriteln("Graphics ICD (skeleton — no real driver)");
    ConsoleWrite("  Vulkan instances: live=");
    WriteU64Dec(s.vk_instances_live);
    ConsoleWrite(" created=");
    WriteU64Dec(s.vk_instances_created);
    ConsoleWrite(" destroyed=");
    WriteU64Dec(s.vk_instances_destroyed);
    ConsoleWriteChar('\n');
    ConsoleWrite("  Vulkan devices:   live=");
    WriteU64Dec(s.vk_devices_live);
    ConsoleWrite(" created=");
    WriteU64Dec(s.vk_devices_created);
    ConsoleWrite(" destroyed=");
    WriteU64Dec(s.vk_devices_destroyed);
    ConsoleWriteChar('\n');
    ConsoleWrite("  D3D11/12 create calls: ");
    WriteU64Dec(s.d3d_create_calls);
    ConsoleWriteChar('\n');
    ConsoleWrite("  DXGI create calls:     ");
    WriteU64Dec(s.dxgi_create_calls);
    ConsoleWriteChar('\n');
    ConsoleWrite("  D3D9 create calls:     ");
    WriteU64Dec(s.d3d9_create_calls);
    ConsoleWriteChar('\n');
    ConsoleWrite("  DInput8 create calls:  ");
    WriteU64Dec(s.dinput8_create_calls);
    ConsoleWriteChar('\n');
    ConsoleWrite("  XInput poll calls:     ");
    WriteU64Dec(s.xinput_create_calls);
    ConsoleWriteChar('\n');
    ConsoleWrite("  XAudio2 create calls:  ");
    WriteU64Dec(s.xaudio2_create_calls);
    ConsoleWriteChar('\n');
    ConsoleWrite("  DSound create calls:   ");
    WriteU64Dec(s.dsound_create_calls);
    ConsoleWriteChar('\n');
    ConsoleWrite("  DDraw create calls:    ");
    WriteU64Dec(s.ddraw_create_calls);
    ConsoleWriteChar('\n');
    ConsoleWrite("  D2D1 create calls:     ");
    WriteU64Dec(s.d2d1_create_calls);
    ConsoleWriteChar('\n');
    ConsoleWrite("  DWrite create calls:   ");
    WriteU64Dec(s.dwrite_create_calls);
    ConsoleWriteChar('\n');

    const u64 ngpu = duetos::drivers::gpu::GpuCount();
    ConsoleWrite("  Physical devices visible to ICD: ");
    WriteU64Dec(ngpu);
    ConsoleWriteChar('\n');

    // Display info — bundles framebuffer + GPU + present backend.
    // Comes after the ICD section so the operator sees the
    // "skeleton ICD" first and the "but here's what's actually
    // driving the screen" reality second.
    const auto di = duetos::drivers::video::Query();
    ConsoleWriteln("Display");
    if (!di.available)
    {
        ConsoleWriteln("  framebuffer: <not available> — boot stayed on serial");
    }
    else
    {
        ConsoleWrite("  framebuffer: ");
        WriteU64Dec(di.width);
        ConsoleWrite("x");
        WriteU64Dec(di.height);
        ConsoleWrite(" pitch=");
        WriteU64Dec(di.pitch);
        ConsoleWrite(" bpp=");
        WriteU64Dec(di.bpp);
        ConsoleWriteChar('\n');
        ConsoleWrite("  fb_phys=");
        WriteU64Hex(di.fb_phys);
        ConsoleWrite(" fb_virt=");
        WriteU64Hex(di.fb_virt);
        ConsoleWriteChar('\n');
    }
    ConsoleWrite("  backend: ");
    ConsoleWrite(duetos::drivers::video::PresentBackendName(di.backend));
    if (di.compose_active)
        ConsoleWrite(" (compose-active)");
    ConsoleWriteChar('\n');
    if (di.gpu_present)
    {
        ConsoleWrite("  primary GPU: vendor=");
        ConsoleWrite(di.gpu_vendor != nullptr ? di.gpu_vendor : "<unknown>");
        ConsoleWrite(" tier=");
        ConsoleWrite(di.gpu_tier != nullptr ? di.gpu_tier : "<unknown>");
        if (di.gpu_family != nullptr)
        {
            ConsoleWrite(" family=");
            ConsoleWrite(di.gpu_family);
        }
        if (di.gpu_arch != nullptr)
        {
            ConsoleWrite(" arch=");
            ConsoleWrite(di.gpu_arch);
        }
        ConsoleWriteChar('\n');
        if (di.gpu_mmio_size != 0)
        {
            ConsoleWrite("  bar0=");
            WriteU64Hex(di.gpu_mmio_phys);
            ConsoleWrite("/");
            WriteU64Hex(di.gpu_mmio_size, 0);
            ConsoleWriteChar('\n');
        }
    }
    else
    {
        ConsoleWriteln("  primary GPU: <none discovered>");
    }

    // Render stats — accumulated since boot (or since the last
    // RenderStatsReset). Reads as a one-shot snapshot, no
    // side effects.
    const auto rs = duetos::drivers::video::RenderStatsRead();
    ConsoleWriteln("Render stats (since boot)");
    ConsoleWrite("  frames composed:   ");
    WriteU64Dec(rs.frames_composed);
    ConsoleWriteChar('\n');
    ConsoleWrite("  frames presented:  ");
    WriteU64Dec(rs.frames_presented);
    ConsoleWrite("  (clean=");
    WriteU64Dec(rs.frames_clean);
    ConsoleWrite(" partial=");
    WriteU64Dec(rs.frames_partial);
    ConsoleWrite(" full=");
    WriteU64Dec(rs.frames_full);
    ConsoleWrite(")\n");
    if (rs.surface_pixels_total != 0)
    {
        // Per-mille rather than percent so a 5% partial frame
        // doesn't round to "0%". The compositor's chrome-heavy
        // frames usually land in the 1-20% range when only the
        // taskbar / clock / cursor blink.
        const u64 permille = (rs.dirty_pixels_total * 1000ULL) / rs.surface_pixels_total;
        ConsoleWrite("  avg dirty fraction: ");
        WriteU64Dec(permille);
        ConsoleWrite("‰ (");
        WriteU64Dec(rs.dirty_pixels_total);
        ConsoleWrite(" / ");
        WriteU64Dec(rs.surface_pixels_total);
        ConsoleWrite(" px)\n");
    }
    if (rs.last_damage_valid)
    {
        ConsoleWrite("  last damage rect: ");
        WriteU64Dec(rs.last_damage_w);
        ConsoleWrite("x");
        WriteU64Dec(rs.last_damage_h);
        ConsoleWrite(" @ (");
        WriteU64Dec(rs.last_damage_x);
        ConsoleWrite(",");
        WriteU64Dec(rs.last_damage_y);
        ConsoleWrite(")\n");
    }
}

void CmdVbe(u32 argc, char** argv)
{
    using duetos::drivers::gpu::VbeCaps;
    using duetos::drivers::gpu::VbeQuery;
    using duetos::drivers::gpu::VbeSetMode;

    if (argc == 1)
    {
        const VbeCaps c = VbeQuery();
        if (!c.present)
        {
            ConsoleWriteln("VBE: not present (no Bochs / BGA-compatible GPU found)");
            return;
        }
        ConsoleWrite("VBE: id=0xB0C");
        WriteU64Hex(c.version, 1);
        ConsoleWrite("  current=");
        WriteU64Dec(c.cur_xres);
        ConsoleWrite("x");
        WriteU64Dec(c.cur_yres);
        ConsoleWrite("x");
        WriteU64Dec(c.cur_bpp);
        ConsoleWrite(c.enabled ? " LIVE" : " DISABLED");
        ConsoleWrite("  max=");
        WriteU64Dec(c.max_xres);
        ConsoleWrite("x");
        WriteU64Dec(c.max_yres);
        ConsoleWrite("x");
        WriteU64Dec(c.max_bpp);
        ConsoleWriteChar('\n');
        ConsoleWriteln("Usage: vbe <width> <height> [bpp]   — set mode (bpp defaults to 32)");
        ConsoleWriteln("       vbe                          — show current + max");
        ConsoleWriteln("NOTE: mode-set programs the controller; the framebuffer driver");
        ConsoleWriteln("      keeps its original layout until the compositor rewires.");
        return;
    }

    if (argc < 3)
    {
        ConsoleWriteln("VBE: usage: vbe [width height [bpp]]");
        return;
    }
    u16 width = 0, height = 0, bpp = 32;
    if (!ParseU16Decimal(argv[1], &width) || !ParseU16Decimal(argv[2], &height))
    {
        ConsoleWriteln("VBE: width/height must be decimal integers");
        return;
    }
    if (argc >= 4 && !ParseU16Decimal(argv[3], &bpp))
    {
        ConsoleWriteln("VBE: bpp must be decimal (8, 15, 16, 24, or 32)");
        return;
    }
    if (VbeSetMode(width, height, bpp))
    {
        ConsoleWrite("VBE: mode set OK — ");
        WriteU64Dec(width);
        ConsoleWrite("x");
        WriteU64Dec(height);
        ConsoleWrite("x");
        WriteU64Dec(bpp);
        ConsoleWriteln("");

        // Rebind the kernel framebuffer driver to the Bochs-
        // stdvga BAR0 at the new dimensions so subsequent
        // paints land at the requested resolution. Find the
        // Bochs GPU in the discovery cache — BAR0 is the
        // linear framebuffer aperture.
        u64 lfb_phys = 0;
        const u64 gn = duetos::drivers::gpu::GpuCount();
        for (u64 i = 0; i < gn; ++i)
        {
            const auto& g = duetos::drivers::gpu::Gpu(i);
            if (g.vendor_id == duetos::drivers::gpu::kVendorQemuBochs && g.mmio_phys != 0)
            {
                lfb_phys = g.mmio_phys;
                break;
            }
        }
        if (lfb_phys == 0)
        {
            ConsoleWriteln("VBE: hardware programmed, but no Bochs BAR0 found — fb not rebound");
            return;
        }
        const u32 pitch = static_cast<u32>(width) * 4;
        if (duetos::drivers::video::FramebufferRebind(lfb_phys, width, height, pitch, static_cast<u8>(bpp)))
        {
            duetos::drivers::video::FramebufferClear(0);
            ConsoleWriteln("VBE: framebuffer rebound; next recompose paints at the new size");
            ConsoleWriteln("     (overlay widgets retain boot-time positions — known limitation)");
        }
        else
        {
            ConsoleWriteln("VBE: hardware programmed, but framebuffer rebind failed");
        }
    }
    else
    {
        ConsoleWriteln("VBE: mode-set rejected (dimensions exceed max, bpp unsupported, or no BGA)");
    }
}

namespace
{

// Decode a single hex nibble. Returns 0xFF on failure.
u8 NibbleFromHex(char c)
{
    if (c >= '0' && c <= '9')
        return static_cast<u8>(c - '0');
    if (c >= 'a' && c <= 'f')
        return static_cast<u8>(c - 'a' + 10);
    if (c >= 'A' && c <= 'F')
        return static_cast<u8>(c - 'A' + 10);
    return 0xFF;
}

// Parse a hex stream of EXACTLY 256 hex digits (whitespace + colons
// allowed) into 128 bytes. Returns false on any malformed digit or
// short input.
bool ParseEdidHex(const char* s, u8 out[128])
{
    u32 written = 0;
    u8 hi = 0xFF;
    while (*s != '\0' && written < 128)
    {
        const char c = *s++;
        if (c == ' ' || c == '\t' || c == ':' || c == ',' || c == '\n' || c == '\r')
            continue;
        const u8 nib = NibbleFromHex(c);
        if (nib == 0xFF)
            return false;
        if (hi == 0xFF)
        {
            hi = nib;
        }
        else
        {
            out[written++] = static_cast<u8>((hi << 4) | nib);
            hi = 0xFF;
        }
    }
    return written == 128 && hi == 0xFF;
}

void RunSyntheticDump()
{
    // Build the same 1080p fixture the boot self-test exercises so
    // operators can see a known-good decode without needing a real
    // monitor wired through DDC.
    u8 buf[128];
    for (u32 i = 0; i < 128; ++i)
        buf[i] = 0;
    buf[0] = 0x00;
    buf[1] = 0xFF;
    buf[2] = 0xFF;
    buf[3] = 0xFF;
    buf[4] = 0xFF;
    buf[5] = 0xFF;
    buf[6] = 0xFF;
    buf[7] = 0x00;
    // "DEL" PnP code = 0x10AC big-endian
    buf[8] = 0x10;
    buf[9] = 0xAC;
    buf[10] = 0xC4;
    buf[11] = 0x0A;
    buf[12] = 0x78;
    buf[13] = 0x56;
    buf[14] = 0x34;
    buf[15] = 0x12;
    buf[16] = 12;
    buf[17] = 30;
    buf[18] = 1;
    buf[19] = 4;
    buf[20] = static_cast<u8>(0x80 | (2 << 4) | 5);
    buf[21] = 60;
    buf[22] = 34;
    buf[23] = 120;
    buf[24] = 0xE0 | 0x04 | 0x02;
    buf[35] = 0x21;
    buf[36] = 0x08;
    buf[38] = static_cast<u8>((1280u / 8u) - 31u);
    buf[39] = static_cast<u8>((2u << 6) | (60 - 60));
    for (u32 i = 1; i < 8; ++i)
    {
        buf[38 + i * 2] = 0x01;
        buf[39 + i * 2] = 0x01;
    }
    // DTD: 1920x1080@60 — same shape as the self-test fixture.
    const u16 px = 14850;
    buf[54] = static_cast<u8>(px & 0xFF);
    buf[55] = static_cast<u8>((px >> 8) & 0xFF);
    buf[56] = 1920 & 0xFF;
    buf[57] = 280 & 0xFF;
    buf[58] = static_cast<u8>(((1920 >> 4) & 0xF0) | ((280 >> 8) & 0x0F));
    buf[59] = 1080 & 0xFF;
    buf[60] = 45 & 0xFF;
    buf[61] = static_cast<u8>(((1080 >> 4) & 0xF0) | ((45 >> 8) & 0x0F));
    buf[62] = 88;
    buf[63] = 44;
    buf[64] = static_cast<u8>(((4 & 0x0F) << 4) | (5 & 0x0F));
    buf[65] = 0;
    buf[66] = 600 & 0xFF;
    buf[67] = 340 & 0xFF;
    buf[68] = static_cast<u8>(((600 >> 4) & 0xF0) | ((340 >> 8) & 0x0F));
    buf[69] = 0;
    buf[70] = 0;
    buf[71] = static_cast<u8>((3u << 3) | 0x04 | 0x02);
    // DTD slot 1 — monitor name
    buf[72] = 0;
    buf[73] = 0;
    buf[74] = 0;
    buf[75] = 0xFC;
    buf[76] = 0;
    const char name[] = "DUET-DEMO-1";
    for (u32 i = 0; i < sizeof(name) - 1; ++i)
        buf[77 + i] = static_cast<u8>(name[i]);
    buf[77 + sizeof(name) - 1] = 0x0A;
    for (u32 i = 77 + sizeof(name); i < 90; ++i)
        buf[i] = 0x20;
    // DTD slot 2 — range limits
    buf[90] = 0;
    buf[91] = 0;
    buf[92] = 0;
    buf[93] = 0xFD;
    buf[94] = 0;
    buf[95] = 50;
    buf[96] = 75;
    buf[97] = 30;
    buf[98] = 80;
    buf[99] = 17;
    buf[100] = 0;
    for (u32 i = 101; i < 108; ++i)
        buf[i] = 0x20;
    // DTD slot 3 — dummy
    buf[111] = 0x10;

    u32 sum = 0;
    for (u32 i = 0; i < 127; ++i)
        sum += buf[i];
    buf[127] = static_cast<u8>((256u - (sum & 0xFFu)) & 0xFFu);

    auto res = duetos::drivers::gpu::EdidParseBaseBlock(buf, sizeof(buf));
    if (!res.has_value())
    {
        ConsoleWriteln("monitor: synthetic EDID failed to parse (parser bug?)");
        return;
    }
    duetos::drivers::gpu::EdidDumpToConsole(res.value());
}

} // namespace

void RunCvtDemo(u32 w, u32 h, u32 ref_mhz)
{
    duetos::drivers::gpu::CvtRequest req = {};
    req.h_active = static_cast<u16>(w);
    req.v_active = static_cast<u16>(h);
    req.refresh_mhz = ref_mhz;
    req.mode = duetos::drivers::gpu::CvtMode::ReducedBlankingV1;
    auto rb = duetos::drivers::gpu::CvtGenerate(req);
    if (rb.has_value())
    {
        const duetos::drivers::gpu::EdidDtd& t = rb.value();
        ConsoleWrite("  CVT-RB:    ");
        WriteU64Dec(t.h_active);
        ConsoleWrite("x");
        WriteU64Dec(t.v_active);
        ConsoleWrite("  htotal=");
        WriteU64Dec(t.h_active + t.h_blanking);
        ConsoleWrite("  vtotal=");
        WriteU64Dec(t.v_active + t.v_blanking);
        ConsoleWrite("  pclk=");
        WriteU64Dec(t.pixel_clock_khz / 1000);
        ConsoleWrite(".");
        WriteU64Dec(t.pixel_clock_khz % 1000);
        ConsoleWrite(" MHz  refresh=");
        WriteU64Dec(t.refresh_mhz / 1000);
        ConsoleWrite(".");
        WriteU64Dec(t.refresh_mhz % 1000);
        ConsoleWriteln(" Hz");
    }
    req.mode = duetos::drivers::gpu::CvtMode::Standard;
    auto std_res = duetos::drivers::gpu::CvtGenerate(req);
    if (std_res.has_value())
    {
        const duetos::drivers::gpu::EdidDtd& t = std_res.value();
        ConsoleWrite("  CVT-STD:   ");
        WriteU64Dec(t.h_active);
        ConsoleWrite("x");
        WriteU64Dec(t.v_active);
        ConsoleWrite("  htotal=");
        WriteU64Dec(t.h_active + t.h_blanking);
        ConsoleWrite("  vtotal=");
        WriteU64Dec(t.v_active + t.v_blanking);
        ConsoleWrite("  pclk=");
        WriteU64Dec(t.pixel_clock_khz / 1000);
        ConsoleWrite(".");
        WriteU64Dec(t.pixel_clock_khz % 1000);
        ConsoleWriteln(" MHz");
    }
}

void CmdMonitor(u32 argc, char** argv)
{
    if (argc == 1)
    {
        ConsoleWriteln("monitor — dump parsed EDID for the system display");
        ConsoleWriteln("");
        ConsoleWriteln("Usage:");
        ConsoleWriteln("  monitor                 — show synthetic test EDID + CVT modes");
        ConsoleWriteln("  monitor demo            — same; explicit synonym");
        ConsoleWriteln("  monitor parse <hex>     — parse + decode a 256-hex-digit EDID blob");
        ConsoleWriteln("  monitor cea <hex>       — parse + decode a 256-hex-digit CEA-861 ext block");
        ConsoleWriteln("  monitor cvt W H R       — generate a CVT timing for WxH @ R Hz");
        ConsoleWriteln("");
        ConsoleWriteln("NOTE: GPU drivers are probe-only in v0; no DDC/I2C transport is live.");
        ConsoleWriteln("      Once a vendor driver gains DDC, this command will pick up real data.");
        ConsoleWriteln("");
        RunSyntheticDump();
        ConsoleWriteln("");
        ConsoleWriteln("CVT timings for common modes:");
        RunCvtDemo(1920, 1080, 60000);
        RunCvtDemo(2560, 1440, 60000);
        RunCvtDemo(3840, 2160, 60000);
        return;
    }
    if (argc == 2 && (argv[1][0] == 'd' || argv[1][0] == 'D'))
    {
        RunSyntheticDump();
        return;
    }
    if (argc >= 3 && (argv[1][0] == 'p' || argv[1][0] == 'P'))
    {
        u8 buf[128];
        if (!ParseEdidHex(argv[2], buf))
        {
            ConsoleWriteln("monitor: hex blob must be exactly 256 hex digits (128 bytes).");
            ConsoleWriteln("         Whitespace, colons and commas are allowed as separators.");
            return;
        }
        auto res = duetos::drivers::gpu::EdidParseBaseBlock(buf, sizeof(buf));
        if (!res.has_value())
        {
            ConsoleWriteln("monitor: parser rejected the input (length check failed).");
            return;
        }
        duetos::drivers::gpu::EdidDumpToConsole(res.value());
        return;
    }
    if (argc >= 3 && argv[1][0] == 'c' && argv[1][1] == 'e')
    {
        u8 buf[128];
        if (!ParseEdidHex(argv[2], buf))
        {
            ConsoleWriteln("monitor cea: hex blob must be exactly 256 hex digits (128 bytes).");
            return;
        }
        auto res = duetos::drivers::gpu::Cea861ParseBlock(buf, sizeof(buf));
        if (!res.has_value())
        {
            ConsoleWriteln("monitor cea: parser rejected the input.");
            return;
        }
        duetos::drivers::gpu::Cea861DumpToConsole(res.value());
        return;
    }
    if (argc >= 5 && argv[1][0] == 'c' && argv[1][1] == 'v')
    {
        u16 w = 0, h = 0;
        u16 r = 60;
        if (!ParseU16Decimal(argv[2], &w) || !ParseU16Decimal(argv[3], &h) || !ParseU16Decimal(argv[4], &r))
        {
            ConsoleWriteln("monitor cvt: usage: monitor cvt <width> <height> <refresh-hz>");
            return;
        }
        RunCvtDemo(w, h, static_cast<u32>(r) * 1000u);
        return;
    }
    ConsoleWriteln("monitor: unrecognised arguments — try `monitor` for usage.");
}

} // namespace duetos::core::shell::internal
