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

#include "shell_internal.h"

#include "../arch/x86_64/cpu.h"
#include "../arch/x86_64/hpet.h"
#include "../arch/x86_64/lapic.h"
#include "../arch/x86_64/smbios.h"
#include "../arch/x86_64/smp.h"
#include "../arch/x86_64/thermal.h"
#include "../arch/x86_64/timer.h"
#include "../drivers/gpu/bochs_vbe.h"
#include "../drivers/gpu/gpu.h"
#include "../drivers/gpu/virtio_gpu.h"
#include "../drivers/input/ps2kbd.h"
#include "../drivers/input/ps2mouse.h"
#include "../drivers/pci/pci.h"
#include "../drivers/power/power.h"
#include "../drivers/video/console.h"
#include "../drivers/video/framebuffer.h"
#include "../mm/kheap.h"
#include "../mm/paging.h"
#include "../sched/sched.h"
#include "../subsystems/graphics/graphics.h"

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
    WriteU64Dec(duetos::arch::TimerTicks());
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

void CmdHeap()
{
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

void CmdGfx()
{
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
    ConsoleWrite("  D3D create calls: ");
    WriteU64Dec(s.d3d_create_calls);
    ConsoleWriteChar('\n');
    ConsoleWrite("  DXGI create calls: ");
    WriteU64Dec(s.dxgi_create_calls);
    ConsoleWriteChar('\n');

    const u64 ngpu = duetos::drivers::gpu::GpuCount();
    ConsoleWrite("  Physical devices visible to ICD: ");
    WriteU64Dec(ngpu);
    ConsoleWriteChar('\n');
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

} // namespace duetos::core::shell::internal
