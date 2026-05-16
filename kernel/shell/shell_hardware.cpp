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
#include "arch/x86_64/serial.h"
#include "arch/x86_64/smbios.h"
#include "arch/x86_64/timer.h"
#include "arch/x86_64/smp.h"
#include "arch/x86_64/thermal.h"
#include "arch/x86_64/timer.h"
#include "diag/cleanroom_trace.h"
#include "diag/fix_journal.h"
#include "drivers/audio/audio.h"
#include "drivers/audio/hda.h"
#include "drivers/audio/hda_jack.h"
#include "drivers/audio/hda_jack_inventory.h"
#include "drivers/mei/mei.h"
#include "drivers/gpu/bochs_vbe.h"
#include "drivers/gpu/cea861.h"
#include "drivers/gpu/cvt.h"
#include "drivers/gpu/dpms.h"
#include "drivers/gpu/edid.h"
#include "drivers/gpu/gpu.h"
#include "drivers/gpu/virtio_gpu.h"
#include "drivers/input/ps2kbd.h"
#include "drivers/input/ps2mouse.h"
#include "drivers/net/net.h"
#include "drivers/pci/pci.h"
#include "drivers/power/power.h"
#include "drivers/storage/ahci.h"
#include "drivers/storage/block.h"
#include "drivers/storage/nvme.h"
#include "drivers/usb/usb.h"
#include "drivers/usb/xhci.h"
#include "drivers/video/console.h"
#include "drivers/video/display_info.h"
#include "drivers/video/framebuffer.h"
#include "drivers/video/render_stats.h"
#include "mm/kheap.h"
#include "mm/page.h"
#include "mm/paging.h"
#include "sched/sched.h"
#include "subsystems/graphics/graphics.h"
#include "time/tick.h"
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
    return ::duetos::arch::TscRead();
}

inline u64 ReadMsrRaw(u32 msr)
{
    u32 lo, hi;
    asm volatile("rdmsr" : "=a"(lo), "=d"(hi) : "c"(msr));
    return (static_cast<u64>(hi) << 32) | lo;
}

void SerialWriteHexField(const char* name, u64 value)
{
    duetos::arch::SerialWrite(" ");
    duetos::arch::SerialWrite(name);
    duetos::arch::SerialWrite("=");
    duetos::arch::SerialWriteHex(value);
}

void RecordHardwareTrace(const char* phase)
{
    const auto kbd = duetos::drivers::input::Ps2KeyboardStats();
    const auto mouse = duetos::drivers::input::Ps2MouseStatsRead();
    const auto power = duetos::drivers::power::PowerSnapshotRead();
    const auto wifi = duetos::drivers::net::WirelessStatusRead();

    duetos::core::CleanroomTraceRecord("hw", phase, duetos::drivers::pci::PciDeviceCount(),
                                       duetos::drivers::gpu::GpuCount(),
                                       duetos::drivers::audio::AudioControllerCount());
    duetos::core::CleanroomTraceRecord("hw", "usb-storage", duetos::drivers::usb::HostControllerCount(),
                                       duetos::drivers::usb::xhci::XhciCount(),
                                       duetos::drivers::storage::BlockDeviceCount());
    duetos::core::CleanroomTraceRecord("hw", "disk-sectors", duetos::drivers::storage::NvmeNamespaceSectorCount(),
                                       duetos::drivers::storage::AhciNamespaceSectorCount(),
                                       duetos::drivers::mei::MeiDeviceCount());
    duetos::core::CleanroomTraceRecord("hw", "net-input", duetos::drivers::net::NicCount(), wifi.adapters_detected,
                                       kbd.irqs_seen + mouse.irqs_seen);
    duetos::core::CleanroomTraceRecord("hw", "power", power.ac, power.battery.state,
                                       (static_cast<u64>(power.package_temp_c) << 32) | power.cpu_temp_c);
}

void PrintHardwareCaptureSummary(bool serial)
{
    const auto kbd = duetos::drivers::input::Ps2KeyboardStats();
    const auto mouse = duetos::drivers::input::Ps2MouseStatsRead();
    const auto power = duetos::drivers::power::PowerSnapshotRead();
    const auto wifi = duetos::drivers::net::WirelessStatusRead();
    const auto fix = duetos::diag::FixJournalGetStats();

    ConsoleWrite("HW: pci=");
    WriteU64Dec(duetos::drivers::pci::PciDeviceCount());
    ConsoleWrite(" gpu=");
    WriteU64Dec(duetos::drivers::gpu::GpuCount());
    ConsoleWrite(" audio=");
    WriteU64Dec(duetos::drivers::audio::AudioControllerCount());
    ConsoleWrite(" mei=");
    WriteU64Dec(duetos::drivers::mei::MeiDeviceCount());
    ConsoleWriteln("");

    ConsoleWrite("HW: usb-hc=");
    WriteU64Dec(duetos::drivers::usb::HostControllerCount());
    ConsoleWrite(" xhci=");
    WriteU64Dec(duetos::drivers::usb::xhci::XhciCount());
    ConsoleWrite(" block=");
    WriteU64Dec(duetos::drivers::storage::BlockDeviceCount());
    ConsoleWrite(" nvme-sectors=");
    WriteU64Dec(duetos::drivers::storage::NvmeNamespaceSectorCount());
    ConsoleWrite(" ahci-sectors=");
    WriteU64Dec(duetos::drivers::storage::AhciNamespaceSectorCount());
    ConsoleWriteln("");

    ConsoleWrite("HW: nic=");
    WriteU64Dec(duetos::drivers::net::NicCount());
    ConsoleWrite(" wifi-adapters=");
    WriteU64Dec(wifi.adapters_detected);
    ConsoleWrite(" wifi-upload-failed=");
    WriteU64Dec(wifi.firmware_upload_failed);
    ConsoleWrite(" hda-streams=");
    WriteU64Dec(duetos::drivers::audio::hda::TotalStreamCount());
    ConsoleWrite(" hda-armed=");
    WriteU64Dec(duetos::drivers::audio::hda::ArmedStreamCount());
    ConsoleWriteln("");

    ConsoleWrite("HW: input kbd-irqs=");
    WriteU64Dec(kbd.irqs_seen);
    ConsoleWrite(" mouse-irqs=");
    WriteU64Dec(mouse.irqs_seen);
    ConsoleWrite(" mouse-packets=");
    WriteU64Dec(mouse.packets_decoded);
    ConsoleWrite(" ac=");
    ConsoleWrite(duetos::drivers::power::AcStateName(power.ac));
    ConsoleWrite(" bat=");
    ConsoleWrite(duetos::drivers::power::BatteryStateName(power.battery.state));
    ConsoleWriteln("");

    ConsoleWrite("HW: traces crtrace=");
    WriteU64Dec(duetos::core::CleanroomTraceCount());
    ConsoleWrite(" fix-unique=");
    WriteU64Dec(fix.records_unique);
    ConsoleWrite(" fix-dedup=");
    WriteU64Dec(fix.dedup_hits);
    ConsoleWriteln("");

    if (!serial)
        return;

    duetos::arch::SerialWrite("[hwcap] summary");
    SerialWriteHexField("pci", duetos::drivers::pci::PciDeviceCount());
    SerialWriteHexField("gpu", duetos::drivers::gpu::GpuCount());
    SerialWriteHexField("audio", duetos::drivers::audio::AudioControllerCount());
    SerialWriteHexField("usb_hc", duetos::drivers::usb::HostControllerCount());
    SerialWriteHexField("xhci", duetos::drivers::usb::xhci::XhciCount());
    SerialWriteHexField("block", duetos::drivers::storage::BlockDeviceCount());
    SerialWriteHexField("nic", duetos::drivers::net::NicCount());
    SerialWriteHexField("wifi", wifi.adapters_detected);
    SerialWriteHexField("mei", duetos::drivers::mei::MeiDeviceCount());
    SerialWriteHexField("crtrace", duetos::core::CleanroomTraceCount());
    SerialWriteHexField("fix_unique", fix.records_unique);
    duetos::arch::SerialWrite("\n");
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

// ============================================================
// DANGER ZONE — raw hardware/memory pokes.
//
// These bypass every kernel safety net by design: no MSR
// whitelist, no page-permission check, no device arbitration.
// They exist so the OS author can drive bring-up / silicon
// debug from the live shell (the wrmsr / devmem2 / inb-outb
// equivalents). A wrong value here triple-faults the box or
// silently corrupts RAM — that is the accepted cost of the
// tool, not a bug. Every one is admin-gated in the dispatcher
// AND requires the literal FORCE confirmation token, mirroring
// the `mkfs ... ERASE` contract.
// ============================================================

namespace
{

// Print the risk banner and check the confirmation token.
// Returns true only when `token` is the literal "FORCE".
bool DangerConfirmed(const char* cmd, const char* risk, const char* token)
{
    ConsoleWriteln("");
    ConsoleWriteln("  !!! ===================== DANGER ===================== !!!");
    ConsoleWrite("  !!!  ");
    ConsoleWrite(cmd);
    ConsoleWriteln("");
    ConsoleWrite("  !!!  ");
    ConsoleWrite(risk);
    ConsoleWriteln("");
    ConsoleWriteln("  !!!  No whitelist, no permission check, no undo.");
    ConsoleWriteln("  !!! =================================================== !!!");
    if (token != nullptr && StrEq(token, "FORCE"))
    {
        ConsoleWriteln("  (FORCE supplied — proceeding)");
        return true;
    }
    ConsoleWriteln("  REFUSED: append the literal token  FORCE  to proceed.");
    return false;
}

// Bare-hex (no 0x) or 0x-prefixed parser for register indices /
// physical addresses — matches how the read-only `msr` command
// already accepts an index.
bool ParseBareHex64(const char* s, u64* out)
{
    u64 v = 0;
    bool any = false;
    for (u32 i = 0; s[i] != '\0'; ++i)
    {
        char ch = s[i];
        if ((i == 1) && (ch == 'x' || ch == 'X') && s[0] == '0')
            continue;
        u8 nib;
        if (ch >= '0' && ch <= '9')
            nib = static_cast<u8>(ch - '0');
        else if (ch >= 'a' && ch <= 'f')
            nib = static_cast<u8>(ch - 'a' + 10);
        else if (ch >= 'A' && ch <= 'F')
            nib = static_cast<u8>(ch - 'A' + 10);
        else
            return false;
        v = (v << 4) | nib;
        any = true;
    }
    if (!any)
        return false;
    *out = v;
    return true;
}

} // namespace

void CmdWrmsr(u32 argc, char** argv)
{
    if (argc < 3)
    {
        ConsoleWriteln("WRMSR: USAGE: WRMSR <HEX-INDEX> <HEX-VALUE> FORCE");
        ConsoleWriteln("  Pairs with the read-only `msr`. NO index whitelist —");
        ConsoleWriteln("  a bad write to EFER/PAT/MTRR triple-faults the box.");
        return;
    }
    u64 idx = 0;
    u64 val = 0;
    if (!ParseBareHex64(argv[1], &idx) || idx > 0xFFFFFFFFull)
    {
        ConsoleWriteln("WRMSR: BAD INDEX (hex u32)");
        return;
    }
    if (!ParseBareHex64(argv[2], &val))
    {
        ConsoleWriteln("WRMSR: BAD VALUE (hex u64)");
        return;
    }
    if (!DangerConfirmed("WRMSR — write a model-specific register",
                         "Wrong MSR/value = #GP / triple fault / silent CPU misconfig.",
                         (argc >= 4) ? argv[3] : nullptr))
        return;
    duetos::arch::WriteMsr(static_cast<u32>(idx), val);
    ConsoleWrite("WRMSR: wrote ");
    WriteU64Hex(val);
    ConsoleWrite(" to MSR ");
    WriteU64Hex(idx, 8);
    ConsoleWrite("  (readback ");
    WriteU64Hex(duetos::arch::ReadMsr(static_cast<u32>(idx)));
    ConsoleWriteln(")");
}

void CmdIo(u32 argc, char** argv)
{
    if (argc < 3)
    {
        ConsoleWriteln("IO: USAGE:");
        ConsoleWriteln("  IO INB|INW  <PORT>                read a port (admin)");
        ConsoleWriteln("  IO OUTB|OUTW <PORT> <VALUE> FORCE write a port");
        ConsoleWriteln("  Ports are hex. Writing the wrong port can reset the");
        ConsoleWriteln("  machine or corrupt a live device.");
        return;
    }
    u64 port = 0;
    if (!ParseBareHex64(argv[2], &port) || port > 0xFFFFull)
    {
        ConsoleWriteln("IO: BAD PORT (hex u16)");
        return;
    }
    const u16 p = static_cast<u16>(port);
    if (StrEq(argv[1], "inb"))
    {
        ConsoleWrite("IO INB ");
        WriteU64Hex(p, 4);
        ConsoleWrite(" = ");
        WriteU64Hex(duetos::arch::Inb(p), 2);
        ConsoleWriteChar('\n');
        return;
    }
    if (StrEq(argv[1], "inw"))
    {
        ConsoleWrite("IO INW ");
        WriteU64Hex(p, 4);
        ConsoleWrite(" = ");
        WriteU64Hex(duetos::arch::Inw(p), 4);
        ConsoleWriteChar('\n');
        return;
    }
    const bool outb = StrEq(argv[1], "outb");
    const bool outw = StrEq(argv[1], "outw");
    if (!outb && !outw)
    {
        ConsoleWriteln("IO: UNKNOWN OP (inb|inw|outb|outw)");
        return;
    }
    if (argc < 4)
    {
        ConsoleWriteln("IO: OUT NEEDS A VALUE");
        return;
    }
    u64 val = 0;
    if (!ParseBareHex64(argv[3], &val))
    {
        ConsoleWriteln("IO: BAD VALUE (hex)");
        return;
    }
    if (!DangerConfirmed("IO OUT — raw x86 port write", "Wrong port can reset the box or wedge a live device.",
                         (argc >= 5) ? argv[4] : nullptr))
        return;
    if (outb)
        duetos::arch::Outb(p, static_cast<u8>(val));
    else
        duetos::arch::Outw(p, static_cast<u16>(val));
    ConsoleWrite("IO: wrote ");
    WriteU64Hex(val, outb ? 2 : 4);
    ConsoleWrite(" -> port ");
    WriteU64Hex(p, 4);
    ConsoleWriteln("");
}

// Shared width decode for peek/poke: 'b'=1 'w'=2 'd'=4 'q'=8.
// Returns 0 on an unrecognised spec.
static u32 PeekWidth(const char* s)
{
    if (s == nullptr)
        return 8;
    if (StrEq(s, "b"))
        return 1;
    if (StrEq(s, "w"))
        return 2;
    if (StrEq(s, "d"))
        return 4;
    if (StrEq(s, "q"))
        return 8;
    return 0;
}

void CmdPeek(u32 argc, char** argv)
{
    if (argc < 2)
    {
        ConsoleWriteln("PEEK: USAGE: PEEK <HEX-PADDR> [b|w|d|q]   (admin)");
        ConsoleWriteln("  Reads raw physical RAM via the 1 GiB direct map.");
        return;
    }
    u64 pa = 0;
    if (!ParseBareHex64(argv[1], &pa))
    {
        ConsoleWriteln("PEEK: BAD ADDRESS");
        return;
    }
    const u32 w = PeekWidth(argc >= 3 ? argv[2] : nullptr);
    if (w == 0)
    {
        ConsoleWriteln("PEEK: BAD WIDTH (b|w|d|q)");
        return;
    }
    if (pa >= duetos::mm::kDirectMapBytes || w > duetos::mm::kDirectMapBytes - pa)
    {
        ConsoleWriteln("PEEK: ADDRESS OUTSIDE 1 GiB DIRECT MAP (would panic)");
        return;
    }
    const volatile u8* base = static_cast<const volatile u8*>(duetos::mm::PhysToVirt(pa));
    u64 v = 0;
    for (u32 i = 0; i < w; ++i)
        v |= static_cast<u64>(base[i]) << (8 * i);
    ConsoleWrite("PEEK ");
    WriteU64Hex(pa);
    ConsoleWrite(" = ");
    WriteU64Hex(v, w * 2);
    ConsoleWriteChar('\n');
}

void CmdPoke(u32 argc, char** argv)
{
    if (argc < 3)
    {
        ConsoleWriteln("POKE: USAGE: POKE <HEX-PADDR> <HEX-VALUE> [b|w|d|q] FORCE");
        ConsoleWriteln("  Writes raw physical RAM. Corrupting a page table,");
        ConsoleWriteln("  kernel struct, or MMIO window faults or bricks the run.");
        return;
    }
    u64 pa = 0;
    u64 val = 0;
    if (!ParseBareHex64(argv[1], &pa))
    {
        ConsoleWriteln("POKE: BAD ADDRESS");
        return;
    }
    if (!ParseBareHex64(argv[2], &val))
    {
        ConsoleWriteln("POKE: BAD VALUE");
        return;
    }
    const char* wspec = (argc >= 4 && PeekWidth(argv[3]) != 0) ? argv[3] : nullptr;
    const u32 w = (argc >= 4 && PeekWidth(argv[3]) != 0) ? PeekWidth(argv[3]) : 8;
    (void)wspec;
    if (pa >= duetos::mm::kDirectMapBytes || w > duetos::mm::kDirectMapBytes - pa)
    {
        ConsoleWriteln("POKE: ADDRESS OUTSIDE 1 GiB DIRECT MAP (would panic)");
        return;
    }
    // The FORCE token is the last arg; it may be at index 3 (no
    // width given) or 4 (width given).
    const char* tok = nullptr;
    if (argc >= 5)
        tok = argv[4];
    else if (argc == 4 && PeekWidth(argv[3]) == 0)
        tok = argv[3];
    if (!DangerConfirmed("POKE — write raw physical memory",
                         "Hitting a page table / kernel struct / MMIO = instant fault or corruption.", tok))
        return;
    volatile u8* base = static_cast<volatile u8*>(duetos::mm::PhysToVirt(pa));
    for (u32 i = 0; i < w; ++i)
        base[i] = static_cast<u8>((val >> (8 * i)) & 0xFF);
    ConsoleWrite("POKE: wrote ");
    WriteU64Hex(val, w * 2);
    ConsoleWrite(" -> phys ");
    WriteU64Hex(pa);
    ConsoleWriteln("");
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

void CmdHw(u32 argc, char** argv)
{
    const bool capture = (argc >= 2 && StrEq(argv[1], "capture"));
    const bool activate = capture || (argc >= 2 && StrEq(argv[1], "activate"));
    if (argc >= 2 && !activate && !StrEq(argv[1], "status"))
    {
        ConsoleWriteln("HW: usage: hw <status|activate|capture>");
        return;
    }

    if (activate)
    {
        // Re-run only init paths documented as idempotent. UsbInit,
        // PowerInit, and PS/2 init are intentionally single-shot, so
        // this command captures their live counters instead of trying
        // to replay controller init sequences that own IRQ routing.
        duetos::drivers::gpu::GpuInit();
        duetos::drivers::audio::AudioInit();
        duetos::drivers::net::NetInit();
        duetos::drivers::mei::MeiInit();
        duetos::drivers::storage::NvmeInit();
        duetos::drivers::storage::AhciInit();
        duetos::drivers::usb::xhci::XhciInit();
    }

    RecordHardwareTrace(capture ? "capture" : (activate ? "activate" : "status"));
    PrintHardwareCaptureSummary(capture);
    if (capture)
    {
        duetos::diag::FixJournalEmitBootSummary();
        ConsoleWriteln("HW: captured hardware summary, cleanroom trace records, and fix-journal summary to serial");
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

void CmdVtop(u32 argc, char** argv)
{
    if (argc < 2)
    {
        ConsoleWriteln("VTOP: USAGE: VTOP <VADDR>   (decimal or 0x-hex)");
        ConsoleWriteln("  Walks the active CR3 and decodes the leaf PTE.");
        return;
    }
    u64 virt = 0;
    if (!ParseU64Str(argv[1], &virt))
    {
        ConsoleWriteln("VTOP: BAD ADDRESS");
        return;
    }
    const auto w = duetos::mm::SnapshotPageWalk(virt);
    ConsoleWrite("VADDR:  ");
    WriteU64Hex(w.virt);
    ConsoleWriteChar('\n');
    ConsoleWrite("CR3:    ");
    WriteU64Hex(w.cr3);
    ConsoleWriteChar('\n');
    ConsoleWrite("INDEX:  pml4=");
    WriteU64Dec(w.idx_pml4);
    ConsoleWrite(" pdpt=");
    WriteU64Dec(w.idx_pdpt);
    ConsoleWrite(" pd=");
    WriteU64Dec(w.idx_pd);
    ConsoleWrite(" pt=");
    WriteU64Dec(w.idx_pt);
    ConsoleWriteChar('\n');

    u64 leaf = 0;
    const char* size = nullptr;
    switch (w.stop)
    {
    case duetos::mm::PageWalkStop::FourKiB:
        leaf = w.entry_pt;
        size = "4 KiB";
        break;
    case duetos::mm::PageWalkStop::TwoMiB:
        leaf = w.entry_pd;
        size = "2 MiB";
        break;
    case duetos::mm::PageWalkStop::OneGiB:
        leaf = w.entry_pdpt;
        size = "1 GiB";
        break;
    case duetos::mm::PageWalkStop::NotPresentPml4:
        ConsoleWriteln("RESULT: not mapped (PML4E not present)");
        return;
    case duetos::mm::PageWalkStop::NotPresentPdpt:
        ConsoleWriteln("RESULT: not mapped (PDPTE not present)");
        return;
    case duetos::mm::PageWalkStop::NotPresentPd:
        ConsoleWriteln("RESULT: not mapped (PDE not present)");
        return;
    case duetos::mm::PageWalkStop::NotPresentPt:
        ConsoleWriteln("RESULT: not mapped (PTE not present)");
        return;
    case duetos::mm::PageWalkStop::NonCanonical:
        ConsoleWriteln("RESULT: non-canonical address");
        return;
    case duetos::mm::PageWalkStop::OutOfDirectMap:
    default:
        ConsoleWriteln("RESULT: walk aborted (table phys outside direct map)");
        return;
    }

    ConsoleWrite("PADDR:  ");
    WriteU64Hex(w.leaf_phys);
    ConsoleWrite("  (");
    ConsoleWrite(size);
    ConsoleWriteln(" page)");
    ConsoleWrite("PTE:    ");
    WriteU64Hex(leaf);
    ConsoleWriteChar('\n');
    ConsoleWrite("FLAGS: ");
    ConsoleWrite((leaf & duetos::mm::kPageWritable) ? " W" : " R");
    ConsoleWrite((leaf & duetos::mm::kPageUser) ? " USER" : " KERN");
    if (leaf & duetos::mm::kPageNoExecute)
        ConsoleWrite(" NX");
    if (leaf & duetos::mm::kPageGlobal)
        ConsoleWrite(" GLOBAL");
    if (leaf & duetos::mm::kPageCacheDisable)
        ConsoleWrite(" UC");
    if (leaf & duetos::mm::kPageWriteThru)
        ConsoleWrite(" WT");
    if (leaf & duetos::mm::kPageAccessed)
        ConsoleWrite(" A");
    if (leaf & duetos::mm::kPageDirty)
        ConsoleWrite(" D");
    ConsoleWriteChar('\n');
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

} // namespace duetos::core::shell::internal
