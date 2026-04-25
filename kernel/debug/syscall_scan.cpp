#include "syscall_scan.h"

#include "../arch/x86_64/serial.h"
#include "../core/syscall_names.h"
#include "../subsystems/linux/linux_syscall_table_generated.h"
#include "../subsystems/translation/translate.h"
#include "inspect.h"

namespace duetos::debug
{

namespace
{

// How far back from a syscall-issuing opcode we'll walk looking
// for a `mov eax, imm32`. MSVC / gcc / clang all emit the
// immediate within a handful of bytes of the dispatch — 32 is
// generous. Going further inflates false positives.
constexpr u64 kMovEaxLookback = 32;

// Walk backward from `site_off` in `bytes` looking for the
// canonical `mov eax, imm32` encoding — opcode B8 followed by
// four little-endian bytes. Returns true on hit, writing the
// immediate to `*out_nr`. False positives are possible (we don't
// track REX / prefix boundaries); they surface as "number
// recovered but name lookup fails in all three tables" — useful
// data in its own right.
bool RecoverSyscallNumber(const u8* bytes, u64 size, u64 site_off, u32* out_nr)
{
    if (site_off == 0)
        return false;
    // A `mov eax, imm32` is 5 bytes: B8 ii ii ii ii. We need at
    // least 5 bytes of lookback room.
    const u64 lo = (site_off > kMovEaxLookback) ? (site_off - kMovEaxLookback) : 0;
    for (u64 i = site_off; i >= lo + 5; --i)
    {
        // Check for `B8 xx xx xx xx` at i-5 .. i-1.
        const u64 op_at = i - 5;
        if (op_at >= size)
            continue;
        if (bytes[op_at] != 0xB8)
        {
            if (i == lo + 5)
                break;
            continue;
        }
        const u32 imm = static_cast<u32>(bytes[op_at + 1]) | (static_cast<u32>(bytes[op_at + 2]) << 8) |
                        (static_cast<u32>(bytes[op_at + 3]) << 16) | (static_cast<u32>(bytes[op_at + 4]) << 24);
        *out_nr = imm;
        return true;
    }
    return false;
}

void ClassifySite(SyscallSite& site)
{
    if (!site.nr_recovered)
        return;
    auto& c = site.coverage;
    // Linux: only meaningful for `syscall` (shared with NT — we
    // look up both).
    c.linux_name = subsystems::translation::LinuxName(site.nr);
    if (c.linux_name != nullptr)
    {
        c.known_linux = true;
        // Did the primary Linux dispatcher pick up a handler?
        const auto* e = subsystems::linux::LinuxSyscallLookup(site.nr);
        if (e != nullptr && e->state == subsystems::linux::HandlerState::Implemented)
        {
            c.impl_linux = true;
        }
    }
    // NT: only meaningful for `syscall` / `int 0x2E`.
    if (site.kind == SyscallSiteKind::Syscall || site.kind == SyscallSiteKind::Int2E)
    {
        c.nt_name = subsystems::translation::NtName(site.nr);
        if (c.nt_name != nullptr)
            c.known_nt = true;
    }
    // Native: only meaningful for `int 0x80`.
    if (site.kind == SyscallSiteKind::Int80)
    {
        c.native_name = core::SyscallNumberName(site.nr);
        if (c.native_name != nullptr)
        {
            c.known_native = true;
            c.impl_native = true; // if it has a native name, it's dispatched
        }
    }
}

void LogSite(const SyscallSite& site)
{
    using arch::SerialWrite;
    using arch::SerialWriteHex;
    SerialWrite("[inspect-sc] site va=");
    SerialWriteHex(site.va);
    SerialWrite(" kind=");
    switch (site.kind)
    {
    case SyscallSiteKind::Syscall:
        SerialWrite("syscall");
        break;
    case SyscallSiteKind::Int80:
        SerialWrite("int80");
        break;
    case SyscallSiteKind::Int2E:
        SerialWrite("int2e");
        break;
    case SyscallSiteKind::Sysenter:
        SerialWrite("sysenter");
        break;
    default:
        SerialWrite("unknown");
        break;
    }
    if (site.nr_recovered)
    {
        SerialWrite(" nr=");
        SerialWriteHex(site.nr);
        const auto& c = site.coverage;
        if (c.linux_name != nullptr)
        {
            SerialWrite(" linux=\"");
            SerialWrite(c.linux_name);
            SerialWrite(c.impl_linux ? "\"(impl)" : "\"(unimpl)");
        }
        if (c.nt_name != nullptr)
        {
            SerialWrite(" nt=\"");
            SerialWrite(c.nt_name);
            SerialWrite("\"");
        }
        if (c.native_name != nullptr)
        {
            SerialWrite(" native=\"");
            SerialWrite(c.native_name);
            SerialWrite("\"");
        }
        if (!c.known_linux && !c.known_nt && !c.known_native)
        {
            SerialWrite(" <no-table-hit>");
        }
    }
    else
    {
        SerialWrite(" nr=<no mov eax,imm32 within 32B>");
    }
    SerialWrite("\n");
}

void UpdateTallies(const SyscallSite& site, SyscallScanReport& r)
{
    ++r.total_sites;
    switch (site.kind)
    {
    case SyscallSiteKind::Syscall:
        ++r.kind_syscall;
        break;
    case SyscallSiteKind::Int80:
        ++r.kind_int80;
        break;
    case SyscallSiteKind::Int2E:
        ++r.kind_int2e;
        break;
    case SyscallSiteKind::Sysenter:
        ++r.kind_sysenter;
        break;
    default:
        break;
    }
    if (site.nr_recovered)
    {
        ++r.recovered;
        const auto& c = site.coverage;
        if (c.known_linux)
            ++r.known_linux;
        if (c.known_nt)
            ++r.known_nt;
        if (c.known_native)
            ++r.known_native;
        if (c.impl_linux)
            ++r.impl_linux;
        if (c.impl_native)
            ++r.impl_native;
        if (!c.known_linux && !c.known_nt && !c.known_native)
            ++r.unknown;
    }
}

void LogSummary(const SyscallScanReport& r)
{
    using arch::SerialWrite;
    using arch::SerialWriteHex;
    SerialWrite("[inspect-sc] summary base=");
    SerialWriteHex(r.region_base_va);
    SerialWrite(" size=");
    SerialWriteHex(r.region_size);
    SerialWrite(" sites=");
    SerialWriteHex(r.total_sites);
    SerialWrite(" recovered=");
    SerialWriteHex(r.recovered);
    SerialWrite(" linux_known=");
    SerialWriteHex(r.known_linux);
    SerialWrite(" (impl=");
    SerialWriteHex(r.impl_linux);
    SerialWrite(") nt_known=");
    SerialWriteHex(r.known_nt);
    SerialWrite(" native_known=");
    SerialWriteHex(r.known_native);
    SerialWrite(" (impl=");
    SerialWriteHex(r.impl_native);
    SerialWrite(") unknown=");
    SerialWriteHex(r.unknown);
    SerialWrite("\n[inspect-sc] summary kinds: syscall=");
    SerialWriteHex(r.kind_syscall);
    SerialWrite(" int80=");
    SerialWriteHex(r.kind_int80);
    SerialWrite(" int2e=");
    SerialWriteHex(r.kind_int2e);
    SerialWrite(" sysenter=");
    SerialWriteHex(r.kind_sysenter);
    if (r.sites_dropped > 0)
    {
        SerialWrite(" dropped=");
        SerialWriteHex(r.sites_dropped);
    }
    SerialWrite("\n");
}

} // namespace

SyscallScanReport SyscallScanRegion(const u8* bytes, u64 size, u64 base_va)
{
    SyscallScanReport r{};
    r.region_base_va = base_va;
    r.region_size = size;
    if (bytes == nullptr || size < 2)
        return r;

    arch::SerialWrite("[inspect-sc] begin base=");
    arch::SerialWriteHex(base_va);
    arch::SerialWrite(" size=");
    arch::SerialWriteHex(size);
    arch::SerialWrite("\n");

    u32 emitted = 0;
    // Walk byte-by-byte. Classifier looks at bytes[i] + bytes[i+1]
    // to decide whether this position is a syscall idiom. No state
    // between iterations — false positives (a `0F 05` inside a
    // longer instruction's operand) are rare enough that the
    // caller can eyeball the log and discount them.
    for (u64 i = 0; i + 1 < size; ++i)
    {
        const u8 b0 = bytes[i];
        const u8 b1 = bytes[i + 1];
        SyscallSiteKind kind = SyscallSiteKind::Unknown;
        if (b0 == 0x0F && b1 == 0x05)
            kind = SyscallSiteKind::Syscall;
        else if (b0 == 0xCD && b1 == 0x80)
            kind = SyscallSiteKind::Int80;
        else if (b0 == 0xCD && b1 == 0x2E)
            kind = SyscallSiteKind::Int2E;
        else if (b0 == 0x0F && b1 == 0x34)
            kind = SyscallSiteKind::Sysenter;
        if (kind == SyscallSiteKind::Unknown)
            continue;

        SyscallSite site{};
        site.va = base_va + i;
        site.kind = kind;
        site.nr_recovered = RecoverSyscallNumber(bytes, size, i, &site.nr);
        ClassifySite(site);
        UpdateTallies(site, r);
        if (emitted < kMaxSitesLogged)
        {
            LogSite(site);
            ++emitted;
        }
        else
        {
            ++r.sites_dropped;
        }
        // Skip ahead by the opcode length so we don't double-count
        // the second byte of a two-byte match as the start of a new
        // one. All four recognized idioms are 2 bytes.
        ++i;
    }

    LogSummary(r);
    return r;
}

// Emitted by the linker script. Addresses of the kernel .text
// section boundaries.
extern "C" const u8 _text_start[];
extern "C" const u8 _text_end[];

SyscallScanReport SyscallScanKernelText()
{
    const u64 base = reinterpret_cast<u64>(_text_start);
    const u64 end = reinterpret_cast<u64>(_text_end);
    if (end <= base)
    {
        arch::SerialWrite("[inspect-sc] kernel text region invalid\n");
        return SyscallScanReport{};
    }
    return SyscallScanRegion(_text_start, end - base, base);
}

SyscallScanReport SyscallScanFile(const char* path)
{
    using arch::SerialWrite;
    SyscallScanReport r{};

    const u8* bytes = nullptr;
    u64 len = 0;
    if (!InspectReadFatFile(path, &bytes, &len))
        return r;

    // Auto-detect using the shared PE / ELF locators.
    InspectSection sec{};
    if (InspectFindPeText(bytes, len, &sec))
    {
        SerialWrite("[inspect-sc] file: PE, scanning .text va=");
        arch::SerialWriteHex(sec.base_va);
        SerialWrite("\n");
        return SyscallScanRegion(bytes + sec.file_off, sec.size, sec.base_va);
    }
    if (InspectFindElfText(bytes, len, &sec))
    {
        SerialWrite("[inspect-sc] file: ELF, scanning PT_LOAD (X) vaddr=");
        arch::SerialWriteHex(sec.base_va);
        SerialWrite("\n");
        return SyscallScanRegion(bytes + sec.file_off, sec.size, sec.base_va);
    }
    // Raw bytes — scan the whole file with base_va=0.
    SerialWrite("[inspect-sc] file: no PE/ELF header, scanning raw bytes\n");
    return SyscallScanRegion(bytes, len, 0);
}

} // namespace duetos::debug
