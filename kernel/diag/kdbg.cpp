#include "diag/kdbg.h"

#include "arch/x86_64/serial.h"
#include "log/klog.h"

namespace duetos::core
{

namespace
{

// Default mask. Overridable at compile-time via
// -DDUETOS_KDBG_DEFAULT_MASK=0x... so a build can opt into a fixed
// channel set without touching code.
#ifndef DUETOS_KDBG_DEFAULT_MASK
#define DUETOS_KDBG_DEFAULT_MASK 0
#endif

constinit u32 g_dbg_mask = DUETOS_KDBG_DEFAULT_MASK;

struct ChannelEntry
{
    DbgChannel ch;
    const char* name;
};

// Stable declaration order — also the iteration order for
// DbgListChannels and DbgChannelNext.
constexpr ChannelEntry kChannels[] = {
    {DbgChannel::Fat32Walker, "fat32-walker"},
    {DbgChannel::Fat32Append, "fat32-append"},
    {DbgChannel::Fat32Lookup, "fat32-lookup"},
    {DbgChannel::Fat32Cluster, "fat32-cluster"},
    {DbgChannel::Win32Thunk, "win32-thunk"},
    {DbgChannel::Win32Batch, "win32-batch"},
    {DbgChannel::Win32Wm, "win32-wm"},
    {DbgChannel::Win32Heap, "win32-heap"},
    {DbgChannel::PeLoad, "pe-load"},
    {DbgChannel::PeReloc, "pe-reloc"},
    {DbgChannel::PeImport, "pe-import"},
    {DbgChannel::PeExport, "pe-export"},
    {DbgChannel::DirectX, "directx"},
    {DbgChannel::Net, "net"},
    {DbgChannel::NetTcp, "net-tcp"},
    {DbgChannel::NetDns, "net-dns"},
    {DbgChannel::NetDhcp, "net-dhcp"},
    {DbgChannel::NetArp, "net-arp"},
    {DbgChannel::Sched, "sched"},
    {DbgChannel::SchedSwitch, "sched-switch"},
    {DbgChannel::Process, "process"},
    {DbgChannel::Ipc, "ipc"},
    {DbgChannel::Sandbox, "sandbox"},
    {DbgChannel::Mm, "mm"},
    {DbgChannel::MmFault, "mm-fault"},
    {DbgChannel::Storage, "storage"},
    {DbgChannel::Usb, "usb"},
    {DbgChannel::Gpu, "gpu"},
    {DbgChannel::Audio, "audio"},
    {DbgChannel::Gdi, "gdi"},
    {DbgChannel::Linux, "linux"},
    {DbgChannel::Health, "health"},
};

constexpr u32 kChannelCount = sizeof(kChannels) / sizeof(kChannels[0]);

bool CharCaseEqual(char a, char b)
{
    if (a >= 'A' && a <= 'Z')
        a = static_cast<char>(a + 32);
    if (b >= 'A' && b <= 'Z')
        b = static_cast<char>(b + 32);
    return a == b;
}

bool NameMatches(const char* a, const char* b)
{
    if (a == nullptr || b == nullptr)
        return false;
    while (*a != 0 && *b != 0)
    {
        if (!CharCaseEqual(*a, *b))
            return false;
        ++a;
        ++b;
    }
    return *a == 0 && *b == 0;
}

// Render a u64 to serial, hex form, with leading "0x" but no
// zero-padding. Reuses the kernel's existing SerialWriteHex which
// emits a fixed-width 16-nibble number — that's noisy for u8s, but
// keeps the output grep-shape stable across calls.
void WriteHex(u64 v)
{
    arch::SerialWriteHex(v);
}

// Compact KDBG line preamble:
//   [DBG/<channel>] <subsystem> :
// Deliberately avoids the klog timestamp helper so we don't pull
// klog.cpp internals into kdbg's TU; the timestamp would also blow
// up the per-line cost of slot-by-slot diagnostics where each line
// is already heavy.
void WritePrefix(const char* channel_name, const char* subsystem)
{
    arch::SerialWrite("[DBG/");
    arch::SerialWrite(channel_name);
    arch::SerialWrite("] ");
    arch::SerialWrite(subsystem);
    arch::SerialWrite(" : ");
}

const char* ChannelName(DbgChannel ch)
{
    for (u32 i = 0; i < kChannelCount; ++i)
    {
        if (kChannels[i].ch == ch)
            return kChannels[i].name;
    }
    return "(unknown)";
}

} // namespace

void DbgEnable(u32 mask)
{
    g_dbg_mask |= mask;
}

void DbgDisable(u32 mask)
{
    g_dbg_mask &= ~mask;
}

void DbgSet(u32 mask)
{
    g_dbg_mask = mask;
}

u32 DbgMask()
{
    return g_dbg_mask;
}

bool DbgIsEnabled(DbgChannel ch)
{
    return (g_dbg_mask & static_cast<u32>(ch)) != 0;
}

const char* DbgChannelName(DbgChannel ch)
{
    return ChannelName(ch);
}

DbgChannel DbgChannelByName(const char* name)
{
    if (name == nullptr)
        return DbgChannel::None;
    if (NameMatches(name, "all"))
        return DbgChannel::All;
    if (NameMatches(name, "none"))
        return DbgChannel::None;
    for (u32 i = 0; i < kChannelCount; ++i)
    {
        if (NameMatches(name, kChannels[i].name))
            return kChannels[i].ch;
    }
    return DbgChannel::None;
}

DbgChannel DbgChannelNext(DbgChannel cursor)
{
    if (cursor == DbgChannel::None)
        return kChannels[0].ch;
    for (u32 i = 0; i < kChannelCount - 1; ++i)
    {
        if (kChannels[i].ch == cursor)
            return kChannels[i + 1].ch;
    }
    return DbgChannel::None;
}

void DbgListChannels()
{
    Log(LogLevel::Info, "kdbg", "channels:");
    for (u32 i = 0; i < kChannelCount; ++i)
    {
        const bool on = (g_dbg_mask & static_cast<u32>(kChannels[i].ch)) != 0;
        // Render through SerialWrite directly — Log's "with string"
        // form would force a fixed message + label, less readable
        // here than aligned columns.
        arch::SerialWrite("  ");
        arch::SerialWrite(kChannels[i].name);
        arch::SerialWrite(on ? " : on\n" : " : off\n");
    }
    arch::SerialWrite("  mask=");
    WriteHex(g_dbg_mask);
    arch::SerialWrite("\n");
}

void DbgEmit(DbgChannel ch, const char* subsys, const char* msg)
{
    WritePrefix(ChannelName(ch), subsys);
    arch::SerialWrite(msg);
    arch::SerialWrite("\n");
}

void DbgEmitV(DbgChannel ch, const char* subsys, const char* msg, u64 v)
{
    WritePrefix(ChannelName(ch), subsys);
    arch::SerialWrite(msg);
    arch::SerialWrite(" val=");
    WriteHex(v);
    arch::SerialWrite("\n");
}

void DbgEmit2V(DbgChannel ch, const char* subsys, const char* msg, const char* la, u64 a, const char* lb, u64 b)
{
    WritePrefix(ChannelName(ch), subsys);
    arch::SerialWrite(msg);
    arch::SerialWrite(" ");
    arch::SerialWrite(la);
    arch::SerialWrite("=");
    WriteHex(a);
    arch::SerialWrite(" ");
    arch::SerialWrite(lb);
    arch::SerialWrite("=");
    WriteHex(b);
    arch::SerialWrite("\n");
}

void DbgEmit3V(DbgChannel ch, const char* subsys, const char* msg, const char* la, u64 a, const char* lb, u64 b,
               const char* lc, u64 c)
{
    WritePrefix(ChannelName(ch), subsys);
    arch::SerialWrite(msg);
    arch::SerialWrite(" ");
    arch::SerialWrite(la);
    arch::SerialWrite("=");
    WriteHex(a);
    arch::SerialWrite(" ");
    arch::SerialWrite(lb);
    arch::SerialWrite("=");
    WriteHex(b);
    arch::SerialWrite(" ");
    arch::SerialWrite(lc);
    arch::SerialWrite("=");
    WriteHex(c);
    arch::SerialWrite("\n");
}

void DbgEmit4V(DbgChannel ch, const char* subsys, const char* msg, const char* la, u64 a, const char* lb, u64 b,
               const char* lc, u64 c, const char* ld, u64 d)
{
    WritePrefix(ChannelName(ch), subsys);
    arch::SerialWrite(msg);
    arch::SerialWrite(" ");
    arch::SerialWrite(la);
    arch::SerialWrite("=");
    WriteHex(a);
    arch::SerialWrite(" ");
    arch::SerialWrite(lb);
    arch::SerialWrite("=");
    WriteHex(b);
    arch::SerialWrite(" ");
    arch::SerialWrite(lc);
    arch::SerialWrite("=");
    WriteHex(c);
    arch::SerialWrite(" ");
    arch::SerialWrite(ld);
    arch::SerialWrite("=");
    WriteHex(d);
    arch::SerialWrite("\n");
}

void DbgEmitS(DbgChannel ch, const char* subsys, const char* msg, const char* label, const char* str)
{
    WritePrefix(ChannelName(ch), subsys);
    arch::SerialWrite(msg);
    arch::SerialWrite(" ");
    arch::SerialWrite(label);
    arch::SerialWrite("=\"");
    arch::SerialWrite(str != nullptr ? str : "(null)");
    arch::SerialWrite("\"\n");
}

} // namespace duetos::core
