#include "net/wireless/wifi_diag.h"

#include "arch/x86_64/serial.h"
#include "core/panic.h"
#include "sync/spinlock.h"
#include "time/tick.h"

namespace duetos::net::wireless::diag
{

namespace
{

constinit Event g_ring[kRingCapacity] = {};
constinit u32 g_head = 0;     // next write slot
constinit u32 g_count = 0;    // valid entries (≤ capacity)
constinit u64 g_total = 0;    // monotonic recorded count
constinit u64 g_dropped = 0;  // total events overwritten
constinit u32 g_seq_next = 0; // next sequence number
constinit bool g_init_done = false;
constinit duetos::sync::SpinLock g_lock = {};

void CopyBounded(char* dst, u32 dst_cap, const char* src)
{
    if (dst == nullptr || dst_cap == 0)
        return;
    u32 i = 0;
    if (src != nullptr)
    {
        for (; i + 1 < dst_cap && src[i] != '\0'; ++i)
        {
            const u8 c = static_cast<u8>(src[i]);
            // Sanitize — diag dumps land in serial logs and panic
            // dumps that may be pasted into bug reports. Strip
            // anything that isn't 7-bit printable.
            dst[i] = (c >= 0x20 && c < 0x7F) ? src[i] : '?';
        }
    }
    dst[i] = '\0';
}

u8 CurrentCpuIndex()
{
    // The wireless stack runs on the BSP today (no per-CPU
    // wireless threads yet). Once it does, swap this for the
    // per-CPU accessor; for now leave as 0 so a panic-time
    // dump on the BSP looks consistent.
    return 0;
}

} // namespace

const char* LayerName(Layer l)
{
    switch (l)
    {
    case Layer::Driver:
        return "drv";
    case Layer::FwUpload:
        return "fwup";
    case Layer::Rings:
        return "ring";
    case Layer::Mlme:
        return "mlme";
    case Layer::Eapol:
        return "eap";
    case Layer::KeyMgmt:
        return "key";
    case Layer::Tx:
        return "tx ";
    case Layer::Rx:
        return "rx ";
    case Layer::Wdev:
        return "wdev";
    case Layer::Diag:
        return "diag";
    default:
        return "??";
    }
}

void Init()
{
    if (g_init_done)
        return;
    auto flags = duetos::sync::SpinLockAcquire(g_lock);
    g_head = 0;
    g_count = 0;
    g_total = 0;
    g_dropped = 0;
    g_seq_next = 0;
    g_init_done = true;
    duetos::sync::SpinLockRelease(g_lock, flags);
    arch::SerialWrite("[wifi-diag] online — ring capacity ");
    arch::SerialWriteHex(kRingCapacity);
    arch::SerialWrite(" events\n");
}

void Record(Layer layer, const char* tag, u64 v0, u64 v1, u64 v2, u32 status, const char* detail)
{
    if (!g_init_done)
        Init();

    auto flags = duetos::sync::SpinLockAcquire(g_lock);
    Event& e = g_ring[g_head];
    e.timestamp_ticks = duetos::time::TickCount();
    e.sequence = g_seq_next++;
    e.cpu = CurrentCpuIndex();
    e.layer = layer;
    e.reserved0 = 0;
    e.reserved1 = 0;
    CopyBounded(e.tag, sizeof(e.tag), tag);
    CopyBounded(e.detail, sizeof(e.detail), detail);
    e.v0 = v0;
    e.v1 = v1;
    e.v2 = v2;
    e.status = status;

    g_head = (g_head + 1u) % kRingCapacity;
    if (g_count < kRingCapacity)
        ++g_count;
    else
        ++g_dropped;
    ++g_total;
    duetos::sync::SpinLockRelease(g_lock, flags);
}

void RecordOk(Layer layer, const char* tag, u64 v0, u64 v1, u64 v2, const char* detail)
{
    Record(layer, tag, v0, v1, v2, /*status=*/0, detail);
}

void RecordErr(Layer layer, const char* tag, u32 status_code, u64 v0, u64 v1, u64 v2, const char* detail)
{
    Record(layer, tag, v0, v1, v2, status_code, detail);
}

u32 EventCount()
{
    return g_count;
}

bool EventAt(u32 index, Event* out)
{
    if (out == nullptr || index >= g_count)
        return false;
    auto flags = duetos::sync::SpinLockAcquire(g_lock);
    const u32 oldest = (g_head + kRingCapacity - g_count) % kRingCapacity;
    const u32 slot = (oldest + index) % kRingCapacity;
    *out = g_ring[slot];
    duetos::sync::SpinLockRelease(g_lock, flags);
    return true;
}

u64 TotalRecorded()
{
    return g_total;
}

u64 TotalDropped()
{
    return g_dropped;
}

void Clear()
{
    auto flags = duetos::sync::SpinLockAcquire(g_lock);
    g_head = 0;
    g_count = 0;
    duetos::sync::SpinLockRelease(g_lock, flags);
}

void Dump(u32 max_events)
{
    arch::SerialWrite("[wifi-diag] ====== ring dump ======\n");
    arch::SerialWrite("[wifi-diag] retained=");
    arch::SerialWriteHex(g_count);
    arch::SerialWrite(" total=");
    arch::SerialWriteHex(g_total);
    arch::SerialWrite(" dropped=");
    arch::SerialWriteHex(g_dropped);
    arch::SerialWrite("\n");

    const u32 to_dump = (max_events == 0 || max_events > g_count) ? g_count : max_events;
    const u32 start = (g_count > to_dump) ? (g_count - to_dump) : 0u;
    for (u32 i = start; i < g_count; ++i)
    {
        Event e{};
        if (!EventAt(i, &e))
            continue;
        arch::SerialWrite("[wifi-diag] #");
        arch::SerialWriteHex(e.sequence);
        arch::SerialWrite(" t=");
        arch::SerialWriteHex(e.timestamp_ticks);
        arch::SerialWrite(" cpu=");
        arch::SerialWriteHex(e.cpu);
        arch::SerialWrite(" ");
        arch::SerialWrite(LayerName(e.layer));
        arch::SerialWrite(" tag=");
        arch::SerialWrite(e.tag);
        if (e.detail[0] != '\0')
        {
            arch::SerialWrite(" \"");
            arch::SerialWrite(e.detail);
            arch::SerialWrite("\"");
        }
        arch::SerialWrite(" v0=");
        arch::SerialWriteHex(e.v0);
        arch::SerialWrite(" v1=");
        arch::SerialWriteHex(e.v1);
        arch::SerialWrite(" v2=");
        arch::SerialWriteHex(e.v2);
        arch::SerialWrite(" st=");
        arch::SerialWriteHex(e.status);
        arch::SerialWrite("\n");
    }
    arch::SerialWrite("[wifi-diag] ====== end ======\n");
}

} // namespace duetos::net::wireless::diag
