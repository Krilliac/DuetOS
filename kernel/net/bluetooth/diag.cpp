#include "net/bluetooth/diag.h"

#include "arch/x86_64/serial.h"
#include "core/panic.h"
#include "log/klog.h"
#include "sync/spinlock.h"

namespace duetos::net::bluetooth
{

namespace
{

// One slot per attached controller + a small ring of recent events.
// Both live behind a single spinlock — this is the only mutator
// path on every byte the transport driver delivers, so we do not
// optimise it for high contention. Real-world Bluetooth chips
// deliver a few events per second per adapter.
struct DiagState
{
    BluetoothAdapter adapters[kBluetoothMaxAdapters];
    BluetoothEventRecord rings[kBluetoothMaxAdapters][kBluetoothEventRingSize];
    u32 ring_head[kBluetoothMaxAdapters]; // next write slot
    u32 ring_count[kBluetoothMaxAdapters];
    u64 next_seq;
    bool init_done;
};

constinit DiagState g_state{};
constinit duetos::sync::SpinLock g_diag_lock{};

void CopyName(char* dst, const char* src)
{
    if (dst == nullptr)
        return;
    if (src == nullptr)
    {
        dst[0] = '\0';
        return;
    }
    u32 i = 0;
    for (; i < kBluetoothNameMax && src[i] != '\0'; ++i)
    {
        const u8 c = static_cast<u8>(src[i]);
        dst[i] = (c >= 0x20 && c < 0x7F) ? static_cast<char>(c) : '?';
    }
    dst[i] = '\0';
}

bool ValidSlot(u32 slot)
{
    return slot < kBluetoothMaxAdapters;
}

} // namespace

const char* BluetoothTransportName(BluetoothTransport t)
{
    switch (t)
    {
    case BluetoothTransport::Unknown:
        return "?";
    case BluetoothTransport::Usb:
        return "btusb";
    case BluetoothTransport::Uart:
        return "btuart";
    case BluetoothTransport::Sdio:
        return "btsdio";
    case BluetoothTransport::Loopback:
        return "loopback";
    }
    return "?";
}

void BluetoothDiagInit()
{
    auto flags = duetos::sync::SpinLockAcquire(g_diag_lock);
    if (g_state.init_done)
    {
        duetos::sync::SpinLockRelease(g_diag_lock, flags);
        return;
    }
    for (u32 i = 0; i < kBluetoothMaxAdapters; ++i)
    {
        g_state.adapters[i] = {};
        for (u32 j = 0; j < kBluetoothEventRingSize; ++j)
            g_state.rings[i][j] = {};
        g_state.ring_head[i] = 0;
        g_state.ring_count[i] = 0;
    }
    g_state.next_seq = 0;
    g_state.init_done = true;
    duetos::sync::SpinLockRelease(g_diag_lock, flags);
    KLOG_INFO("net/bluetooth/diag", "online");
}

::duetos::core::Result<u32> BluetoothDiagRegisterAdapter(BluetoothTransport transport)
{
    BluetoothDiagInit();
    auto flags = duetos::sync::SpinLockAcquire(g_diag_lock);
    for (u32 i = 0; i < kBluetoothMaxAdapters; ++i)
    {
        if (g_state.adapters[i].live)
            continue;
        g_state.adapters[i] = {};
        g_state.adapters[i].live = true;
        g_state.adapters[i].transport = transport;
        g_state.ring_head[i] = 0;
        g_state.ring_count[i] = 0;
        duetos::sync::SpinLockRelease(g_diag_lock, flags);
        return i;
    }
    duetos::sync::SpinLockRelease(g_diag_lock, flags);
    return ::duetos::core::Err{::duetos::core::ErrorCode::OutOfMemory};
}

void BluetoothDiagUnregisterAdapter(u32 slot)
{
    if (!ValidSlot(slot))
        return;
    auto flags = duetos::sync::SpinLockAcquire(g_diag_lock);
    g_state.adapters[slot] = {};
    g_state.ring_head[slot] = 0;
    g_state.ring_count[slot] = 0;
    duetos::sync::SpinLockRelease(g_diag_lock, flags);
}

void BluetoothDiagStampLocalVersion(u32 slot, const HciReadLocalVersion& v)
{
    if (!ValidSlot(slot))
        return;
    auto flags = duetos::sync::SpinLockAcquire(g_diag_lock);
    if (g_state.adapters[slot].live)
    {
        g_state.adapters[slot].manufacturer_id = v.manufacturer_name;
        g_state.adapters[slot].hci_version = v.hci_version;
        g_state.adapters[slot].lmp_version = v.lmp_version;
    }
    duetos::sync::SpinLockRelease(g_diag_lock, flags);
}

void BluetoothDiagStampBdAddr(u32 slot, const HciReadBdAddr& a)
{
    if (!ValidSlot(slot))
        return;
    auto flags = duetos::sync::SpinLockAcquire(g_diag_lock);
    if (g_state.adapters[slot].live)
    {
        for (u32 i = 0; i < 6; ++i)
            g_state.adapters[slot].bd_addr[i] = a.bd_addr[i];
        g_state.adapters[slot].bd_addr_valid = (a.status == 0);
    }
    duetos::sync::SpinLockRelease(g_diag_lock, flags);
}

void BluetoothDiagSetName(u32 slot, const char* name)
{
    if (!ValidSlot(slot))
        return;
    auto flags = duetos::sync::SpinLockAcquire(g_diag_lock);
    if (g_state.adapters[slot].live)
        CopyName(g_state.adapters[slot].name, name);
    duetos::sync::SpinLockRelease(g_diag_lock, flags);
}

void BluetoothDiagRecordEvent(u32 slot, const HciEventHeader& evt)
{
    if (!ValidSlot(slot))
        return;
    auto flags = duetos::sync::SpinLockAcquire(g_diag_lock);
    BluetoothAdapter& a = g_state.adapters[slot];
    if (!a.live)
    {
        duetos::sync::SpinLockRelease(g_diag_lock, flags);
        return;
    }

    BluetoothEventRecord rec{};
    rec.sequence = g_state.next_seq++;
    rec.event_code = evt.event_code;
    rec.parameter_total_length = evt.parameter_total_length;

    // Best-effort fill of the per-event-kind metadata. The full
    // parse stays in the transport driver's IRQ path; we only
    // peek a handful of bytes for the diag display.
    if (evt.event_code == kEvtCommandComplete && evt.parameter_total_length >= 3)
    {
        rec.command_opcode =
            static_cast<u16>(static_cast<u16>(evt.parameters[1]) | (static_cast<u16>(evt.parameters[2]) << 8));
        ++a.cmd_complete_seen;
    }
    else if (evt.event_code == kEvtCommandStatus && evt.parameter_total_length >= 4)
    {
        rec.status = evt.parameters[0];
        rec.command_opcode =
            static_cast<u16>(static_cast<u16>(evt.parameters[2]) | (static_cast<u16>(evt.parameters[3]) << 8));
        ++a.cmd_status_seen;
    }
    else if (evt.event_code == kEvtDisconnectionComplete)
    {
        ++a.disconnection_seen;
    }
    else if (evt.event_code == kEvtLeMetaEvent && evt.parameter_total_length >= 1)
    {
        rec.le_subevent = evt.parameters[0];
        ++a.le_meta_seen;
    }
    else
    {
        ++a.unknown_seen;
    }

    ++a.events_seen;
    g_state.rings[slot][g_state.ring_head[slot]] = rec;
    g_state.ring_head[slot] = (g_state.ring_head[slot] + 1) % kBluetoothEventRingSize;
    if (g_state.ring_count[slot] < kBluetoothEventRingSize)
        ++g_state.ring_count[slot];
    else
        ++a.ring_overflows;

    duetos::sync::SpinLockRelease(g_diag_lock, flags);
}

u32 BluetoothDiagAdapterCount()
{
    u32 count = 0;
    auto flags = duetos::sync::SpinLockAcquire(g_diag_lock);
    for (u32 i = 0; i < kBluetoothMaxAdapters; ++i)
        if (g_state.adapters[i].live)
            ++count;
    duetos::sync::SpinLockRelease(g_diag_lock, flags);
    return count;
}

const BluetoothAdapter& BluetoothDiagAdapter(u32 slot)
{
    KASSERT(slot < kBluetoothMaxAdapters, "net/bluetooth/diag", "adapter slot out of range");
    return g_state.adapters[slot];
}

u32 BluetoothDiagEventRingFill(u32 slot)
{
    if (!ValidSlot(slot))
        return 0;
    return g_state.ring_count[slot];
}

const BluetoothEventRecord& BluetoothDiagEventRingAt(u32 slot, u32 index)
{
    KASSERT(slot < kBluetoothMaxAdapters, "net/bluetooth/diag", "event slot out of range");
    KASSERT(index < g_state.ring_count[slot], "net/bluetooth/diag", "event index out of range");
    const u32 oldest =
        (g_state.ring_head[slot] + kBluetoothEventRingSize - g_state.ring_count[slot]) % kBluetoothEventRingSize;
    return g_state.rings[slot][(oldest + index) % kBluetoothEventRingSize];
}

namespace
{

void EqU64(u64 actual, u64 expected, const char* what)
{
    if (actual == expected)
        return;
    arch::SerialWrite("[bt-diag] MISMATCH ");
    arch::SerialWrite(what);
    arch::SerialWrite(" actual=");
    arch::SerialWriteHex(actual);
    arch::SerialWrite(" expected=");
    arch::SerialWriteHex(expected);
    arch::SerialWrite("\n");
    core::PanicWithValue("net/bluetooth/diag", "BT diag self-test mismatch", actual);
}

} // namespace

void BluetoothDiagSelfTest()
{
    BluetoothDiagInit();

    // Wipe any state from previous runs (init is idempotent — but we
    // need an empty slate for the assertions below).
    {
        auto flags = duetos::sync::SpinLockAcquire(g_diag_lock);
        for (u32 i = 0; i < kBluetoothMaxAdapters; ++i)
        {
            g_state.adapters[i] = {};
            g_state.ring_head[i] = 0;
            g_state.ring_count[i] = 0;
        }
        g_state.next_seq = 0;
        duetos::sync::SpinLockRelease(g_diag_lock, flags);
    }

    auto reg = BluetoothDiagRegisterAdapter(BluetoothTransport::Loopback);
    EqU64(u64(reg.has_value() ? 1 : 0), 1, "register adapter ok");
    const u32 slot = reg.value();
    EqU64(slot, 0, "first slot is 0");

    // Stamp identity.
    HciReadLocalVersion v{};
    v.status = 0;
    v.hci_version = 0x0C;
    v.hci_revision = 0x0123;
    v.lmp_version = 0x0C;
    v.manufacturer_name = 0x000F;
    v.lmp_subversion = 0x4567;
    BluetoothDiagStampLocalVersion(slot, v);

    HciReadBdAddr addr{};
    addr.status = 0;
    addr.bd_addr[0] = 0x66;
    addr.bd_addr[1] = 0x55;
    addr.bd_addr[2] = 0x44;
    addr.bd_addr[3] = 0x33;
    addr.bd_addr[4] = 0x22;
    addr.bd_addr[5] = 0x11;
    BluetoothDiagStampBdAddr(slot, addr);
    BluetoothDiagSetName(slot, "selftest");

    const BluetoothAdapter& a = BluetoothDiagAdapter(slot);
    EqU64(a.manufacturer_id, 0x000F, "adapter manufacturer");
    EqU64(a.hci_version, 0x0C, "adapter hci_version");
    EqU64(u64(a.bd_addr_valid ? 1 : 0), 1, "bd_addr_valid");
    EqU64(a.bd_addr[0], 0x66, "bd_addr[0]");
    EqU64(a.bd_addr[5], 0x11, "bd_addr[5]");
    EqU64(u64(a.name[0]), u64('s'), "name[0]");

    // Push 3 synthetic events: Disconnection_Complete, Command_Complete
    // for HCI_Reset, LE Meta advertising report.
    {
        u8 evt_disc_buf[6] = {kEvtDisconnectionComplete, 4, 0, 0x40, 0, 0x13};
        HciEventHeader h;
        EqU64(u64(HciParseEventHeader(evt_disc_buf, sizeof(evt_disc_buf), &h) ? 1 : 0), 1, "parse disc evt");
        BluetoothDiagRecordEvent(slot, h);
    }
    {
        u8 evt_cc_buf[6] = {kEvtCommandComplete, 4, 1, 0, 0, 0};
        const u16 op = HciOpcode(kOgfHostController, kOcfReset);
        evt_cc_buf[3] = u8(op & 0xFF);
        evt_cc_buf[4] = u8((op >> 8) & 0xFF);
        evt_cc_buf[5] = 0; // status
        HciEventHeader h;
        EqU64(u64(HciParseEventHeader(evt_cc_buf, sizeof(evt_cc_buf), &h) ? 1 : 0), 1, "parse cc evt");
        BluetoothDiagRecordEvent(slot, h);
    }
    {
        u8 evt_le_buf[4] = {kEvtLeMetaEvent, 2, kLeSubEvtAdvertisingReport, 0};
        HciEventHeader h;
        EqU64(u64(HciParseEventHeader(evt_le_buf, sizeof(evt_le_buf), &h) ? 1 : 0), 1, "parse le evt");
        BluetoothDiagRecordEvent(slot, h);
    }

    EqU64(BluetoothDiagAdapter(slot).events_seen, 3, "events_seen");
    EqU64(BluetoothDiagAdapter(slot).cmd_complete_seen, 1, "cmd_complete_seen");
    EqU64(BluetoothDiagAdapter(slot).disconnection_seen, 1, "disconnection_seen");
    EqU64(BluetoothDiagAdapter(slot).le_meta_seen, 1, "le_meta_seen");
    EqU64(BluetoothDiagEventRingFill(slot), 3, "ring fill 3");
    EqU64(BluetoothDiagEventRingAt(slot, 0).event_code, kEvtDisconnectionComplete, "ring[0] code");
    EqU64(BluetoothDiagEventRingAt(slot, 1).event_code, kEvtCommandComplete, "ring[1] code");
    EqU64(BluetoothDiagEventRingAt(slot, 1).command_opcode, HciOpcode(kOgfHostController, kOcfReset), "ring[1] opcode");
    EqU64(BluetoothDiagEventRingAt(slot, 2).le_subevent, kLeSubEvtAdvertisingReport, "ring[2] le_sub");

    // Overflow the ring (push 32+ more events) and assert overflow
    // counter increments without losing the per-event-kind tallies.
    for (u32 i = 0; i < kBluetoothEventRingSize + 5; ++i)
    {
        u8 evt[2] = {kEvtNumberOfCompletedPackets, 0};
        HciEventHeader h;
        HciParseEventHeader(evt, sizeof(evt), &h);
        BluetoothDiagRecordEvent(slot, h);
    }
    EqU64(BluetoothDiagEventRingFill(slot), kBluetoothEventRingSize, "ring saturated at cap");
    EqU64(u64(BluetoothDiagAdapter(slot).ring_overflows > 0 ? 1 : 0), 1, "overflow counter bumped");

    // Adapter-count accessor.
    EqU64(BluetoothDiagAdapterCount(), 1, "adapter count == 1");
    BluetoothDiagUnregisterAdapter(slot);
    EqU64(BluetoothDiagAdapterCount(), 0, "adapter count == 0 after unregister");

    arch::SerialWrite("[bt-diag] selftest pass\n");
}

} // namespace duetos::net::bluetooth
