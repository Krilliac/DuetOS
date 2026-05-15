#include "drivers/usb/btusb.h"

#include "arch/x86_64/serial.h"
#include "core/panic.h"
#include "drivers/usb/usb.h"
#include "drivers/usb/xhci.h"
#include "log/klog.h"
#include "mm/frame_allocator.h"
#include "mm/page.h"
#include "net/bluetooth/diag.h"
#include "net/bluetooth/hci.h"
#include "net/bluetooth/hid.h"
#include "sched/sched.h"

namespace duetos::drivers::usb
{

namespace
{

// EP0 request-type bytes (mirrors cdc_ecm.cpp's local set).
constexpr u8 kReqTypeStandardIn = 0x80;  // dev->host | standard | device
constexpr u8 kReqTypeStandardOut = 0x00; // host->dev | standard | device

constexpr u8 kUsbReqGetDescriptor = 0x06;
constexpr u8 kUsbReqSetConfiguration = 0x09;
constexpr u8 kDescTypeConfig = 0x02;
constexpr u8 kDescTypeInterface = 0x04;
constexpr u8 kDescTypeEndpoint = 0x05;

// USB endpoint bmAttributes transfer-type field (bits 1:0).
constexpr u8 kEpXferBulk = 0x02;
constexpr u8 kEpXferInterrupt = 0x03;

// Bluetooth primary interface identity (Vol 4 Part B §2.1).
constexpr u8 kBtIfaceClass = 0xE0;
constexpr u8 kBtIfaceSubclass = 0x01;
constexpr u8 kBtIfaceProtocol = 0x01;

constexpr u32 kAclRxBufBytes = 4096;

// Minimum bytes for a hand-off to the HID stack: a valid HCI ACL
// packet is at least its 4-byte header (handle + length).
constexpr u32 kAclMinBytes = 4;

struct BtusbState
{
    bool online;
    u8 slot_id;
    u8 acl_in_ep;
    u16 acl_in_mps;
    u8 acl_out_ep;
    u16 acl_out_mps;
    u8 event_in_ep; // located, not drained in v0 (GAP)
    mm::PhysAddr rx_buf_phys;
    u8* rx_buf_virt;
    BtusbStats stats;
};

constinit BtusbState g_state{};

// Pure: a received bulk-IN length is worth handing to the HID
// stack iff it could contain at least an ACL header. Exposed shape
// so the self-test can pin the boundary.
bool AclAcceptLen(u32 got)
{
    return got >= kAclMinBytes;
}

// Pure: walk a USB configuration descriptor and classify the
// Bluetooth primary interface's endpoints. Returns true iff the
// ACL bulk-IN + bulk-OUT pair (mandatory for the keyboard data
// path) were found. The interrupt-IN (events) endpoint is recorded
// when present but is not required by v0 (see GAP). Bounds-checked
// against `len`; a malformed descriptor yields false.
bool ClassifyEndpoints(const u8* cfg, u32 len, u8* acl_in, u16* acl_in_mps, u8* acl_out, u16* acl_out_mps, u8* event_in)
{
    if (cfg == nullptr || acl_in == nullptr || acl_out == nullptr || event_in == nullptr)
        return false;
    *acl_in = 0;
    *acl_out = 0;
    *event_in = 0;
    *acl_in_mps = 0;
    *acl_out_mps = 0;

    bool in_bt_iface = false;
    bool got_in = false;
    bool got_out = false;
    u32 off = 0;
    while (off + 2 <= len)
    {
        const u8 desc_len = cfg[off];
        const u8 desc_type = cfg[off + 1];
        if (desc_len < 2 || off + desc_len > len)
            break;

        if (desc_type == kDescTypeInterface && desc_len >= 9)
        {
            const u8 if_class = cfg[off + 5];
            const u8 if_sub = cfg[off + 6];
            const u8 if_proto = cfg[off + 7];
            in_bt_iface = (if_class == kBtIfaceClass && if_sub == kBtIfaceSubclass && if_proto == kBtIfaceProtocol);
        }
        else if (desc_type == kDescTypeEndpoint && desc_len >= 7 && in_bt_iface)
        {
            const u8 ep_addr = cfg[off + 2];
            const u8 attr = cfg[off + 3];
            const u16 mps = u16(u16(cfg[off + 4]) | (u16(cfg[off + 5]) << 8));
            const bool is_in = (ep_addr & 0x80) != 0;
            switch (attr & 0x03)
            {
            case kEpXferBulk:
                if (is_in)
                {
                    *acl_in = ep_addr;
                    *acl_in_mps = mps;
                    got_in = true;
                }
                else
                {
                    *acl_out = ep_addr;
                    *acl_out_mps = mps;
                    got_out = true;
                }
                break;
            case kEpXferInterrupt:
                if (is_in)
                    *event_in = ep_addr;
                break;
            default:
                break;
            }
        }
        off += desc_len;
    }
    return got_in && got_out;
}

// Push one HCI Command down EP0 via the Bluetooth class request.
bool SendHciCommand(u8 slot_id, const u8* cmd, u16 cmd_len)
{
    const bool ok = xhci::XhciControlOut(slot_id, kBtusbReqTypeHciCommand, kBtusbReqHciCommand,
                                         /*wValue=*/0, /*wIndex=*/0, cmd, cmd_len);
    if (ok)
        ++g_state.stats.hci_cmds_sent;
    return ok;
}

// Real, wired keyboard data path: drain bulk-IN ACL packets and
// hand each to the HID upper stack. One report = one short ACL
// packet in practice; the stack tolerates fragmentation anyway.
void AclRxEntry(void*)
{
    using namespace duetos::net::bluetooth;
    for (;;)
    {
        const u64 trb = xhci::XhciBulkSubmit(g_state.slot_id, g_state.acl_in_ep, g_state.rx_buf_phys, kAclRxBufBytes);
        if (trb == 0)
        {
            duetos::sched::SchedSleepTicks(10);
            continue;
        }
        u32 got = 0;
        if (xhci::XhciBulkPoll(g_state.slot_id, g_state.acl_in_ep, trb, &got, /*timeout_us=*/100000))
        {
            if (AclAcceptLen(got))
            {
                ++g_state.stats.acl_packets_rx;
                g_state.stats.acl_bytes_rx += got;
                BtHidDeliverAcl(g_state.rx_buf_virt, got);
            }
            else
            {
                ++g_state.stats.acl_short_drops;
            }
        }
        else
        {
            duetos::sched::SchedSleepTicks(1);
        }
    }
}

bool BringUp(u8 slot_id)
{
    KLOG_TRACE_SCOPE("drivers/usb/btusb", "BringUp");

    // GET_DESCRIPTOR(Config) header first to learn wTotalLength,
    // then the full descriptor.
    mm::PhysAddr cfg_phys = mm::AllocateFrame();
    if (cfg_phys == mm::kNullFrame)
        return false;
    auto* cfg = static_cast<u8*>(mm::PhysToVirt(cfg_phys));

    if (!xhci::XhciControlIn(slot_id, kReqTypeStandardIn, kUsbReqGetDescriptor, u16(u16(kDescTypeConfig) << 8) | 0, 0,
                             cfg, 9))
    {
        mm::FreeFrame(cfg_phys);
        return false;
    }
    const u16 total = u16(u16(cfg[2]) | (u16(cfg[3]) << 8));
    if (total < 9 || total > 1024)
    {
        mm::FreeFrame(cfg_phys);
        return false;
    }
    if (!xhci::XhciControlIn(slot_id, kReqTypeStandardIn, kUsbReqGetDescriptor, u16(u16(kDescTypeConfig) << 8) | 0, 0,
                             cfg, total))
    {
        mm::FreeFrame(cfg_phys);
        return false;
    }

    u8 acl_in = 0, acl_out = 0, evt_in = 0;
    u16 acl_in_mps = 0, acl_out_mps = 0;
    const bool classified = ClassifyEndpoints(cfg, total, &acl_in, &acl_in_mps, &acl_out, &acl_out_mps, &evt_in);
    const u8 config_value = cfg[5];
    mm::FreeFrame(cfg_phys);
    if (!classified)
        return false;

    if (!xhci::XhciControlOut(slot_id, kReqTypeStandardOut, kUsbReqSetConfiguration, config_value, 0, nullptr, 0))
        return false;

    if (!xhci::XhciConfigureBulkEndpoint(slot_id, acl_in, acl_in_mps))
        return false;
    if (!xhci::XhciConfigureBulkEndpoint(slot_id, acl_out, acl_out_mps))
        return false;

    g_state.rx_buf_phys = mm::AllocateFrame();
    if (g_state.rx_buf_phys == mm::kNullFrame)
        return false;
    g_state.rx_buf_virt = static_cast<u8*>(mm::PhysToVirt(g_state.rx_buf_phys));

    g_state.slot_id = slot_id;
    g_state.acl_in_ep = acl_in;
    g_state.acl_in_mps = acl_in_mps;
    g_state.acl_out_ep = acl_out;
    g_state.acl_out_mps = acl_out_mps;
    g_state.event_in_ep = evt_in;

    // HCI identity bring-up. Responses arrive on the event
    // interrupt-IN endpoint, which v0 does not drain (GAP) — we
    // send the commands so a real chip is reset + queried, and the
    // (future) event-endpoint slice will read the answers and stamp
    // diag. Build via the shared HCI encoder.
    u8 cmd[8];
    u32 n = duetos::net::bluetooth::HciBuildCmdReset(cmd, sizeof(cmd));
    if (n != 0)
        SendHciCommand(slot_id, cmd, u16(n));
    n = duetos::net::bluetooth::HciBuildCmd(cmd, sizeof(cmd), duetos::net::bluetooth::kOgfInformational,
                                            duetos::net::bluetooth::kOcfReadLocalVersion);
    if (n != 0)
        SendHciCommand(slot_id, cmd, u16(n));
    n = duetos::net::bluetooth::HciBuildCmd(cmd, sizeof(cmd), duetos::net::bluetooth::kOgfInformational,
                                            duetos::net::bluetooth::kOcfReadBdAddr);
    if (n != 0)
        SendHciCommand(slot_id, cmd, u16(n));

    g_state.online = true;
    g_state.stats.online = true;
    g_state.stats.slot_id = slot_id;
    g_state.stats.acl_in_ep = acl_in;
    g_state.stats.acl_out_ep = acl_out;
    g_state.stats.event_in_ep = evt_in;

    duetos::sched::SchedCreate(AclRxEntry, nullptr, "btusb-acl-rx");
    KLOG_INFO("drivers/usb/btusb", "online — ACL RX pump started");
    return true;
}

} // namespace

bool BtusbProbe()
{
    if (g_state.online)
        return true;

    xhci::XhciPauseEventConsumer(true);
    duetos::sched::SchedSleepTicks(1);

    bool ok = false;
    u8 slot = xhci::XhciFindDeviceByClass(kUsbClassWireless, kUsbWirelessSubclassRf);
    if (slot != 0 && BringUp(slot))
    {
        ok = true;
    }
    else
    {
        u8 slots[8];
        const u32 cnt = xhci::XhciEnumerateDevices(slots, 8);
        for (u32 i = 0; i < cnt && !ok; ++i)
        {
            if (slots[i] != 0 && BringUp(slots[i]))
                ok = true;
        }
    }

    // Leave the consumer paused on success for the same reason
    // cdc-ecm does: the ACL RX task races HidPollEntry on the
    // shared event ring until the TRB-dispatch slice lands. With no
    // HID device on a BT-only config the drain is a no-op.
    if (!ok)
        xhci::XhciPauseEventConsumer(false);
    return ok;
}

BtusbStats BtusbStatsRead()
{
    return g_state.stats;
}

namespace
{

void Expect(bool cond, const char* what)
{
    if (cond)
        return;
    arch::SerialWrite("[btusb] MISMATCH ");
    arch::SerialWrite(what);
    arch::SerialWrite("\n");
    core::Panic("drivers/usb/btusb", "btusb self-test mismatch");
}

} // namespace

void BtusbSelfTest()
{
    // Class-request constants the HCI command path depends on
    // (Vol 4 Part B §2.2.2).
    Expect(kBtusbReqTypeHciCommand == 0x20, "HCI command bmRequestType");
    Expect(kBtusbReqHciCommand == 0x00, "HCI command bRequest");

    // ACL hand-off boundary: a packet shorter than the 4-byte ACL
    // header can't be a real ACL packet.
    Expect(!AclAcceptLen(0), "len 0 dropped");
    Expect(!AclAcceptLen(3), "len 3 dropped");
    Expect(AclAcceptLen(4), "len 4 accepted");
    Expect(AclAcceptLen(64), "len 64 accepted");

    // Synthetic Bluetooth-interface config descriptor:
    //   config(9) + interface(9, class E0/01/01)
    //   + interrupt-IN 0x81 + bulk-OUT 0x02 + bulk-IN 0x82.
    const u8 cfg[] = {// config descriptor
                      9, kDescTypeConfig, 39, 0, 1, 1, 0, 0xC0, 50,
                      // interface descriptor (class 0xE0 / sub 0x01 / proto 0x01)
                      9, kDescTypeInterface, 0, 0, 3, kBtIfaceClass, kBtIfaceSubclass, kBtIfaceProtocol, 0,
                      // interrupt-IN endpoint 0x81, mps=16
                      7, kDescTypeEndpoint, 0x81, kEpXferInterrupt, 16, 0, 1,
                      // bulk-OUT endpoint 0x02, mps=64
                      7, kDescTypeEndpoint, 0x02, kEpXferBulk, 64, 0, 0,
                      // bulk-IN endpoint 0x82, mps=64
                      7, kDescTypeEndpoint, 0x82, kEpXferBulk, 64, 0, 0};

    u8 ai = 0, ao = 0, ei = 0;
    u16 aimps = 0, aomps = 0;
    Expect(ClassifyEndpoints(cfg, sizeof(cfg), &ai, &aimps, &ao, &aomps, &ei), "classify ok");
    Expect(ai == 0x82 && aimps == 64, "acl-in ep + mps");
    Expect(ao == 0x02 && aomps == 64, "acl-out ep + mps");
    Expect(ei == 0x81, "event-in ep located");

    // Endpoints outside a Bluetooth interface must be ignored.
    const u8 not_bt[] = {9,
                         kDescTypeConfig,
                         23,
                         0,
                         1,
                         1,
                         0,
                         0xC0,
                         50,
                         9,
                         kDescTypeInterface,
                         0,
                         0,
                         1,
                         0x08 /* mass-storage, not BT */,
                         0x06,
                         0x50,
                         0,
                         7,
                         kDescTypeEndpoint,
                         0x82,
                         kEpXferBulk,
                         64,
                         0,
                         0};
    Expect(!ClassifyEndpoints(not_bt, sizeof(not_bt), &ai, &aimps, &ao, &aomps, &ei), "non-BT iface ignored");

    // Missing the bulk pair (only interrupt-IN) → not usable.
    const u8 no_bulk[] = {9,
                          kDescTypeConfig,
                          25,
                          0,
                          1,
                          1,
                          0,
                          0xC0,
                          50,
                          9,
                          kDescTypeInterface,
                          0,
                          0,
                          1,
                          kBtIfaceClass,
                          kBtIfaceSubclass,
                          kBtIfaceProtocol,
                          0,
                          7,
                          kDescTypeEndpoint,
                          0x81,
                          kEpXferInterrupt,
                          16,
                          0,
                          1};
    Expect(!ClassifyEndpoints(no_bulk, sizeof(no_bulk), &ai, &aimps, &ao, &aomps, &ei), "no bulk pair rejected");

    // Malformed: a zero-length descriptor mid-stream must bail
    // without running off the buffer.
    const u8 bad[] = {9, kDescTypeConfig, 12, 0, 1, 1, 0, 0xC0, 50, 0 /*bLength=0*/, 0, 0};
    Expect(!ClassifyEndpoints(bad, sizeof(bad), &ai, &aimps, &ao, &aomps, &ei), "malformed descriptor safe");

    // Null-arg guard.
    Expect(!ClassifyEndpoints(nullptr, 0, &ai, &aimps, &ao, &aomps, &ei), "null cfg rejected");

    arch::SerialWrite("[btusb] selftest pass\n");
}

} // namespace duetos::drivers::usb
