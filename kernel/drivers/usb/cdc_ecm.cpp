#include "cdc_ecm.h"

#include "../../arch/x86_64/serial.h"
#include "../../core/klog.h"
#include "../../mm/frame_allocator.h"
#include "../../mm/page.h"
#include "../../net/stack.h"
#include "../../sched/sched.h"
#include "xhci.h"

namespace duetos::drivers::usb
{

namespace
{

// USB descriptor types.
constexpr u8 kDescTypeConfig = 0x02;
constexpr u8 kDescTypeString = 0x03;
constexpr u8 kDescTypeInterface = 0x04;
constexpr u8 kDescTypeEndpoint = 0x05;
constexpr u8 kDescTypeCsInterface = 0x24; // Class-Specific Interface descriptor

// CDC functional-descriptor subtypes (CDC1.2 §5.2.3).
constexpr u8 kCdcFuncSubtypeEthernet = 0x0F;

// USB class codes.
constexpr u8 kUsbClassCdcComm = 0x02;
constexpr u8 kUsbSubclassEcm = 0x06;
constexpr u8 kUsbClassCdcData = 0x0A;

// Standard USB requests.
constexpr u8 kUsbReqGetDescriptor = 0x06;
constexpr u8 kUsbReqSetConfiguration = 0x09;
constexpr u8 kUsbReqSetInterface = 0x0B;
constexpr u8 kReqTypeStandardIn = 0x80;       // dev->host | standard | device
constexpr u8 kReqTypeStandardOut = 0x00;      // host->dev | standard | device
constexpr u8 kReqTypeStandardIfaceOut = 0x01; // host->dev | standard | interface

// Class-specific (CDC) requests.
constexpr u8 kCdcReqSetEthernetPacketFilter = 0x43;
constexpr u8 kReqTypeClassIfaceOut = 0x21; // host->dev | class | interface

// Packet filter bits (CDC1.2 §6.2.4).
constexpr u16 kPktFilterAllMulticast = 1u << 1;
constexpr u16 kPktFilterDirected = 1u << 2;
constexpr u16 kPktFilterBroadcast = 1u << 3;
constexpr u16 kPktFilterDefault = kPktFilterDirected | kPktFilterBroadcast | kPktFilterAllMulticast;

// English (US) language ID for GET_DESCRIPTOR(STRING).
constexpr u16 kLangIdEnUs = 0x0409;

// RX buffer size — Ethernet MTU + slack, single page.
constexpr u32 kRxBufBytes = 2048;

struct CdcEcmState
{
    bool online;
    u8 slot_id;
    u8 mac[6];
    u8 config_value;
    u8 data_iface;
    u8 bulk_in_ep;
    u8 bulk_out_ep;
    u16 bulk_in_mps;
    u16 bulk_out_mps;
    u8 imac_string_idx;
    u32 iface_index;

    mm::PhysAddr rx_buf_phys;
    u8* rx_buf_virt;
    mm::PhysAddr tx_buf_phys;
    u8* tx_buf_virt;

    CdcEcmStats stats;
};

constinit CdcEcmState g_state = {};

bool ParseHexNibble(u8 c, u8& out)
{
    if (c >= '0' && c <= '9')
    {
        out = u8(c - '0');
        return true;
    }
    if (c >= 'a' && c <= 'f')
    {
        out = u8(10 + (c - 'a'));
        return true;
    }
    if (c >= 'A' && c <= 'F')
    {
        out = u8(10 + (c - 'A'));
        return true;
    }
    return false;
}

// Parse the 9-byte top-level Config descriptor + walk its full
// `wTotalLength` bytes looking for:
//  - the data interface (class 0x0A) with bAlternateSetting=1
//  - that interface's bulk-IN + bulk-OUT endpoint descriptors
//  - the CDC Ethernet Functional Descriptor's iMACAddress index
// Returns true iff every required field was filled.
bool ParseConfigDescriptor(const u8* buf, u32 len, CdcEcmState& s)
{
    if (len < 9 || buf[1] != kDescTypeConfig)
        return false;
    s.config_value = buf[5];
    const u32 total = u32(buf[2]) | (u32(buf[3]) << 8);
    if (total > len)
        return false;

    bool got_data_iface = false;
    bool got_bulk_in = false;
    bool got_bulk_out = false;
    bool got_imac = false;
    u8 cur_iface = 0xFF;
    u8 cur_iface_class = 0xFF;
    u8 cur_iface_alt = 0xFF;

    for (u32 off = 0; off + 2 <= total;)
    {
        const u8 desc_len = buf[off];
        const u8 desc_type = buf[off + 1];
        if (desc_len < 2 || off + desc_len > total)
            break;
        switch (desc_type)
        {
        case kDescTypeInterface:
        {
            // bLength=9, bInterfaceNumber, bAlternateSetting,
            // bNumEndpoints, bInterfaceClass, ...
            if (desc_len < 9)
                break;
            cur_iface = buf[off + 2];
            cur_iface_alt = buf[off + 3];
            cur_iface_class = buf[off + 5];
            if (cur_iface_class == kUsbClassCdcData && cur_iface_alt == 1)
            {
                s.data_iface = cur_iface;
                got_data_iface = true;
            }
            break;
        }
        case kDescTypeCsInterface:
        {
            // bLength, bDescriptorType=0x24, bDescriptorSubtype, ...
            if (desc_len >= 13 && buf[off + 2] == kCdcFuncSubtypeEthernet)
            {
                // Ethernet Networking Functional Descriptor:
                //  bLength=13, bDescriptorType=0x24, bDescriptorSubtype=0x0F,
                //  iMACAddress (1 byte string index), bmEthernetStatistics (4),
                //  wMaxSegmentSize (2), wNumberMCFilters (2), bNumberPowerFilters (1).
                s.imac_string_idx = buf[off + 3];
                got_imac = true;
            }
            break;
        }
        case kDescTypeEndpoint:
        {
            // bLength=7, bDescriptorType=0x05, bEndpointAddress,
            // bmAttributes, wMaxPacketSize (2), bInterval.
            if (desc_len < 7)
                break;
            // Only consider endpoints inside our chosen data
            // interface (alt 1). bmAttributes bits 0..1 == 0b10 = bulk.
            if (cur_iface_class != kUsbClassCdcData || cur_iface_alt != 1)
                break;
            const u8 ep_addr = buf[off + 2];
            const u8 attr = buf[off + 3];
            if ((attr & 0x03) != 0x02 /* bulk */)
                break;
            const u16 mps = u16(buf[off + 4]) | (u16(buf[off + 5]) << 8);
            if ((ep_addr & 0x80) != 0)
            {
                s.bulk_in_ep = ep_addr;
                s.bulk_in_mps = mps;
                got_bulk_in = true;
            }
            else
            {
                s.bulk_out_ep = ep_addr;
                s.bulk_out_mps = mps;
                got_bulk_out = true;
            }
            break;
        }
        default:
            break;
        }
        off += desc_len;
    }
    return got_data_iface && got_bulk_in && got_bulk_out && got_imac;
}

bool ReadMacFromString(u8 slot_id, u8 string_idx, u8 mac[6])
{
    if (string_idx == 0)
        return false;
    // GET_DESCRIPTOR(STRING) writes the descriptor into `buf`.
    // Layout: bLength, bDescriptorType=0x03, then UTF-16LE chars.
    // CDC Ethernet's iMACAddress is 12 hex chars = 24 UTF-16 bytes.
    u8 buf[64];
    if (!xhci::XhciControlIn(slot_id, kReqTypeStandardIn, kUsbReqGetDescriptor,
                             u16(u16(kDescTypeString) << 8) | string_idx, kLangIdEnUs, buf, sizeof(buf)))
        return false;
    if (buf[1] != kDescTypeString || buf[0] < 2 + 24)
        return false;
    // Walk 12 UTF-16LE chars, take the low byte (ASCII), pair into hex bytes.
    for (u32 i = 0; i < 6; ++i)
    {
        u8 hi = 0, lo = 0;
        if (!ParseHexNibble(buf[2 + (i * 2 + 0) * 2], hi) || !ParseHexNibble(buf[2 + (i * 2 + 1) * 2], lo))
            return false;
        mac[i] = u8((hi << 4) | lo);
    }
    return true;
}

bool CdcEcmSendImpl(const u8* data, u32 len)
{
    if (!g_state.online || data == nullptr || len == 0)
        return false;
    if (len > kRxBufBytes)
        return false;
    for (u32 i = 0; i < len; ++i)
        g_state.tx_buf_virt[i] = data[i];
    const u64 trb_phys = xhci::XhciBulkSubmit(g_state.slot_id, g_state.bulk_out_ep, g_state.tx_buf_phys, len);
    if (trb_phys == 0)
    {
        ++g_state.stats.tx_failures;
        return false;
    }
    u32 sent = 0;
    if (!xhci::XhciBulkPoll(g_state.slot_id, g_state.bulk_out_ep, trb_phys, &sent, /*timeout_us=*/200000))
    {
        ++g_state.stats.tx_failures;
        return false;
    }
    ++g_state.stats.tx_packets;
    g_state.stats.tx_bytes += sent;
    return true;
}

bool TxTrampoline(u32 iface_index, const void* frame, u64 len)
{
    (void)iface_index;
    return CdcEcmSendImpl(static_cast<const u8*>(frame), u32(len));
}

void RxPollEntry(void*)
{
    for (;;)
    {
        const u64 trb_phys =
            xhci::XhciBulkSubmit(g_state.slot_id, g_state.bulk_in_ep, g_state.rx_buf_phys, kRxBufBytes);
        if (trb_phys == 0)
        {
            duetos::sched::SchedSleepTicks(10);
            continue;
        }
        u32 got = 0;
        if (xhci::XhciBulkPoll(g_state.slot_id, g_state.bulk_in_ep, trb_phys, &got, /*timeout_us=*/100000))
        {
            if (got >= 14)
            {
                ++g_state.stats.rx_packets;
                g_state.stats.rx_bytes += got;
                duetos::net::NetStackInjectRx(g_state.iface_index, g_state.rx_buf_virt, got);
            }
            else
            {
                ++g_state.stats.rx_dropped;
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
    KLOG_TRACE_SCOPE("drivers/usb/cdc-ecm", "BringUp");
    g_state.slot_id = slot_id;

    // GET_DESCRIPTOR(Config) — first 9 bytes to learn wTotalLength,
    // then full descriptor.
    u8 hdr[9];
    if (!xhci::XhciControlIn(slot_id, kReqTypeStandardIn, kUsbReqGetDescriptor, u16(u16(kDescTypeConfig) << 8) | 0,
                             /*wIndex=*/0, hdr, sizeof(hdr)))
    {
        return false;
    }
    const u16 total = u16(hdr[2]) | (u16(hdr[3]) << 8);
    if (total > 1024)
    {
        arch::SerialWrite("[cdc-ecm] config descriptor too large\n");
        return false;
    }
    // Pull the full config descriptor into an allocated page so we
    // don't need large stack arrays (no memset in freestanding).
    const mm::PhysAddr cfg_phys = mm::AllocateFrame();
    if (cfg_phys == mm::kNullFrame)
        return false;
    auto* cfg = static_cast<u8*>(mm::PhysToVirt(cfg_phys));
    if (!xhci::XhciControlIn(slot_id, kReqTypeStandardIn, kUsbReqGetDescriptor, u16(u16(kDescTypeConfig) << 8) | 0,
                             /*wIndex=*/0, cfg, total))
    {
        arch::SerialWrite("[cdc-ecm] GET_DESCRIPTOR(Config, full) failed\n");
        mm::FreeFrame(cfg_phys);
        return false;
    }
    const bool parsed = ParseConfigDescriptor(cfg, total, g_state);
    mm::FreeFrame(cfg_phys);
    if (!parsed)
    {
        // Not CDC-ECM — silent to avoid log noise since we probe
        // every enumerated device.
        return false;
    }

    if (!ReadMacFromString(slot_id, g_state.imac_string_idx, g_state.mac))
    {
        arch::SerialWrite("[cdc-ecm] failed to parse MAC from iMACAddress string descriptor\n");
        return false;
    }

    // SET_CONFIGURATION (no data stage).
    if (!xhci::XhciControlOut(slot_id, kReqTypeStandardOut, kUsbReqSetConfiguration, g_state.config_value, 0, nullptr,
                              0))
    {
        arch::SerialWrite("[cdc-ecm] SET_CONFIGURATION failed\n");
        return false;
    }

    // SET_INTERFACE 1 on the data interface (enables bulk endpoints).
    if (!xhci::XhciControlOut(slot_id, kReqTypeStandardIfaceOut, kUsbReqSetInterface, /*wValue=*/1,
                              /*wIndex=*/g_state.data_iface, nullptr, 0))
    {
        arch::SerialWrite("[cdc-ecm] SET_INTERFACE 1 failed\n");
        return false;
    }

    // Configure bulk endpoints in the xHCI device context.
    if (!xhci::XhciConfigureBulkEndpoint(slot_id, g_state.bulk_in_ep, g_state.bulk_in_mps))
    {
        arch::SerialWrite("[cdc-ecm] configure bulk-IN failed\n");
        return false;
    }
    if (!xhci::XhciConfigureBulkEndpoint(slot_id, g_state.bulk_out_ep, g_state.bulk_out_mps))
    {
        arch::SerialWrite("[cdc-ecm] configure bulk-OUT failed\n");
        return false;
    }

    // SET_ETHERNET_PACKET_FILTER — class request to the
    // communication interface. CDC-ECM puts the comm interface
    // at iface 0 (by convention; spec actually says it's separate
    // from data iface — the data interface number is data_iface,
    // so the comm iface is data_iface - 1 typically). For QEMU's
    // emulation iface 0 is comm.
    const u8 comm_iface = u8(g_state.data_iface == 0 ? 0 : g_state.data_iface - 1);
    if (!xhci::XhciControlOut(slot_id, kReqTypeClassIfaceOut, kCdcReqSetEthernetPacketFilter,
                              /*wValue=*/kPktFilterDefault, /*wIndex=*/comm_iface, nullptr, 0))
    {
        arch::SerialWrite("[cdc-ecm] SET_ETHERNET_PACKET_FILTER failed (continuing — some devices reject this)\n");
        // Don't bail — QEMU's emulation accepts even without this;
        // some real devices reject the request and still RX fine.
    }

    // DMA buffers.
    g_state.rx_buf_phys = mm::AllocateFrame();
    g_state.tx_buf_phys = mm::AllocateFrame();
    if (g_state.rx_buf_phys == mm::kNullFrame || g_state.tx_buf_phys == mm::kNullFrame)
    {
        arch::SerialWrite("[cdc-ecm] DMA buffer allocation failed\n");
        return false;
    }
    g_state.rx_buf_virt = static_cast<u8*>(mm::PhysToVirt(g_state.rx_buf_phys));
    g_state.tx_buf_virt = static_cast<u8*>(mm::PhysToVirt(g_state.tx_buf_phys));

    g_state.iface_index = 1; // iface 0 is e1000
    g_state.online = true;
    g_state.stats.online = true;
    g_state.stats.slot_id = slot_id;
    g_state.stats.bulk_in_ep = g_state.bulk_in_ep;
    g_state.stats.bulk_out_ep = g_state.bulk_out_ep;
    g_state.stats.bulk_in_mps = g_state.bulk_in_mps;
    g_state.stats.bulk_out_mps = g_state.bulk_out_mps;
    for (u32 i = 0; i < 6; ++i)
        g_state.stats.mac[i] = g_state.mac[i];

    arch::SerialWrite("[cdc-ecm] online slot=");
    arch::SerialWriteHex(slot_id);
    arch::SerialWrite(" mac=");
    for (u32 i = 0; i < 6; ++i)
    {
        if (i != 0)
            arch::SerialWrite(":");
        arch::SerialWriteHex(g_state.mac[i]);
    }
    arch::SerialWrite(" bulk_in=");
    arch::SerialWriteHex(g_state.bulk_in_ep);
    arch::SerialWrite("/");
    arch::SerialWriteHex(g_state.bulk_in_mps);
    arch::SerialWrite(" bulk_out=");
    arch::SerialWriteHex(g_state.bulk_out_ep);
    arch::SerialWrite("/");
    arch::SerialWriteHex(g_state.bulk_out_mps);
    arch::SerialWrite("\n");

    duetos::net::MacAddress mac{};
    for (u32 i = 0; i < 6; ++i)
        mac.octets[i] = g_state.mac[i];
    duetos::net::Ipv4Address ip{{0, 0, 0, 0}};
    duetos::net::NetStackBindInterface(g_state.iface_index, mac, ip, TxTrampoline);
    duetos::sched::SchedCreate(RxPollEntry, nullptr, "cdc-ecm-rx");
    duetos::net::DhcpStart(g_state.iface_index);
    return true;
}

} // namespace

bool CdcEcmProbe()
{
    KLOG_TRACE_SCOPE("drivers/usb/cdc-ecm", "Probe");
    if (g_state.online)
        return true;

    // Pause the xHCI HID poll task's event-ring drain for the
    // duration of our control / bulk transfers. v0 event consumer
    // isn't TRB-dispatched — an un-paused drain steals the Transfer
    // Events we need.
    xhci::XhciPauseEventConsumer(true);
    // Give the poll task one tick to notice + park at its
    // pause gate before we start touching the ring.
    duetos::sched::SchedSleepTicks(1);

    // First try the cheap device-level class match. Some CDC-ECM
    // devices (Linux g_ether gadget, most USB-Ethernet dongles)
    // declare class 0x02 / subclass 0x06 at the device descriptor.
    u8 slot = xhci::XhciFindDeviceByClass(kUsbClassCdcComm, kUsbSubclassEcm);
    if (slot != 0 && BringUp(slot))
    {
        // Deliberately leave the consumer paused — the RX poll
        // task will keep racing with HidPollEntry on the event
        // ring otherwise. With no HID devices on this config
        // the drain is a no-op anyway. A future slice can route
        // events by TRB and let both drainers coexist.
        return true;
    }

    // Fall back to "walk every device, try-parse each". Covers the
    // composite-device case where the device reports class 0x00 or
    // 0xEF (Misc + IAD) and CDC-ECM lives at an interface.
    u8 slots[8];
    const u32 n = xhci::XhciEnumerateDevices(slots, 8);
    for (u32 i = 0; i < n; ++i)
    {
        if (slots[i] == 0)
            continue;
        if (BringUp(slots[i]))
        {
            // See note above — pause stays asserted while the RX
            // task runs. Safe because no HID device is attached.
            return true;
        }
        // BringUp touched g_state — clear the online flag + slot
        // id before the next attempt. Leaving the rest in place
        // is harmless; the successful attempt overwrites what it
        // needs. Avoid aggregate-init (= {}) because freestanding
        // lowers it to a memset the kernel doesn't provide.
        g_state.online = false;
        g_state.slot_id = 0;
        g_state.stats.online = false;
    }
    xhci::XhciPauseEventConsumer(false);
    return false;
}

CdcEcmStats CdcEcmStatsRead()
{
    return g_state.stats;
}

} // namespace duetos::drivers::usb
