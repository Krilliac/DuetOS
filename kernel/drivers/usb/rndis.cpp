#include "rndis.h"

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

// USB descriptor types we walk to find bulk endpoints.
constexpr u8 kDescTypeConfig = 0x02;
constexpr u8 kDescTypeInterface = 0x04;
constexpr u8 kDescTypeEndpoint = 0x05;

// USB standard requests.
constexpr u8 kUsbReqGetDescriptor = 0x06;
constexpr u8 kUsbReqSetConfiguration = 0x09;
constexpr u8 kReqTypeStandardIn = 0x80;
constexpr u8 kReqTypeStandardOut = 0x00;

// RNDIS class-specific requests on EP0 (bRequest field).
constexpr u8 kRndisSendEncap = 0x00;
constexpr u8 kRndisGetEncap = 0x01;
constexpr u8 kReqTypeClassIfaceOut = 0x21; // host->dev | class | interface
constexpr u8 kReqTypeClassIfaceIn = 0xA1;  // dev->host | class | interface

// RNDIS message types (msft RNDIS spec §3.1).
constexpr u32 kRndisMsgPacket = 0x00000001;
constexpr u32 kRndisMsgInit = 0x00000002;
constexpr u32 kRndisMsgInitCmplt = 0x80000002;
constexpr u32 kRndisMsgQuery = 0x00000004;
constexpr u32 kRndisMsgQueryCmplt = 0x80000004;
constexpr u32 kRndisMsgSet = 0x00000005;
constexpr u32 kRndisMsgSetCmplt = 0x80000005;

// RNDIS status codes.
constexpr u32 kRndisStatusSuccess = 0x00000000;

// NDIS OIDs we use.
constexpr u32 kOidGenCurrentPacketFilter = 0x0001010E;
constexpr u32 kOid8023PermanentAddress = 0x01010101;

// Packet filter bits.
constexpr u32 kPktFilterDirected = 1u << 0;
constexpr u32 kPktFilterAllMulticast = 1u << 1;
constexpr u32 kPktFilterBroadcast = 1u << 2;

// MTU + RX buffer sizing. RNDIS adds a 44-byte header to each
// Ethernet frame, plus possible alignment padding.
constexpr u32 kRxBufBytes = 2048;

// RNDIS packet header (44 bytes, §3.4.4).
struct alignas(4) RndisPacketHeader
{
    u32 message_type;          // = kRndisMsgPacket
    u32 message_length;        // total bytes (header + data)
    u32 data_offset;           // offset from this field to data start
    u32 data_length;           // ethernet payload size
    u32 oob_data_offset;       // 0
    u32 oob_data_length;       // 0
    u32 num_oob_data_elements; // 0
    u32 per_pkt_info_offset;   // 0
    u32 per_pkt_info_length;   // 0
    u32 vc_handle;             // 0
    u32 reserved;              // 0
};
static_assert(sizeof(RndisPacketHeader) == 44, "RNDIS_PACKET_MSG header must be 44 bytes");

struct RndisState
{
    bool online;
    u8 slot_id;
    u8 mac[6];
    u8 ctrl_iface; // class-IFACE wIndex for SEND_/GET_ENCAPSULATED
    u8 bulk_in_ep;
    u8 bulk_out_ep;
    u16 bulk_in_mps;
    u16 bulk_out_mps;
    u32 next_request_id;
    u32 device_max_xfer;
    u32 packet_alignment;
    u32 iface_index;

    mm::PhysAddr rx_buf_phys;
    u8* rx_buf_virt;
    mm::PhysAddr tx_buf_phys;
    u8* tx_buf_virt;

    RndisStats stats;
};

constinit RndisState g_state = {};

// Little-endian u32 read/write helpers — RNDIS messages are LE on
// the wire. The kernel runs on x86_64 (LE) so a direct memcpy
// works, but go through helpers for explicitness.
u32 LeU32(const u8* p)
{
    return u32(p[0]) | (u32(p[1]) << 8) | (u32(p[2]) << 16) | (u32(p[3]) << 24);
}

void StoreLeU32(u8* p, u32 v)
{
    p[0] = u8(v & 0xFF);
    p[1] = u8((v >> 8) & 0xFF);
    p[2] = u8((v >> 16) & 0xFF);
    p[3] = u8((v >> 24) & 0xFF);
}

bool RndisSendCommand(const u8* msg, u16 len)
{
    ++g_state.stats.control_msgs;
    if (!xhci::XhciControlOut(g_state.slot_id, kReqTypeClassIfaceOut, kRndisSendEncap,
                              /*wValue=*/0, /*wIndex=*/g_state.ctrl_iface, msg, len))
    {
        ++g_state.stats.control_failures;
        return false;
    }
    return true;
}

bool RndisFetchResponse(u8* buf, u16 len)
{
    if (!xhci::XhciControlIn(g_state.slot_id, kReqTypeClassIfaceIn, kRndisGetEncap,
                             /*wValue=*/0, /*wIndex=*/g_state.ctrl_iface, buf, len))
    {
        ++g_state.stats.control_failures;
        return false;
    }
    return true;
}

// Send INITIALIZE_MSG, fetch INITIALIZE_CMPLT, learn max_transfer_size.
bool RndisInitialize()
{
    u8 msg[24];
    StoreLeU32(msg + 0, kRndisMsgInit);
    StoreLeU32(msg + 4, 24);                        // MessageLength
    StoreLeU32(msg + 8, ++g_state.next_request_id); // RequestID
    StoreLeU32(msg + 12, 1);                        // MajorVersion
    StoreLeU32(msg + 16, 0);                        // MinorVersion
    StoreLeU32(msg + 20, 0x4000);                   // MaxTransferSize host can RX
    if (!RndisSendCommand(msg, sizeof(msg)))
        return false;

    u8 reply[52];
    if (!RndisFetchResponse(reply, sizeof(reply)))
        return false;
    if (LeU32(reply + 0) != kRndisMsgInitCmplt)
        return false;
    if (LeU32(reply + 12) != kRndisStatusSuccess)
        return false;

    // Reply layout (RNDIS spec §3.2.2):
    //   off 0  MessageType, off 4  MessageLength, off 8  RequestID,
    //   off 12 Status, off 16 MajorVersion, off 20 MinorVersion,
    //   off 24 DeviceFlags, off 28 Medium,
    //   off 32 MaxPacketsPerTransfer,
    //   off 36 MaxTransferSize  (← what we want)
    //   off 40 PacketAlignmentFactor (log2; 0 = byte-aligned)
    g_state.device_max_xfer = LeU32(reply + 36);
    g_state.packet_alignment = LeU32(reply + 40);
    g_state.stats.device_max_xfer = g_state.device_max_xfer;
    g_state.stats.packet_alignment = g_state.packet_alignment;
    return true;
}

bool RndisSetU32Oid(u32 oid, u32 value)
{
    u8 msg[32];
    StoreLeU32(msg + 0, kRndisMsgSet);
    StoreLeU32(msg + 4, 32);                        // MessageLength
    StoreLeU32(msg + 8, ++g_state.next_request_id); // RequestID
    StoreLeU32(msg + 12, oid);
    StoreLeU32(msg + 16, 4);  // InfoBufferLength
    StoreLeU32(msg + 20, 20); // InfoBufferOffset (from start of RequestID)
    StoreLeU32(msg + 24, 0);  // Reserved
    StoreLeU32(msg + 28, value);
    if (!RndisSendCommand(msg, sizeof(msg)))
        return false;

    u8 reply[16];
    if (!RndisFetchResponse(reply, sizeof(reply)))
        return false;
    if (LeU32(reply + 0) != kRndisMsgSetCmplt)
        return false;
    if (LeU32(reply + 12) != kRndisStatusSuccess)
        return false;
    return true;
}

bool RndisQueryMac(u8 mac_out[6])
{
    u8 msg[28];
    StoreLeU32(msg + 0, kRndisMsgQuery);
    StoreLeU32(msg + 4, 28);                        // MessageLength
    StoreLeU32(msg + 8, ++g_state.next_request_id); // RequestID
    StoreLeU32(msg + 12, kOid8023PermanentAddress);
    StoreLeU32(msg + 16, 0); // InfoBufferLength (0 for queries)
    StoreLeU32(msg + 20, 0); // InfoBufferOffset
    StoreLeU32(msg + 24, 0); // Reserved
    if (!RndisSendCommand(msg, sizeof(msg)))
        return false;

    u8 reply[64];
    if (!RndisFetchResponse(reply, sizeof(reply)))
        return false;
    if (LeU32(reply + 0) != kRndisMsgQueryCmplt)
        return false;
    if (LeU32(reply + 12) != kRndisStatusSuccess)
        return false;
    const u32 info_len = LeU32(reply + 16);
    const u32 info_off = LeU32(reply + 20);
    if (info_len < 6)
        return false;
    // info_off is from the start of RequestID (offset 8); add 8 to
    // get an absolute offset into the reply buffer.
    const u32 abs = 8 + info_off;
    if (abs + 6 > sizeof(reply))
        return false;
    for (u32 i = 0; i < 6; ++i)
        mac_out[i] = reply[abs + i];
    return true;
}

// Walk the configuration descriptor to find the comm interface
// number (where RNDIS lives) + the bulk endpoints. RNDIS uses
// the same interface layout as CDC-ECM but the comm interface
// has subclass 0x02 (ACM-style) protocol 0xFF (vendor / RNDIS).
bool RndisParseConfig(const u8* buf, u32 total, RndisState& s)
{
    if (total < 9 || buf[1] != kDescTypeConfig)
        return false;
    const u8 config_value = buf[5];
    s.ctrl_iface = 0xFF; // sentinel
    bool got_bulk_in = false;
    bool got_bulk_out = false;
    bool got_ctrl_iface = false;
    u8 cur_iface_class = 0xFF;
    u8 cur_iface_alt = 0xFF;
    u8 cur_iface = 0xFF;
    for (u32 off = 0; off + 2 <= total;)
    {
        const u8 desc_len = buf[off];
        const u8 desc_type = buf[off + 1];
        if (desc_len < 2 || off + desc_len > total)
            break;
        if (desc_type == kDescTypeInterface && desc_len >= 9)
        {
            cur_iface = buf[off + 2];
            cur_iface_alt = buf[off + 3];
            cur_iface_class = buf[off + 5];
            const u8 sub = buf[off + 6];
            const u8 prot = buf[off + 7];
            // RNDIS comm interface: class 0x02 / sub 0x02 / proto
            // 0xFF (msft-specific) — that's how QEMU's usb-net and
            // the Linux gadget advertise. Some devices use class
            // 0xEF / sub 0x04 / proto 0x01 (USB-IF Wireless Mobile
            // Communications RNDIS) — also accept.
            const bool match_a = cur_iface_class == 0x02 && sub == 0x02 && prot == 0xFF;
            const bool match_b = cur_iface_class == 0xEF && sub == 0x04 && prot == 0x01;
            if ((match_a || match_b) && cur_iface_alt == 0)
            {
                s.ctrl_iface = cur_iface;
                got_ctrl_iface = true;
            }
        }
        else if (desc_type == kDescTypeEndpoint && desc_len >= 7)
        {
            // Find bulk endpoints inside the data interface. RNDIS
            // data interface follows the comm interface at
            // bInterfaceNumber+1, class 0x0A. We accept any alt.
            if (cur_iface_class == 0x0A)
            {
                const u8 ep_addr = buf[off + 2];
                const u8 attr = buf[off + 3];
                if ((attr & 0x03) == 0x02 /* bulk */)
                {
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
                }
            }
        }
        off += desc_len;
    }
    if (got_ctrl_iface && got_bulk_in && got_bulk_out)
    {
        // Stash config_value in s for later SET_CONFIGURATION.
        // Re-use the iface_index field temporarily — replaced
        // before BringUp returns.
        (void)config_value;
        return true;
    }
    return false;
}

bool RndisSendImpl(const u8* data, u32 len)
{
    if (!g_state.online || data == nullptr || len == 0)
        return false;
    const u32 total = sizeof(RndisPacketHeader) + len;
    if (total > kRxBufBytes)
        return false;
    auto* hdr = reinterpret_cast<RndisPacketHeader*>(g_state.tx_buf_virt);
    hdr->message_type = kRndisMsgPacket;
    hdr->message_length = total;
    hdr->data_offset = sizeof(RndisPacketHeader) - 8; // offset relative to "DataOffset" field (offset 8 in header)
    hdr->data_length = len;
    hdr->oob_data_offset = 0;
    hdr->oob_data_length = 0;
    hdr->num_oob_data_elements = 0;
    hdr->per_pkt_info_offset = 0;
    hdr->per_pkt_info_length = 0;
    hdr->vc_handle = 0;
    hdr->reserved = 0;
    u8* payload = g_state.tx_buf_virt + sizeof(RndisPacketHeader);
    for (u32 i = 0; i < len; ++i)
        payload[i] = data[i];
    const u64 trb_phys = xhci::XhciBulkSubmit(g_state.slot_id, g_state.bulk_out_ep, g_state.tx_buf_phys, total);
    if (trb_phys == 0)
    {
        ++g_state.stats.tx_failures;
        return false;
    }
    u32 sent = 0;
    if (!xhci::XhciBulkPoll(g_state.slot_id, g_state.bulk_out_ep, trb_phys, &sent, /*timeout_us=*/50000))
    {
        ++g_state.stats.tx_failures;
        return false;
    }
    ++g_state.stats.tx_packets;
    g_state.stats.tx_bytes += len;
    return true;
}

bool TxTrampoline(u32 iface_index, const void* frame, u64 len)
{
    (void)iface_index;
    return RndisSendImpl(static_cast<const u8*>(frame), u32(len));
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
        // Short timeout per poll cycle so the bulk-poll lock is
        // released often — TX from the network stack uses the
        // same lock and would starve under a long RX hold.
        if (xhci::XhciBulkPoll(g_state.slot_id, g_state.bulk_in_ep, trb_phys, &got, /*timeout_us=*/5000))
        {
            // Each transfer can carry one or more RNDIS_PACKET_MSG
            // records back to back. Walk them by `msg_len`,
            // delivering each one's data span to the net stack and
            // stopping at the first malformed record so a runt
            // tail byte can't desync the loop.
            u32 cursor = 0;
            while (cursor + sizeof(RndisPacketHeader) <= got)
            {
                const u8* hdr = g_state.rx_buf_virt + cursor;
                const u32 msg_type = LeU32(hdr + 0);
                if (msg_type != kRndisMsgPacket)
                {
                    // Probably a control-plane indication
                    // (RNDIS_INDICATE_STATUS_MSG) — ignore in v0
                    // and stop walking the buffer.
                    ++g_state.stats.rx_dropped;
                    break;
                }
                const u32 msg_len = LeU32(hdr + 4);
                const u32 data_off = LeU32(hdr + 8);
                const u32 data_len = LeU32(hdr + 12);
                if (msg_len < sizeof(RndisPacketHeader) || cursor + msg_len > got)
                {
                    ++g_state.stats.rx_dropped;
                    break;
                }
                const u32 abs = 8 + data_off; // data_off is from offset 8
                if (abs + data_len <= msg_len && data_len >= 14)
                {
                    ++g_state.stats.rx_packets;
                    g_state.stats.rx_bytes += data_len;
                    duetos::net::NetStackInjectRx(g_state.iface_index, hdr + abs, data_len);
                }
                else
                {
                    ++g_state.stats.rx_dropped;
                }
                cursor += msg_len;
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
    KLOG_TRACE_SCOPE("drivers/usb/rndis", "BringUp");
    g_state.slot_id = slot_id;
    g_state.next_request_id = 0;

    // Pull the full config descriptor.
    u8 hdr[9];
    if (!xhci::XhciControlIn(slot_id, kReqTypeStandardIn, kUsbReqGetDescriptor, u16(u16(kDescTypeConfig) << 8) | 0,
                             /*wIndex=*/0, hdr, sizeof(hdr)))
        return false;
    const u16 total = u16(hdr[2]) | (u16(hdr[3]) << 8);
    if (total > 1024)
        return false;
    const mm::PhysAddr cfg_phys = mm::AllocateFrame();
    if (cfg_phys == mm::kNullFrame)
        return false;
    auto* cfg = static_cast<u8*>(mm::PhysToVirt(cfg_phys));
    if (!xhci::XhciControlIn(slot_id, kReqTypeStandardIn, kUsbReqGetDescriptor, u16(u16(kDescTypeConfig) << 8) | 0,
                             /*wIndex=*/0, cfg, total))
    {
        mm::FreeFrame(cfg_phys);
        return false;
    }

    if (!RndisParseConfig(cfg, total, g_state))
    {
        mm::FreeFrame(cfg_phys);
        return false;
    }
    const u8 config_value = cfg[5];
    mm::FreeFrame(cfg_phys);

    // SET_CONFIGURATION.
    if (!xhci::XhciControlOut(slot_id, kReqTypeStandardOut, kUsbReqSetConfiguration, config_value, 0, nullptr, 0))
    {
        arch::SerialWrite("[rndis] SET_CONFIGURATION failed\n");
        return false;
    }

    // Configure both bulk endpoints.
    if (!xhci::XhciConfigureBulkEndpoint(slot_id, g_state.bulk_in_ep, g_state.bulk_in_mps))
    {
        arch::SerialWrite("[rndis] configure bulk-IN failed\n");
        return false;
    }
    if (!xhci::XhciConfigureBulkEndpoint(slot_id, g_state.bulk_out_ep, g_state.bulk_out_mps))
    {
        arch::SerialWrite("[rndis] configure bulk-OUT failed\n");
        return false;
    }

    // RNDIS protocol bring-up.
    if (!RndisInitialize())
    {
        arch::SerialWrite("[rndis] INITIALIZE failed\n");
        return false;
    }
    if (!RndisSetU32Oid(kOidGenCurrentPacketFilter, kPktFilterDirected | kPktFilterBroadcast | kPktFilterAllMulticast))
    {
        arch::SerialWrite("[rndis] SET packet filter failed\n");
        return false;
    }
    if (!RndisQueryMac(g_state.mac))
    {
        arch::SerialWrite("[rndis] QUERY mac failed\n");
        return false;
    }

    // DMA buffers.
    g_state.rx_buf_phys = mm::AllocateFrame();
    g_state.tx_buf_phys = mm::AllocateFrame();
    if (g_state.rx_buf_phys == mm::kNullFrame || g_state.tx_buf_phys == mm::kNullFrame)
        return false;
    g_state.rx_buf_virt = static_cast<u8*>(mm::PhysToVirt(g_state.rx_buf_phys));
    g_state.tx_buf_virt = static_cast<u8*>(mm::PhysToVirt(g_state.tx_buf_phys));

    g_state.iface_index = 1; // iface 0 is e1000
    g_state.online = true;
    g_state.stats.online = true;
    g_state.stats.slot_id = slot_id;
    for (u32 i = 0; i < 6; ++i)
        g_state.stats.mac[i] = g_state.mac[i];

    arch::SerialWrite("[rndis] online slot=");
    arch::SerialWriteHex(slot_id);
    arch::SerialWrite(" mac=");
    for (u32 i = 0; i < 6; ++i)
    {
        if (i != 0)
            arch::SerialWrite(":");
        arch::SerialWriteHex(g_state.mac[i]);
    }
    arch::SerialWrite(" max_xfer=");
    arch::SerialWriteHex(g_state.device_max_xfer);
    arch::SerialWrite(" bulk_in=");
    arch::SerialWriteHex(g_state.bulk_in_ep);
    arch::SerialWrite(" bulk_out=");
    arch::SerialWriteHex(g_state.bulk_out_ep);
    arch::SerialWrite("\n");

    duetos::net::MacAddress mac{};
    for (u32 i = 0; i < 6; ++i)
        mac.octets[i] = g_state.mac[i];
    duetos::net::Ipv4Address ip{{0, 0, 0, 0}};
    duetos::net::NetStackBindInterface(g_state.iface_index, mac, ip, TxTrampoline);
    duetos::sched::SchedCreate(RxPollEntry, nullptr, "rndis-rx");
    duetos::net::DhcpStart(g_state.iface_index);
    return true;
}

} // namespace

bool RndisProbe()
{
    KLOG_TRACE_SCOPE("drivers/usb/rndis", "Probe");
    if (g_state.online)
        return true;
    xhci::XhciPauseEventConsumer(true);
    duetos::sched::SchedSleepTicks(1);

    u8 slots[8];
    const u32 n = xhci::XhciEnumerateDevices(slots, 8);
    for (u32 i = 0; i < n; ++i)
    {
        if (slots[i] == 0)
            continue;
        if (BringUp(slots[i]))
            return true; // pause stays asserted; see CDC-ECM note
        // Reset for next attempt.
        g_state.online = false;
        g_state.slot_id = 0;
        g_state.stats.online = false;
    }
    xhci::XhciPauseEventConsumer(false);
    return false;
}

RndisStats RndisStatsRead()
{
    return g_state.stats;
}

} // namespace duetos::drivers::usb
