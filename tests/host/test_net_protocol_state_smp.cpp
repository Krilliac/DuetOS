#include "net/firewall.h"
#include "net/stack.h"
#include "net_protocol_state_smp_frames.h"

#include <array>
#include <atomic>
#include <cassert>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <deque>
#include <mutex>
#include <thread>

namespace duetos::net
{
void NetUdpDispatch(u32 iface_index, Ipv4Address src_ip, u16 src_port, u16 dst_port, const void* payload, u64 len);
} // namespace duetos::net

namespace
{

using namespace duetos;
using namespace duetos::net;

constexpr u16 kStressPort = 47000;
constexpr u16 kDnsPort = 53;
constexpr u16 kNtpPort = 123;
constexpr u16 kDhcpServerPort = 67;
constexpr u16 kDhcpClientPort = 68;

std::atomic<u64> g_dns_responses{0};
std::atomic<u64> g_ntp_responses{0};
std::atomic<u64> g_dhcp_offers{0};
std::atomic<u64> g_dhcp_acks{0};

struct OutboundDatagram
{
    u32 iface_index{};
    Ipv4Address dst_ip{};
    u16 src_port{};
    u16 dst_port{};
    u16 payload_len{};
    std::array<u8, 512> payload{};
};

struct TxContext
{
    std::mutex mutex;
    std::condition_variable ready;
    std::deque<OutboundDatagram> pending;
    std::atomic<u64> callbacks{0};
};

bool Tx(void* raw, u32 iface_index, const void* frame, u64 frame_len)
{
    auto* context = static_cast<TxContext*>(raw);
    context->callbacks.fetch_add(1, std::memory_order_relaxed);

    // Re-enter every protected reader from the TX callback. If any protocol
    // state lock leaked across TX, this callback would deadlock immediately.
    (void)ArpStatsRead();
    (void)Ipv4StatsRead();
    (void)IcmpStatsRead();
    (void)Ipv6StatsRead();
    (void)UdpStatsRead();
    (void)DhcpLeaseRead(iface_index);
    (void)NetDnsResultRead();
    (void)NetNtpResultRead();
    (void)firewall::FwStatsRead();
    (void)firewall::FwLogTotalCount();
    firewall::Rule rules[firewall::kFwMaxRules]{};
    firewall::DenialRecord denials[firewall::kFwLogCap]{};
    firewall::ConntrackEntry conntrack[firewall::kConntrackCap]{};
    assert(firewall::FwSnapshot(rules, firewall::kFwMaxRules) <= firewall::kFwMaxRules);
    assert(firewall::FwLogSnapshot(denials, firewall::kFwLogCap) <= firewall::kFwLogCap);
    assert(firewall::ConntrackSnapshot(conntrack, firewall::kConntrackCap) <= firewall::kConntrackCap);

    if (frame == nullptr || frame_len < 42)
        return true;
    const auto* bytes = static_cast<const u8*>(frame);
    if (bytes[12] != 0x08 || bytes[13] != 0x00 || bytes[23] != 17)
        return true;
    const u64 ip_header_len = static_cast<u64>(bytes[14] & 0x0F) * 4;
    const u64 udp_offset = 14 + ip_header_len;
    if (ip_header_len < 20 || frame_len < udp_offset + 8)
        return true;
    const u16 udp_len =
        static_cast<u16>((static_cast<u16>(bytes[udp_offset + 4]) << 8) | static_cast<u16>(bytes[udp_offset + 5]));
    if (udp_len < 8 || frame_len < udp_offset + udp_len || udp_len - 8 > 512)
        return true;

    OutboundDatagram datagram{};
    datagram.iface_index = iface_index;
    for (u32 i = 0; i < 4; ++i)
        datagram.dst_ip.octets[i] = bytes[30 + i];
    datagram.src_port =
        static_cast<u16>((static_cast<u16>(bytes[udp_offset]) << 8) | static_cast<u16>(bytes[udp_offset + 1]));
    datagram.dst_port =
        static_cast<u16>((static_cast<u16>(bytes[udp_offset + 2]) << 8) | static_cast<u16>(bytes[udp_offset + 3]));
    datagram.payload_len = static_cast<u16>(udp_len - 8);
    std::memcpy(datagram.payload.data(), bytes + udp_offset + 8, datagram.payload_len);
    {
        std::lock_guard lock(context->mutex);
        context->pending.push_back(datagram);
    }
    context->ready.notify_one();
    return true;
}

bool PopDatagram(TxContext& context, OutboundDatagram& out, std::chrono::milliseconds timeout)
{
    std::unique_lock lock(context.mutex);
    if (!context.ready.wait_for(lock, timeout, [&] { return !context.pending.empty(); }))
        return false;
    out = context.pending.front();
    context.pending.pop_front();
    return true;
}

bool HasPending(TxContext& context)
{
    std::lock_guard lock(context.mutex);
    return !context.pending.empty();
}

template <typename Predicate> bool WaitUntil(Predicate predicate)
{
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
    while (std::chrono::steady_clock::now() < deadline)
    {
        if (predicate())
            return true;
        std::this_thread::yield();
    }
    return false;
}

u8 DhcpMessageType(const OutboundDatagram& datagram)
{
    if (datagram.payload_len <= 240)
        return 0;
    u32 offset = 240;
    while (offset < datagram.payload_len)
    {
        const u8 code = datagram.payload[offset++];
        if (code == 0)
            continue;
        if (code == 255 || offset >= datagram.payload_len)
            return 0;
        const u8 length = datagram.payload[offset++];
        if (offset + length > datagram.payload_len)
            return 0;
        if (code == 53 && length == 1)
            return datagram.payload[offset];
        offset += length;
    }
    return 0;
}

void DispatchDnsResponse(const OutboundDatagram& request)
{
    assert(request.payload_len >= 2);
    std::array<u8, 28> response{};
    response[0] = request.payload[0];
    response[1] = request.payload[1];
    response[2] = 0x81;
    response[3] = 0x80;
    response[7] = 1; // ANCOUNT
    response[12] = 0xC0;
    response[13] = 0x0C;
    response[15] = 1; // A
    response[17] = 1; // IN
    response[23] = 4; // RDLENGTH
    response[24] = 203;
    response[25] = 0;
    response[26] = 113;
    response[27] = 9;
    g_dns_responses.fetch_add(1, std::memory_order_relaxed);
    NetUdpDispatch(request.iface_index, request.dst_ip, kDnsPort, request.src_port, response.data(), response.size());
}

void DispatchNtpResponse(const OutboundDatagram& request)
{
    assert(request.payload_len >= 48);
    std::array<u8, 48> response{};
    response[0] = 0x1C; // LI=0, VN=3, Mode=4 (server)
    response[1] = 2;
    for (u32 i = 0; i < 8; ++i)
        response[24 + i] = request.payload[40 + i];
    constexpr u32 ntp_seconds = 2208988800u + 12345u;
    response[40] = static_cast<u8>(ntp_seconds >> 24);
    response[41] = static_cast<u8>(ntp_seconds >> 16);
    response[42] = static_cast<u8>(ntp_seconds >> 8);
    response[43] = static_cast<u8>(ntp_seconds);
    response[44] = 0x40;
    g_ntp_responses.fetch_add(1, std::memory_order_relaxed);
    NetUdpDispatch(request.iface_index, request.dst_ip, kNtpPort, request.src_port, response.data(), response.size());
}

void PutDhcpOption(std::array<u8, 304>& response, u32& offset, u8 code, const u8* value, u8 length)
{
    response[offset++] = code;
    response[offset++] = length;
    for (u32 i = 0; i < length; ++i)
        response[offset++] = value[i];
}

enum class DhcpReplyFault
{
    None,
    WrongPorts,
    WrongClientMac,
    MissingServerIdentifier,
    WrongServerIdentifier,
    WrongOfferedAddress,
    AckBeforeOffer,
};

void DispatchDhcpResponse(const OutboundDatagram& request, DhcpReplyFault fault = DhcpReplyFault::None)
{
    assert(request.payload_len >= 240);
    const u8 request_type = DhcpMessageType(request);
    assert(request_type == 1 || request_type == 3);
    std::array<u8, 304> response{};
    response[0] = 2;
    response[1] = 1;
    response[2] = 6;
    for (u32 i = 0; i < 4; ++i)
        response[4 + i] = request.payload[4 + i];
    for (u32 i = 0; i < 16; ++i)
        response[28 + i] = request.payload[28 + i];
    if (fault == DhcpReplyFault::WrongClientMac)
        response[28] ^= 1;

    const Ipv4Address lease_ip =
        fault == DhcpReplyFault::WrongOfferedAddress ? Ipv4Address{{10, 0, 0, 101}} : Ipv4Address{{10, 0, 0, 100}};
    const Ipv4Address server_ip{{10, 0, 0, 2}};
    const Ipv4Address server_id =
        fault == DhcpReplyFault::WrongServerIdentifier ? Ipv4Address{{10, 0, 0, 99}} : server_ip;
    const Ipv4Address dns_ip{{10, 0, 0, 53}};
    for (u32 i = 0; i < 4; ++i)
        response[16 + i] = lease_ip.octets[i];
    response[236] = 0x63;
    response[237] = 0x82;
    response[238] = 0x53;
    response[239] = 0x63;
    u32 offset = 240;
    const u8 reply_type = fault == DhcpReplyFault::AckBeforeOffer ? 5 : (request_type == 1 ? 2 : 5);
    if (reply_type == 2)
        g_dhcp_offers.fetch_add(1, std::memory_order_relaxed);
    else
        g_dhcp_acks.fetch_add(1, std::memory_order_relaxed);
    PutDhcpOption(response, offset, 53, &reply_type, 1);
    if (fault != DhcpReplyFault::MissingServerIdentifier)
        PutDhcpOption(response, offset, 54, server_id.octets, 4);
    PutDhcpOption(response, offset, 3, server_ip.octets, 4);
    PutDhcpOption(response, offset, 6, dns_ip.octets, 4);
    const u8 lease_seconds[4] = {0, 0, 0x0E, 0x10};
    PutDhcpOption(response, offset, 51, lease_seconds, 4);
    response[offset] = 255;
    const u16 src_port = fault == DhcpReplyFault::WrongPorts ? 1067 : kDhcpServerPort;
    const u16 dst_port = fault == DhcpReplyFault::WrongPorts ? 1068 : kDhcpClientPort;
    NetUdpDispatch(request.iface_index, server_ip, src_port, dst_port, response.data(), response.size());
}

void DispatchResponse(const OutboundDatagram& request)
{
    if (request.dst_port == kDnsPort)
        DispatchDnsResponse(request);
    else if (request.dst_port == kNtpPort)
        DispatchNtpResponse(request);
    else if (request.dst_port == kDhcpServerPort)
        DispatchDhcpResponse(request);
    else
        assert(false);
}

std::atomic<u64> g_stress_rx_calls{0};
std::atomic<bool> g_block_stress_rx{false};
std::atomic<bool> g_stress_rx_entered{false};
std::atomic<bool> g_release_stress_rx{false};

void StressRx(u32, Ipv4Address, u16, u16, const void*, u64)
{
    g_stress_rx_calls.fetch_add(1, std::memory_order_relaxed);
    if (g_block_stress_rx.load(std::memory_order_acquire))
    {
        g_stress_rx_entered.store(true, std::memory_order_release);
        while (!g_release_stress_rx.load(std::memory_order_acquire))
            std::this_thread::yield();
    }
}

NetInterfaceBinding Bind(TxContext& context, u8 mac_tail, u8 ip_tail)
{
    const MacAddress mac{{0x02, 0, 0, 0, 0, mac_tail}};
    const Ipv4Address ip{{10, 0, 0, ip_tail}};
    NetInterfaceBinding binding = kInvalidNetInterfaceBinding;
    assert(NetStackBindInterfaceOwned(0, mac, ip, Tx, &context, &binding));
    return binding;
}

void InsertPeer(Ipv4Address ip, u8 mac_tail)
{
    const MacAddress mac{{0x52, 0x54, 0, 0, 0, mac_tail}};
    ArpInsert(0, ip, mac);
    ArpEntry entry{};
    assert(ArpLookup(0, ip, &entry));
}

void ExpectNoArp(Ipv4Address ip)
{
    ArpEntry entry{};
    assert(!ArpLookup(0, ip, &entry));
}

firewall::Rule IngressDenyRule(firewall::Proto proto, u16 dst_port)
{
    firewall::Rule rule{};
    rule.active = true;
    rule.dir = firewall::Direction::Ingress;
    rule.proto = proto;
    rule.src = firewall::Ipv4Prefix{{{0, 0, 0, 0}}, 0};
    rule.dst = firewall::Ipv4Prefix{{{0, 0, 0, 0}}, 0};
    rule.src_port = firewall::PortRange{0, 0xFFFF};
    rule.dst_port = firewall::PortRange{dst_port, dst_port};
    rule.action = firewall::Action::Deny;
    return rule;
}

} // namespace

int main()
{
    using namespace duetos;
    using namespace duetos::net;

    NetStackInit();
    TxContext tx_context{};
    const Ipv4Address dns_server{{10, 0, 0, 53}};
    const Ipv4Address ntp_server{{10, 0, 0, 123}};

    // A delayed DNS response must not survive the A -> B replacement.
    NetInterfaceBinding binding_a = Bind(tx_context, 1, 1);
    InsertPeer(dns_server, 53);
    DnsQueryReceipt stale_dns_receipt = kInvalidDnsQueryReceipt;
    assert(NetDnsQueryA(0, dns_server, "smp.example", &stale_dns_receipt));
    assert(DnsQueryReceiptIsValid(stale_dns_receipt));
    OutboundDatagram stale_dns{};
    assert(PopDatagram(tx_context, stale_dns, std::chrono::seconds(10)));
    assert(stale_dns.dst_port == kDnsPort);
    assert(NetStackUnbindInterface(binding_a, 0) == NetInterfaceUnbindResult::Unbound);

    NetInterfaceBinding binding_b = Bind(tx_context, 2, 2);
    assert(binding_b.generation != binding_a.generation);
    ExpectNoArp(dns_server);
    DispatchDnsResponse(stale_dns);
    assert(!NetDnsResultRead().resolved);
    assert(!NetDnsResultRead(stale_dns_receipt).resolved);

    // The fixed NTP port is likewise tied to the exact B transaction.
    InsertPeer(ntp_server, 123);
    NtpQueryReceipt stale_ntp_receipt = kInvalidNtpQueryReceipt;
    assert(NetNtpQuery(0, ntp_server, &stale_ntp_receipt));
    assert(NtpQueryReceiptIsValid(stale_ntp_receipt));
    OutboundDatagram stale_ntp{};
    assert(PopDatagram(tx_context, stale_ntp, std::chrono::seconds(10)));
    assert(stale_ntp.dst_port == kNtpPort);
    assert(NetStackUnbindInterface(binding_b, 0) == NetInterfaceUnbindResult::Unbound);

    NetInterfaceBinding binding_c = Bind(tx_context, 3, 3);
    assert(binding_c.generation != binding_b.generation);
    DispatchNtpResponse(stale_ntp);
    assert(!NetNtpResultRead().synced);
    assert(!NetNtpResultRead(stale_ntp_receipt).synced);

    // DHCP keeps one shared port-68 handler, so the transaction token and
    // interface generation (not handler removal) must reject C's late OFFER.
    assert(DhcpStart(0));
    OutboundDatagram stale_dhcp{};
    assert(PopDatagram(tx_context, stale_dhcp, std::chrono::seconds(10)));
    assert(stale_dhcp.dst_port == kDhcpServerPort);
    assert(NetStackUnbindInterface(binding_c, 0) == NetInterfaceUnbindResult::Unbound);

    NetInterfaceBinding binding_d = Bind(tx_context, 4, 4);
    assert(binding_d.generation != binding_c.generation);
    DispatchDhcpResponse(stale_dhcp);
    assert(!DhcpLeaseRead(0).valid);

    InsertPeer(dns_server, 53);
    InsertPeer(ntp_server, 123);

    // Two same-generation queries may supersede each other, but their
    // receipts must never alias. Deliver the responses in the hostile order:
    // old after new publication, then current.
    DnsQueryReceipt obsolete_dns_receipt = kInvalidDnsQueryReceipt;
    assert(NetDnsQueryA(0, dns_server, "old.smp.example", &obsolete_dns_receipt));
    OutboundDatagram obsolete_dns{};
    assert(PopDatagram(tx_context, obsolete_dns, std::chrono::seconds(10)));
    DnsQueryReceipt current_dns_receipt = kInvalidDnsQueryReceipt;
    assert(NetDnsQueryA(0, dns_server, "current.smp.example", &current_dns_receipt));
    OutboundDatagram current_dns{};
    assert(PopDatagram(tx_context, current_dns, std::chrono::seconds(10)));
    assert(obsolete_dns_receipt.transaction != current_dns_receipt.transaction);
    DispatchDnsResponse(obsolete_dns);
    assert(!NetDnsResultRead(obsolete_dns_receipt).resolved);
    assert(!NetDnsResultRead(current_dns_receipt).resolved);
    DispatchDnsResponse(current_dns);
    assert(!NetDnsResultRead(obsolete_dns_receipt).resolved);
    assert(NetDnsResultRead(current_dns_receipt).resolved);

    NtpQueryReceipt obsolete_ntp_receipt = kInvalidNtpQueryReceipt;
    assert(NetNtpQuery(0, ntp_server, &obsolete_ntp_receipt));
    OutboundDatagram obsolete_ntp{};
    assert(PopDatagram(tx_context, obsolete_ntp, std::chrono::seconds(10)));
    NtpQueryReceipt current_ntp_receipt = kInvalidNtpQueryReceipt;
    assert(NetNtpQuery(0, ntp_server, &current_ntp_receipt));
    OutboundDatagram current_ntp{};
    assert(PopDatagram(tx_context, current_ntp, std::chrono::seconds(10)));
    assert(obsolete_ntp_receipt.transaction != current_ntp_receipt.transaction);
    DispatchNtpResponse(obsolete_ntp);
    assert(!NetNtpResultRead(obsolete_ntp_receipt).synced);
    assert(!NetNtpResultRead(current_ntp_receipt).synced);
    DispatchNtpResponse(current_ntp);
    assert(!NetNtpResultRead(obsolete_ntp_receipt).synced);
    assert(NetNtpResultRead(current_ntp_receipt).synced);

    // DHCP accepts only an exact 67->68 BOOTP reply for this generation and
    // client MAC. OFFER must identify a server; ACK must follow REQUEST and
    // repeat the selected server/address.
    assert(DhcpStart(0));
    OutboundDatagram dhcp_discover{};
    assert(PopDatagram(tx_context, dhcp_discover, std::chrono::seconds(10)));
    DispatchDhcpResponse(dhcp_discover, DhcpReplyFault::AckBeforeOffer);
    DispatchDhcpResponse(dhcp_discover, DhcpReplyFault::WrongPorts);
    DispatchDhcpResponse(dhcp_discover, DhcpReplyFault::WrongClientMac);
    DispatchDhcpResponse(dhcp_discover, DhcpReplyFault::MissingServerIdentifier);
    assert(!DhcpLeaseRead(0).valid);
    assert(!HasPending(tx_context));
    DispatchDhcpResponse(dhcp_discover);
    OutboundDatagram dhcp_request{};
    assert(PopDatagram(tx_context, dhcp_request, std::chrono::seconds(10)));
    DispatchDhcpResponse(dhcp_discover); // OFFER in Requesting is stale.
    assert(!HasPending(tx_context));
    DispatchDhcpResponse(dhcp_request, DhcpReplyFault::WrongServerIdentifier);
    DispatchDhcpResponse(dhcp_request, DhcpReplyFault::WrongOfferedAddress);
    DispatchDhcpResponse(dhcp_request, DhcpReplyFault::WrongPorts);
    DispatchDhcpResponse(dhcp_request, DhcpReplyFault::WrongClientMac);
    assert(!DhcpLeaseRead(0).valid);
    DispatchDhcpResponse(dhcp_request);
    assert(DhcpLeaseRead(0).valid);

    // Keep one immutable deny rule producing log traffic while another is
    // toggled concurrently with packet evaluation and UI-style snapshots.
    firewall::FwSetDefaultPolicy(firewall::Direction::Ingress, firewall::Action::Allow);
    firewall::FwSetDefaultPolicy(firewall::Direction::Egress, firewall::Action::Allow);
    const u32 fixed_deny_index = firewall::FwAdd(IngressDenyRule(firewall::Proto::Tcp, 445));
    const u32 toggled_deny_index = firewall::FwAdd(IngressDenyRule(firewall::Proto::Udp, kStressPort));
    assert(fixed_deny_index < firewall::kFwMaxRules);
    assert(toggled_deny_index < firewall::kFwMaxRules);

    // Establish deterministic ICMP and IPv6 coverage before the hostile
    // phase. The same paths continue racing below.
    constexpr u16 kPingId = 0x2A2A;
    const Ipv4Address local_ip{{10, 0, 0, 100}};
    const Ipv4Address ping_peer{{192, 0, 2, 42}};
    InsertPeer(ping_peer, 42);
    NetPingArm(kPingId, 1);
    assert(NetIcmpSendEcho(0, ping_peer, kPingId, 1));
    const auto initial_reply = host_test::BuildIpv4IcmpEchoFrame(ping_peer, local_ip, 0, kPingId, 1);
    NetStackInjectRx(binding_d, initial_reply.data(), initial_reply.size());
    assert(NetPingRead().replied);

    const auto initial_request = host_test::BuildIpv4IcmpEchoFrame(ping_peer, local_ip, 8, kPingId, 2);
    NetStackInjectRx(binding_d, initial_request.data(), initial_request.size());
    const auto initial_ipv6 = host_test::BuildIpv6EmptyFrame();
    NetStackInjectRx(binding_d, initial_ipv6.data(), initial_ipv6.size());
    assert(IcmpStatsRead().echo_requests_tx != 0);
    assert(IcmpStatsRead().echo_replies_rx != 0);
    assert(Ipv6StatsRead().rx_packets != 0);

    // Unbind must close admission without holding the table lock, then wait
    // for the already-snapshotted callback before making the slot reusable.
    g_block_stress_rx.store(true, std::memory_order_release);
    g_stress_rx_entered.store(false, std::memory_order_release);
    g_release_stress_rx.store(false, std::memory_order_release);
    assert(NetUdpBindRx(kStressPort, StressRx));
    const Ipv4Address stress_peer{{192, 0, 2, 1}};
    std::thread held_dispatch([&] { NetUdpDispatch(0, stress_peer, 9000, kStressPort, nullptr, 0); });
    assert(WaitUntil([] { return g_stress_rx_entered.load(std::memory_order_acquire); }));

    std::atomic<bool> drain_done{false};
    std::thread draining_unbind(
        [&]
        {
            assert(NetUdpBindRx(kStressPort, nullptr));
            drain_done.store(true, std::memory_order_release);
        });
    assert(WaitUntil([] { return !NetUdpBindRx(kStressPort, StressRx); }));
    assert(!drain_done.load(std::memory_order_acquire));
    g_release_stress_rx.store(true, std::memory_order_release);
    held_dispatch.join();
    draining_unbind.join();
    assert(drain_done.load(std::memory_order_acquire));
    g_block_stress_rx.store(false, std::memory_order_release);

    std::atomic<bool> running{true};
    std::atomic<bool> responder_stop{false};
    std::atomic<u16> active_ping_sequence{2};
    std::thread responder(
        [&]
        {
            while (!responder_stop.load(std::memory_order_acquire) || HasPending(tx_context))
            {
                OutboundDatagram request{};
                if (PopDatagram(tx_context, request, std::chrono::milliseconds(10)))
                    DispatchResponse(request);
            }
        });

    std::thread arp_writer_a(
        [&]
        {
            u32 iteration = 0;
            while (running.load(std::memory_order_acquire))
            {
                const Ipv4Address ip{{10, 20, 1, static_cast<u8>(1 + (iteration % 8))}};
                const MacAddress mac{{0x52, 0x54, 1, 0, 0, static_cast<u8>(iteration)}};
                ArpInsert(0, ip, mac);
                ArpEntry entry{};
                if (ArpLookup(0, ip, &entry))
                    assert(entry.binding_generation == binding_d.generation);
                ++iteration;
            }
        });

    std::thread arp_writer_b(
        [&]
        {
            u32 iteration = 0;
            while (running.load(std::memory_order_acquire))
            {
                const Ipv4Address ip{{10, 20, 2, static_cast<u8>(1 + (iteration % 8))}};
                const MacAddress mac{{0x52, 0x54, 2, 0, 0, static_cast<u8>(iteration)}};
                ArpInsert(0, ip, mac);
                (void)ArpEntryCount();
                ++iteration;
            }
        });

    std::thread udp_binder(
        [&]
        {
            while (running.load(std::memory_order_acquire))
            {
                assert(NetUdpBindRx(kStressPort, StressRx));
                std::this_thread::yield();
                assert(NetUdpBindRx(kStressPort, nullptr));
            }
        });

    std::thread udp_dispatcher(
        [&]
        {
            const Ipv4Address peer{{192, 0, 2, 1}};
            while (running.load(std::memory_order_acquire))
                NetUdpDispatch(0, peer, 9000, kStressPort, nullptr, 0);
        });

    std::thread packet_injector(
        [&]
        {
            u16 iteration = 2;
            while (running.load(std::memory_order_acquire))
            {
                const auto udp = host_test::BuildIpv4UdpFrame(ping_peer, local_ip, 9000, kStressPort);
                NetStackInjectRx(binding_d, udp.data(), udp.size());

                const auto request = host_test::BuildIpv4IcmpEchoFrame(ping_peer, local_ip, 8, kPingId, iteration);
                NetStackInjectRx(binding_d, request.data(), request.size());

                const u16 reply_sequence = active_ping_sequence.load(std::memory_order_acquire);
                const auto reply = host_test::BuildIpv4IcmpEchoFrame(ping_peer, local_ip, 0, kPingId, reply_sequence);
                NetStackInjectRx(binding_d, reply.data(), reply.size());

                const auto ipv6 = host_test::BuildIpv6EmptyFrame();
                NetStackInjectRx(binding_d, ipv6.data(), ipv6.size());
                ++iteration;
            }
        });

    std::thread ping_writer(
        [&]
        {
            u16 sequence = 3;
            while (running.load(std::memory_order_acquire))
            {
                NetPingArm(kPingId, sequence);
                active_ping_sequence.store(sequence, std::memory_order_release);
                (void)NetIcmpSendEcho(0, ping_peer, kPingId, sequence);
                (void)NetPingRead();
                ++sequence;
            }
        });

    std::thread firewall_admin(
        [&]
        {
            u32 iteration = 0;
            while (running.load(std::memory_order_acquire))
            {
                firewall::FwToggle(toggled_deny_index);
                firewall::FwSetDefaultPolicy(firewall::Direction::Ingress,
                                             (iteration & 1) != 0 ? firewall::Action::Deny : firewall::Action::Allow);
                if ((iteration & 7) == 0)
                    firewall::ConntrackReset();
                ++iteration;
            }
        });

    std::thread firewall_evaluator(
        [&]
        {
            const Ipv4Address remote{{198, 51, 100, 25}};
            while (running.load(std::memory_order_acquire))
            {
                (void)firewall::FwEvaluate(firewall::Direction::Egress, firewall::Proto::Udp, local_ip, remote, 52000,
                                           53000, 0, nullptr);
                (void)firewall::FwEvaluate(firewall::Direction::Ingress, firewall::Proto::Udp, remote, local_ip, 53000,
                                           52000, 0, nullptr);
                (void)firewall::FwEvaluate(firewall::Direction::Ingress, firewall::Proto::Tcp, remote, local_ip, 1234,
                                           445, firewall::kTcpSyn, nullptr);
            }
        });

    std::thread result_reader(
        [&]
        {
            while (running.load(std::memory_order_acquire))
            {
                (void)ArpStatsRead();
                (void)Ipv4StatsRead();
                (void)IcmpStatsRead();
                (void)Ipv6StatsRead();
                (void)UdpStatsRead();
                (void)DhcpLeaseRead(0);
                (void)NetDnsResultRead();
                (void)NetNtpResultRead();
                assert(!NetDnsResultRead(stale_dns_receipt).resolved);
                assert(!NetDnsResultRead(obsolete_dns_receipt).resolved);
                assert(!NetNtpResultRead(stale_ntp_receipt).synced);
                assert(!NetNtpResultRead(obsolete_ntp_receipt).synced);
                (void)firewall::FwDefaultPolicy(firewall::Direction::Ingress);
                (void)firewall::FwStatsRead();
                (void)firewall::FwLogTotalCount();
                firewall::Rule rules[firewall::kFwMaxRules]{};
                firewall::DenialRecord denials[firewall::kFwLogCap]{};
                firewall::ConntrackEntry conntrack[firewall::kConntrackCap]{};
                assert(firewall::FwSnapshot(rules, firewall::kFwMaxRules) <= firewall::kFwMaxRules);
                assert(firewall::FwLogSnapshot(denials, firewall::kFwLogCap) <= firewall::kFwLogCap);
                assert(firewall::ConntrackSnapshot(conntrack, firewall::kConntrackCap) <= firewall::kConntrackCap);
            }
        });

    for (u32 iteration = 0; iteration < 48; ++iteration)
    {
        // Other threads read the old result while this task publishes a new
        // transaction and the responder commits from the RX side.
        DnsQueryReceipt dns_receipt = kInvalidDnsQueryReceipt;
        assert(NetDnsQueryA(0, dns_server, "smp.example", &dns_receipt));
        assert(WaitUntil(
            [dns_receipt]
            {
                const DnsResult result = NetDnsResultRead(dns_receipt);
                return result.resolved && result.ip.octets[0] == 203 && result.ip.octets[3] == 9;
            }));

        NtpQueryReceipt ntp_receipt = kInvalidNtpQueryReceipt;
        assert(NetNtpQuery(0, ntp_server, &ntp_receipt));
        assert(WaitUntil(
            [ntp_receipt]
            {
                const NtpResult result = NetNtpResultRead(ntp_receipt);
                return result.synced && result.unix_secs == 12345 && result.stratum == 2;
            }));

        assert(DhcpStart(0));
        const bool lease_ready = WaitUntil(
            []
            {
                const DhcpLease lease = DhcpLeaseRead(0);
                return lease.valid && lease.ip.octets[3] == 100 && lease.lease_secs == 3600;
            });
        if (!lease_ready)
        {
            std::fprintf(stderr, "DHCP timeout at iteration %u (dns=%llu ntp=%llu offers=%llu acks=%llu pending=%d)\n",
                         iteration, static_cast<unsigned long long>(g_dns_responses.load(std::memory_order_relaxed)),
                         static_cast<unsigned long long>(g_ntp_responses.load(std::memory_order_relaxed)),
                         static_cast<unsigned long long>(g_dhcp_offers.load(std::memory_order_relaxed)),
                         static_cast<unsigned long long>(g_dhcp_acks.load(std::memory_order_relaxed)),
                         HasPending(tx_context) ? 1 : 0);
        }
        assert(lease_ready);
    }

    running.store(false, std::memory_order_release);
    arp_writer_a.join();
    arp_writer_b.join();
    udp_binder.join();
    udp_dispatcher.join();
    packet_injector.join();
    ping_writer.join();
    firewall_admin.join();
    firewall_evaluator.join();
    result_reader.join();

    responder_stop.store(true, std::memory_order_release);
    tx_context.ready.notify_all();
    responder.join();

    assert(NetUdpBindRx(kStressPort, nullptr));
    assert(g_stress_rx_calls.load(std::memory_order_relaxed) != 0);
    assert(g_dns_responses.load(std::memory_order_relaxed) == 51);
    assert(g_ntp_responses.load(std::memory_order_relaxed) == 51);
    assert(g_dhcp_offers.load(std::memory_order_relaxed) == 54);
    assert(g_dhcp_acks.load(std::memory_order_relaxed) == 54);
    assert(ArpStatsRead().inserts != 0);
    assert(Ipv4StatsRead().rx_packets != 0);
    assert(Ipv4StatsRead().rx_icmp != 0);
    assert(IcmpStatsRead().echo_requests_rx != 0);
    assert(IcmpStatsRead().echo_requests_tx != 0);
    assert(IcmpStatsRead().echo_replies_rx != 0);
    assert(Ipv6StatsRead().rx_packets != 0);
    assert(Ipv6StatsRead().rx_other_proto != 0);
    assert(UdpStatsRead().rx_packets != 0);
    const firewall::Stats firewall_stats = firewall::FwStatsRead();
    assert(firewall_stats.ingress_checked != 0);
    assert(firewall_stats.egress_checked != 0);
    assert(firewall_stats.ingress_denied != 0);
    assert(firewall::FwLogTotalCount() != 0);
    assert(tx_context.callbacks.load(std::memory_order_relaxed) >= 48 * 4);

    firewall::FwSetDefaultPolicy(firewall::Direction::Ingress, firewall::Action::Allow);
    firewall::FwRemove(toggled_deny_index);
    firewall::FwRemove(fixed_deny_index);

    assert(NetStackUnbindInterface(binding_d, 0) == NetInterfaceUnbindResult::Unbound);
    ExpectNoArp(dns_server);
    assert(!DhcpLeaseRead(0).valid);
    assert(!NetDnsResultRead().resolved);
    assert(!NetNtpResultRead().synced);
    assert(!NetDnsResultRead(stale_dns_receipt).resolved);
    assert(!NetDnsResultRead(obsolete_dns_receipt).resolved);
    assert(!NetNtpResultRead(stale_ntp_receipt).synced);
    assert(!NetNtpResultRead(obsolete_ntp_receipt).synced);
    return 0;
}
