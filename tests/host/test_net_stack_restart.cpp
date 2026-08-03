#include "net/stack.h"
#include "net/socket.h"
#include "net/tcp.h"
#include "net/tcp_internal.h"

#include <atomic>
#include <cassert>
#include <cstdint>
#include <thread>

extern "C" bool DuetosNetIfaceTx(duetos::u32 iface_index, const void* frame, duetos::u64 frame_len);

namespace
{

using namespace duetos;
using namespace duetos::net;

struct TxContext
{
    std::atomic<u32> calls{0};
    std::atomic<u32> entered{0};
    std::atomic<bool> release{false};
    std::atomic<bool> block{false};
    std::atomic<u64> last_dst_mac{0};
    std::atomic<u64> last_src_mac{0};
    std::atomic<u64> last_src_ip{0};
    std::atomic<u64> last_dst_ip{0};
    std::atomic<u32> last_tcp_src_port{0};
    std::atomic<u32> last_tcp_seq{0};
};

u64 PackBytes(const u8* bytes, u32 count)
{
    u64 value = 0;
    for (u32 i = 0; i < count; ++i)
        value = (value << 8) | bytes[i];
    return value;
}

bool Tx(void* raw, u32, const void* frame, u64 frame_len)
{
    auto* context = static_cast<TxContext*>(raw);
    const auto* bytes = static_cast<const u8*>(frame);
    if (bytes != nullptr && frame_len >= 34 && bytes[12] == 0x08 && bytes[13] == 0x00)
    {
        context->last_dst_mac.store(PackBytes(bytes, 6), std::memory_order_relaxed);
        context->last_src_mac.store(PackBytes(bytes + 6, 6), std::memory_order_relaxed);
        context->last_src_ip.store(PackBytes(bytes + 26, 4), std::memory_order_relaxed);
        context->last_dst_ip.store(PackBytes(bytes + 30, 4), std::memory_order_relaxed);
        const u64 ip_header_len = static_cast<u64>(bytes[14] & 0x0F) * 4;
        const u64 tcp_offset = 14 + ip_header_len;
        if (bytes[23] == 6 && ip_header_len >= 20 && frame_len >= tcp_offset + 20)
        {
            context->last_tcp_src_port.store((static_cast<u32>(bytes[tcp_offset]) << 8) |
                                                 static_cast<u32>(bytes[tcp_offset + 1]),
                                             std::memory_order_relaxed);
            context->last_tcp_seq.store(
                (static_cast<u32>(bytes[tcp_offset + 4]) << 24) | (static_cast<u32>(bytes[tcp_offset + 5]) << 16) |
                    (static_cast<u32>(bytes[tcp_offset + 6]) << 8) | static_cast<u32>(bytes[tcp_offset + 7]),
                std::memory_order_relaxed);
        }
    }
    context->calls.fetch_add(1, std::memory_order_relaxed);
    context->entered.fetch_add(1, std::memory_order_release);
    while (context->block.load(std::memory_order_acquire) && !context->release.load(std::memory_order_acquire))
        std::this_thread::yield();
    return true;
}

bool WaitForTxEntered(const TxContext& context, u32 entered_before)
{
    constexpr u32 max_yields = 10'000'000;
    for (u32 spins = 0; spins < max_yields; ++spins)
    {
        if (context.entered.load(std::memory_order_acquire) != entered_before)
            return true;
        std::this_thread::yield();
    }
    return false;
}

void BuildArpRequest(u8 (&frame)[42], MacAddress target_mac, Ipv4Address target_ip)
{
    for (u32 i = 0; i < 6; ++i)
    {
        frame[i] = 0xFF;
        frame[6 + i] = u8(0xA0 + i);
    }
    frame[12] = 0x08;
    frame[13] = 0x06;
    frame[14] = 0x00;
    frame[15] = 0x01;
    frame[16] = 0x08;
    frame[17] = 0x00;
    frame[18] = 6;
    frame[19] = 4;
    frame[20] = 0;
    frame[21] = 1;
    for (u32 i = 0; i < 6; ++i)
    {
        frame[22 + i] = frame[6 + i];
        frame[32 + i] = target_mac.octets[i];
    }
    frame[28] = 10;
    frame[29] = 0;
    frame[30] = 0;
    frame[31] = 2;
    for (u32 i = 0; i < 4; ++i)
        frame[38 + i] = target_ip.octets[i];
}

void BuildArpReply(u8 (&frame)[42], MacAddress local_mac, Ipv4Address local_ip, MacAddress peer_mac,
                   Ipv4Address peer_ip)
{
    for (u32 i = 0; i < 6; ++i)
    {
        frame[i] = local_mac.octets[i];
        frame[6 + i] = peer_mac.octets[i];
    }
    frame[12] = 0x08;
    frame[13] = 0x06;
    frame[14] = 0x00;
    frame[15] = 0x01;
    frame[16] = 0x08;
    frame[17] = 0x00;
    frame[18] = 6;
    frame[19] = 4;
    frame[20] = 0;
    frame[21] = 2;
    for (u32 i = 0; i < 6; ++i)
    {
        frame[22 + i] = peer_mac.octets[i];
        frame[32 + i] = local_mac.octets[i];
    }
    for (u32 i = 0; i < 4; ++i)
    {
        frame[28 + i] = peer_ip.octets[i];
        frame[38 + i] = local_ip.octets[i];
    }
}

u64 BuildUdpFrame(u8* frame, u64 capacity, MacAddress dst_mac, MacAddress src_mac, Ipv4Address src_ip,
                  Ipv4Address dst_ip, u16 src_port, u16 dst_port, const u8* payload, u16 payload_len)
{
    const u64 frame_len = 14 + 20 + 8 + payload_len;
    assert(frame != nullptr);
    assert(capacity >= frame_len);
    assert(payload != nullptr || payload_len == 0);

    for (u32 i = 0; i < 6; ++i)
    {
        frame[i] = dst_mac.octets[i];
        frame[6 + i] = src_mac.octets[i];
    }
    frame[12] = 0x08;
    frame[13] = 0x00;

    u8* ip = frame + 14;
    ip[0] = 0x45;
    ip[1] = 0;
    const u16 ip_len = static_cast<u16>(20 + 8 + payload_len);
    ip[2] = static_cast<u8>(ip_len >> 8);
    ip[3] = static_cast<u8>(ip_len & 0xFF);
    ip[4] = 0;
    ip[5] = 1;
    ip[6] = 0;
    ip[7] = 0;
    ip[8] = 64;
    ip[9] = 17;
    ip[10] = 0;
    ip[11] = 0;
    for (u32 i = 0; i < 4; ++i)
    {
        ip[12 + i] = src_ip.octets[i];
        ip[16 + i] = dst_ip.octets[i];
    }
    const u16 checksum = Ipv4HeaderChecksum(ip, 20);
    ip[10] = static_cast<u8>(checksum >> 8);
    ip[11] = static_cast<u8>(checksum & 0xFF);

    u8* udp = ip + 20;
    udp[0] = static_cast<u8>(src_port >> 8);
    udp[1] = static_cast<u8>(src_port & 0xFF);
    udp[2] = static_cast<u8>(dst_port >> 8);
    udp[3] = static_cast<u8>(dst_port & 0xFF);
    const u16 udp_len = static_cast<u16>(8 + payload_len);
    udp[4] = static_cast<u8>(udp_len >> 8);
    udp[5] = static_cast<u8>(udp_len & 0xFF);
    udp[6] = 0; // optional for IPv4; the receive path accepts zero
    udp[7] = 0;
    for (u16 i = 0; i < payload_len; ++i)
        udp[8 + i] = payload[i];
    return frame_len;
}

u64 BuildTcpSynAck(u8* frame, u64 capacity, MacAddress dst_mac, MacAddress src_mac, Ipv4Address src_ip,
                   Ipv4Address dst_ip, u16 src_port, u16 dst_port, u32 ack)
{
    constexpr u64 frame_len = 14 + 20 + 20;
    assert(frame != nullptr);
    assert(capacity >= frame_len);

    for (u32 i = 0; i < 6; ++i)
    {
        frame[i] = dst_mac.octets[i];
        frame[6 + i] = src_mac.octets[i];
    }
    frame[12] = 0x08;
    frame[13] = 0x00;

    u8* ip = frame + 14;
    ip[0] = 0x45;
    ip[1] = 0;
    ip[2] = 0;
    ip[3] = 40;
    ip[4] = 0;
    ip[5] = 2;
    ip[6] = 0;
    ip[7] = 0;
    ip[8] = 64;
    ip[9] = 6;
    ip[10] = 0;
    ip[11] = 0;
    for (u32 i = 0; i < 4; ++i)
    {
        ip[12 + i] = src_ip.octets[i];
        ip[16 + i] = dst_ip.octets[i];
    }
    const u16 checksum = Ipv4HeaderChecksum(ip, 20);
    ip[10] = static_cast<u8>(checksum >> 8);
    ip[11] = static_cast<u8>(checksum & 0xFF);

    constexpr u32 peer_seq = 0x10203040;
    u8* tcp = ip + 20;
    tcp[0] = static_cast<u8>(src_port >> 8);
    tcp[1] = static_cast<u8>(src_port & 0xFF);
    tcp[2] = static_cast<u8>(dst_port >> 8);
    tcp[3] = static_cast<u8>(dst_port & 0xFF);
    tcp[4] = static_cast<u8>(peer_seq >> 24);
    tcp[5] = static_cast<u8>((peer_seq >> 16) & 0xFF);
    tcp[6] = static_cast<u8>((peer_seq >> 8) & 0xFF);
    tcp[7] = static_cast<u8>(peer_seq & 0xFF);
    tcp[8] = static_cast<u8>(ack >> 24);
    tcp[9] = static_cast<u8>((ack >> 16) & 0xFF);
    tcp[10] = static_cast<u8>((ack >> 8) & 0xFF);
    tcp[11] = static_cast<u8>(ack & 0xFF);
    tcp[12] = 0x50;
    tcp[13] = 0x12; // SYN | ACK
    tcp[14] = 0xFF;
    tcp[15] = 0xFF;
    tcp[16] = 0;
    tcp[17] = 0;
    tcp[18] = 0;
    tcp[19] = 0;
    return frame_len;
}

} // namespace

int main()
{
    using namespace duetos;
    using namespace duetos::net;

    NetStackInit();
    assert(InterfaceCount() == 0);

    const MacAddress mac_a{{0x02, 0, 0, 0, 0, 1}};
    const Ipv4Address ip_a{{10, 0, 0, 1}};
    TxContext context_a{};
    NetInterfaceBinding binding_a = kInvalidNetInterfaceBinding;
    assert(NetStackBindInterfaceOwned(0, mac_a, ip_a, &Tx, &context_a, &binding_a));
    assert(NetInterfaceBindingIsValid(binding_a));

    const MacAddress peer_mac{{0x52, 0x54, 0, 0x12, 0x34, 0x56}};
    const Ipv4Address peer_ip{{10, 0, 0, 2}};
    u8 arp_reply[42] = {};
    BuildArpReply(arp_reply, mac_a, ip_a, peer_mac, peer_ip);
    NetStackInjectRx(binding_a, arp_reply, sizeof(arp_reply));
    assert(ArpLookup(0, peer_ip) != nullptr);

    const tcp::TcbId old_listener = tcp::Listen(0, ip_a, 4321, 1);
    assert(old_listener != tcp::kInvalidTcbId);
    assert(tcp::Alive(old_listener));

    u8 tx_frame[14] = {};
    tx_frame[12] = 0x08;
    tx_frame[13] = 0x06;
    context_a.block.store(true, std::memory_order_release);
    const u32 entered_before = context_a.entered.load(std::memory_order_acquire);
    std::atomic<tcp::TcbId> old_connection{tcp::kInvalidTcbId};
    std::thread pinned([&] { old_connection.store(tcp::Connect(0, peer_ip, 80, 40000), std::memory_order_release); });
    assert(WaitForTxEntered(context_a, entered_before));

    assert(NetStackUnbindInterface(binding_a, 0) == NetInterfaceUnbindResult::DrainTimedOut);
    assert(!InterfaceIsBound(0));
    assert(InterfaceCount() == 0);
    assert(InterfaceIp(0).octets[0] == 0);
    assert(ArpLookup(0, peer_ip) == nullptr);
    assert(!DuetosNetIfaceTx(0, tx_frame, sizeof(tx_frame)));

    TxContext rejected_context{};
    NetInterfaceBinding rejected_binding{};
    assert(!NetStackBindInterfaceOwned(0, mac_a, ip_a, &Tx, &rejected_context, &rejected_binding));
    assert(!NetInterfaceBindingIsValid(rejected_binding));

    context_a.release.store(true, std::memory_order_release);
    pinned.join();
    const tcp::TcbId old_connection_id = old_connection.load(std::memory_order_acquire);
    assert(old_connection_id != tcp::kInvalidTcbId);
    assert(tcp::Alive(old_connection_id));
    assert(NetStackUnbindInterface(binding_a, 10) == NetInterfaceUnbindResult::Unbound);
    assert(NetStackUnbindInterface(binding_a, 0) == NetInterfaceUnbindResult::Unbound);
    assert(!tcp::Alive(old_listener));
    assert(!tcp::Alive(old_connection_id));
    assert(InterfaceCount() == 0);

    const MacAddress mac_b{{0x02, 0, 0, 0, 0, 2}};
    const Ipv4Address ip_b{{10, 0, 0, 3}};
    TxContext context_b{};
    NetInterfaceBinding binding_b = kInvalidNetInterfaceBinding;
    assert(NetStackBindInterfaceOwned(0, mac_b, ip_b, &Tx, &context_b, &binding_b));
    assert(binding_b.generation != binding_a.generation);

    const i32 listener_socket = SocketAlloc(kSocketDomainInet, kSocketTypeStream);
    assert(listener_socket >= 0);
    assert(SocketBind(static_cast<u32>(listener_socket), ip_b, 4322));
    assert(SocketListen(static_cast<u32>(listener_socket), 1));
    assert(SocketIsListening(static_cast<u32>(listener_socket)));

    assert(NetStackUnbindInterface(binding_a, 0) == NetInterfaceUnbindResult::StaleBinding);
    assert(ArpLookup(0, peer_ip) == nullptr);
    assert(InterfaceCountersRead(0).rx_packets == 0);
    assert(!NetStackTransmit(binding_a, tx_frame, sizeof(tx_frame)));

    tcp::internal::Tcb delayed_tcb{};
    tcp::internal::ResetTcbStorage(delayed_tcb);
    delayed_tcb.interface_binding = binding_a;
    delayed_tcb.local_mac = mac_a;
    delayed_tcb.local_ip = ip_a;
    delayed_tcb.peer_mac = peer_mac;
    delayed_tcb.peer_ip = peer_ip;
    delayed_tcb.local_port = 40000;
    delayed_tcb.peer_port = 80;
    assert(!tcp::internal::SendSegment(delayed_tcb, tcp::internal::kFlagAck, 1, 1, nullptr, 0));
    tcp::TimerTick();
    assert(context_b.calls.load(std::memory_order_relaxed) == 0);

    u8 arp_request[42] = {};
    BuildArpRequest(arp_request, mac_b, ip_b);
    NetStackInjectRx(binding_a, arp_request, sizeof(arp_request));
    assert(context_b.calls.load(std::memory_order_relaxed) == 0);
    assert(InterfaceCountersRead(0).rx_packets == 0);
    NetStackInjectRx(binding_b, arp_request, sizeof(arp_request));
    assert(context_b.calls.load(std::memory_order_relaxed) == 1);
    const IfaceCounters counters_b = InterfaceCountersRead(0);
    assert(counters_b.rx_packets == 1);
    assert(counters_b.tx_packets == 1);

    const Ipv4Address any_ip{};
    constexpr u16 wildcard_port = 45000;
    const i32 wildcard_socket = SocketAlloc(kSocketDomainInet, kSocketTypeDgram);
    assert(wildcard_socket >= 0);
    assert(SocketBind(static_cast<u32>(wildcard_socket), any_ip, wildcard_port));

    const u8 outbound_payload[] = {0x11, 0x22, 0x33, 0x44};
    context_b.block.store(true, std::memory_order_release);
    context_b.release.store(false, std::memory_order_release);
    const u32 udp_entered_before = context_b.entered.load(std::memory_order_acquire);
    std::atomic<i64> udp_send_result{-999};
    std::thread udp_pinned(
        [&]
        {
            udp_send_result.store(SocketSendDgram(static_cast<u32>(wildcard_socket), peer_ip, 7000, outbound_payload,
                                                  static_cast<u32>(sizeof(outbound_payload))),
                                  std::memory_order_release);
        });
    assert(WaitForTxEntered(context_b, udp_entered_before));

    assert(NetStackUnbindInterface(binding_b, 0) == NetInterfaceUnbindResult::DrainTimedOut);
    assert(!InterfaceIsBound(0));

    const MacAddress mac_c{{0x02, 0, 0, 0, 0, 3}};
    const Ipv4Address ip_c{{10, 0, 0, 4}};
    TxContext premature_c{};
    NetInterfaceBinding premature_binding = kInvalidNetInterfaceBinding;
    assert(!NetStackBindInterfaceOwned(0, mac_c, ip_c, &Tx, &premature_c, &premature_binding));

    context_b.release.store(true, std::memory_order_release);
    udp_pinned.join();
    assert(udp_send_result.load(std::memory_order_acquire) == static_cast<i64>(sizeof(outbound_payload)));
    assert(context_b.last_src_mac.load(std::memory_order_relaxed) == PackBytes(mac_b.octets, 6));
    assert(context_b.last_src_ip.load(std::memory_order_relaxed) == PackBytes(ip_b.octets, 4));

    assert(NetStackUnbindInterface(binding_b, 10) == NetInterfaceUnbindResult::Unbound);
    assert(NetStackUnbindInterface(binding_b, 0) == NetInterfaceUnbindResult::Unbound);

    // TCP retirement invalidates the listener TCB. Socket APIs must lazily
    // clear their cached state rather than report a phantom listener or spin
    // forever in accept on the dead generation.
    assert(SocketPollEvents(static_cast<u32>(listener_socket)) == 0);
    assert(!SocketIsListening(static_cast<u32>(listener_socket)));
    assert(SocketAcceptNonblocking(static_cast<u32>(listener_socket), nullptr, nullptr) == -1);
    assert(!SocketListen(static_cast<u32>(listener_socket), 1));

    TxContext context_c{};
    NetInterfaceBinding binding_c = kInvalidNetInterfaceBinding;
    assert(NetStackBindInterfaceOwned(0, mac_c, ip_c, &Tx, &context_c, &binding_c));
    assert(binding_c.generation != binding_b.generation);

    // The same wildcard-bound UDP socket adopts C. B's ARP entry is not
    // visible in C's generation, so this first C send is broadcast and must
    // carry C's source MAC/IP without ever invoking B again.
    const u32 b_calls_after_unbind = context_b.calls.load(std::memory_order_relaxed);
    assert(SocketSendDgram(static_cast<u32>(wildcard_socket), peer_ip, 7000, outbound_payload,
                           static_cast<u32>(sizeof(outbound_payload))) == static_cast<i64>(sizeof(outbound_payload)));
    assert(context_b.calls.load(std::memory_order_relaxed) == b_calls_after_unbind);
    assert(context_c.calls.load(std::memory_order_relaxed) == 1);
    assert(context_c.last_dst_mac.load(std::memory_order_relaxed) == 0xFFFFFFFFFFFFull);
    assert(context_c.last_src_mac.load(std::memory_order_relaxed) == PackBytes(mac_c.octets, 6));
    assert(context_c.last_src_ip.load(std::memory_order_relaxed) == PackBytes(ip_c.octets, 4));
    assert(context_c.last_dst_ip.load(std::memory_order_relaxed) == PackBytes(peer_ip.octets, 4));

    // Explicit B source ownership cannot silently migrate to C.
    constexpr u16 explicit_port = 45001;
    const i32 explicit_socket = SocketAlloc(kSocketDomainInet, kSocketTypeDgram);
    assert(explicit_socket >= 0);
    assert(SocketBind(static_cast<u32>(explicit_socket), ip_b, explicit_port));
    const u32 c_calls_before_explicit = context_c.calls.load(std::memory_order_relaxed);
    assert(SocketSendDgram(static_cast<u32>(explicit_socket), peer_ip, 7000, outbound_payload,
                           static_cast<u32>(sizeof(outbound_payload))) == -99);
    assert(context_c.calls.load(std::memory_order_relaxed) == c_calls_before_explicit);

    // Exact ingress receipts provide the receive-side half: a delayed B
    // datagram cannot enter the wildcard socket after C replaces the slot.
    const u8 inbound_payload[] = {0xD0, 0xD1, 0xD2, 0xD3};
    u8 udp_frame[64] = {};
    const u64 udp_frame_len = BuildUdpFrame(udp_frame, sizeof(udp_frame), mac_c, peer_mac, peer_ip, ip_c, 6000,
                                            wildcard_port, inbound_payload, static_cast<u16>(sizeof(inbound_payload)));
    assert(!SocketDgramReady(static_cast<u32>(wildcard_socket)));
    NetStackInjectRx(binding_b, udp_frame, udp_frame_len);
    assert(!SocketDgramReady(static_cast<u32>(wildcard_socket)));
    NetStackInjectRx(binding_c, udp_frame, udp_frame_len);
    assert(SocketDgramReady(static_cast<u32>(wildcard_socket)));

    u8 received[8] = {};
    u32 received_len = 0;
    Ipv4Address received_ip{};
    u16 received_port = 0;
    assert(SocketRecvDgram(static_cast<u32>(wildcard_socket), received, sizeof(received), &received_len, &received_ip,
                           &received_port) == static_cast<i64>(sizeof(inbound_payload)));
    assert(received_len == sizeof(inbound_payload));
    assert(received_port == 6000);
    assert(PackBytes(received_ip.octets, 4) == PackBytes(peer_ip.octets, 4));
    for (u32 i = 0; i < sizeof(inbound_payload); ++i)
        assert(received[i] == inbound_payload[i]);

    // Complete one wire-side TCP handshake on C so retirement also proves
    // connected-socket reconciliation and readiness notification.
    const i32 connected_socket = SocketAlloc(kSocketDomainInet, kSocketTypeStream);
    assert(connected_socket >= 0);
    const u32 tcp_entered_before = context_c.entered.load(std::memory_order_acquire);
    std::atomic<bool> connect_result{false};
    std::thread connector(
        [&] {
            connect_result.store(SocketConnect(static_cast<u32>(connected_socket), peer_ip, 8080),
                                 std::memory_order_release);
        });
    assert(WaitForTxEntered(context_c, tcp_entered_before));
    const u16 tcp_local_port = static_cast<u16>(context_c.last_tcp_src_port.load(std::memory_order_relaxed));
    const u32 tcp_local_seq = context_c.last_tcp_seq.load(std::memory_order_relaxed);
    assert(tcp_local_port != 0);
    u8 syn_ack_frame[64] = {};
    const u64 syn_ack_len = BuildTcpSynAck(syn_ack_frame, sizeof(syn_ack_frame), mac_c, peer_mac, peer_ip, ip_c, 8080,
                                           tcp_local_port, tcp_local_seq + 1);
    NetStackInjectRx(binding_c, syn_ack_frame, syn_ack_len);
    connector.join();
    assert(connect_result.load(std::memory_order_acquire));
    assert(SocketIsConnected(static_cast<u32>(connected_socket)));

    SocketRelease(static_cast<u32>(explicit_socket));
    SocketRelease(static_cast<u32>(wildcard_socket));
    SocketRelease(static_cast<u32>(listener_socket));
    assert(NetStackUnbindInterface(binding_c, 0) == NetInterfaceUnbindResult::Unbound);
    assert((SocketPollEvents(static_cast<u32>(connected_socket)) & 0x20u) != 0);
    assert(!SocketIsConnected(static_cast<u32>(connected_socket)));
    assert(SocketSendStream(static_cast<u32>(connected_socket), outbound_payload,
                            static_cast<u32>(sizeof(outbound_payload))) == -32);
    u8 stream_byte = 0;
    assert(SocketRecvStream(static_cast<u32>(connected_socket), &stream_byte, 1) == 0);
    SocketRelease(static_cast<u32>(connected_socket));
    assert(InterfaceCount() == 0);
    return 0;
}
