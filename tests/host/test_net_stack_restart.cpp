#include "net/stack.h"
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
    std::atomic<bool> block{false};
    std::atomic<bool> release{false};
};

bool Tx(void* raw_context, u32, const void*, u64)
{
    auto* context = static_cast<TxContext*>(raw_context);
    context->calls.fetch_add(1, std::memory_order_relaxed);
    context->entered.fetch_add(1, std::memory_order_release);
    while (context->block.load(std::memory_order_acquire) && !context->release.load(std::memory_order_acquire))
    {
        std::this_thread::yield();
    }
    return true;
}

bool WaitForTx(const TxContext& context, u32 entered_before)
{
    constexpr u32 kMaxYields = 10'000'000;
    for (u32 spins = 0; spins < kMaxYields; ++spins)
    {
        if (context.entered.load(std::memory_order_acquire) != entered_before)
            return true;
        std::this_thread::yield();
    }
    return false;
}

void BuildArpRequest(u8 (&frame)[42], MacAddress local_mac, Ipv4Address local_ip)
{
    for (u32 i = 0; i < 6; ++i)
    {
        frame[i] = 0xFF;
        frame[6 + i] = static_cast<u8>(0xA0 + i);
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
        frame[32 + i] = local_mac.octets[i];
    }
    frame[28] = 10;
    frame[29] = 0;
    frame[30] = 0;
    frame[31] = 2;
    for (u32 i = 0; i < 4; ++i)
        frame[38 + i] = local_ip.octets[i];
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

} // namespace

int main()
{
    using namespace duetos;
    using namespace duetos::net;

    NetStackInit();
    assert(InterfaceCount() == 0);

    const MacAddress mac_a{{0x02, 0, 0, 0, 0, 1}};
    const Ipv4Address ip_a{{10, 0, 0, 1}};
    const MacAddress peer_mac{{0x52, 0x54, 0, 0x12, 0x34, 0x56}};
    const Ipv4Address peer_ip{{10, 0, 0, 2}};

    TxContext context_a{};
    NetInterfaceBinding binding_a = kInvalidNetInterfaceBinding;
    assert(NetStackBindInterfaceOwned(0, mac_a, ip_a, &Tx, &context_a, &binding_a));
    assert(NetInterfaceBindingIsValid(binding_a));

    u8 arp_reply[42] = {};
    BuildArpReply(arp_reply, mac_a, ip_a, peer_mac, peer_ip);
    NetStackInjectRx(binding_a, arp_reply, sizeof(arp_reply));
    const ArpEntry* learned = ArpLookup(0, peer_ip);
    assert(learned != nullptr);
    assert(learned->binding_generation == binding_a.generation);

    const tcp::TcbId old_listener = tcp::Listen(0, ip_a, 4321, 1);
    assert(old_listener != tcp::kInvalidTcbId);
    assert(tcp::Alive(old_listener));

    context_a.block.store(true, std::memory_order_release);
    const u32 entered_before = context_a.entered.load(std::memory_order_acquire);
    std::atomic<tcp::TcbId> old_connection{tcp::kInvalidTcbId};
    std::thread pinned([&] { old_connection.store(tcp::Connect(0, peer_ip, 80, 40000), std::memory_order_release); });
    assert(WaitForTx(context_a, entered_before));

    // Closing admission must not clear the callback/context while one exact
    // generation TX is still inside the owner callback.
    assert(NetStackUnbindInterface(binding_a, 0) == NetInterfaceUnbindResult::DrainTimedOut);
    assert(!InterfaceIsBound(0));
    assert(InterfaceCount() == 0);
    assert(InterfaceIp(0).octets[0] == 0);

    NetInterfaceBinding premature = kInvalidNetInterfaceBinding;
    TxContext rejected_context{};
    assert(!NetStackBindInterfaceOwned(0, mac_a, ip_a, &Tx, &rejected_context, &premature));
    assert(!NetInterfaceBindingIsValid(premature));

    u8 raw_frame[14] = {};
    raw_frame[12] = 0x08;
    raw_frame[13] = 0x06;
    assert(!NetStackTransmit(binding_a, raw_frame, sizeof(raw_frame)));
    assert(!DuetosNetIfaceTx(0, raw_frame, sizeof(raw_frame)));

    context_a.release.store(true, std::memory_order_release);
    pinned.join();
    const tcp::TcbId old_connection_id = old_connection.load(std::memory_order_acquire);
    assert(old_connection_id != tcp::kInvalidTcbId);
    assert(tcp::Alive(old_connection_id));

    assert(NetStackUnbindInterface(binding_a, 10) == NetInterfaceUnbindResult::Unbound);
    assert(NetStackUnbindInterface(binding_a, 0) == NetInterfaceUnbindResult::Unbound);
    assert(!tcp::Alive(old_listener));
    assert(!tcp::Alive(old_connection_id));
    assert(ArpLookup(0, peer_ip) == nullptr);

    const MacAddress mac_b{{0x02, 0, 0, 0, 0, 2}};
    const Ipv4Address ip_b{{10, 0, 0, 3}};
    TxContext context_b{};
    NetInterfaceBinding binding_b = kInvalidNetInterfaceBinding;
    assert(NetStackBindInterfaceOwned(0, mac_b, ip_b, &Tx, &context_b, &binding_b));
    assert(binding_b.generation != binding_a.generation);
    assert(NetStackUnbindInterface(binding_a, 0) == NetInterfaceUnbindResult::StaleBinding);

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

    u8 arp_request[42] = {};
    BuildArpRequest(arp_request, mac_b, ip_b);
    NetStackInjectRx(binding_a, arp_request, sizeof(arp_request));
    assert(context_b.calls.load(std::memory_order_relaxed) == 0);
    NetStackInjectRx(binding_b, arp_request, sizeof(arp_request));
    assert(context_b.calls.load(std::memory_order_relaxed) == 1);

    assert(NetStackUnbindInterface(binding_b, 0) == NetInterfaceUnbindResult::Unbound);
    return 0;
}
