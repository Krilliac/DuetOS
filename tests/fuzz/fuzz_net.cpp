// DuetOS — network L2/L3 ingest fuzz harness.
//
// NetStackInjectRx is the single chokepoint every NIC driver
// (e1000 / virtio-net / cdc-ecm / rndis) funnels received frames
// through. It parses an attacker-controlled Ethernet frame and
// dispatches to ArpHandleIncoming / Ipv4HandleIncoming, which
// reach ICMP / UDP / TCP. Those bytes come straight off the wire
// — a rogue host or hostile NIC's DMA — so this is the network
// stack's primary untrusted-input attack surface.
//
// The harness feeds the libFuzzer input as the raw frame on
// iface 0 (NetStackInjectRx only requires iface_index <
// kMaxInterfaces; it does not need a registered interface — it
// bumps counters then dispatches to the L3 parsers).

#include "net/stack.h"

#include <cstddef>
#include <cstdint>

// The real kernel runs NetStackInit() at boot before any frame is
// received. It is what stamps the ARP hash buckets and the TCP
// bucket/TCB table with their "empty" sentinels (kArpEntryNone /
// kBucketNone) — a zero-init table makes every bucket point at
// entry 0 and the lookup walkers loop forever. Mirror boot:
// initialise exactly once before the first injected frame, so the
// fuzzer exercises the parsers from the same state a booted box
// would, not a never-initialised one.
extern "C" int LLVMFuzzerInitialize(int*, char***)
{
    duetos::net::NetStackInit();
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    // NetStackInjectRx ignores < 14 bytes and clamps to the
    // 1514-byte bus max; stay a little above so truncated-frame
    // paths are still reachable.
    if (size > 2048)
        return 0;

    duetos::net::NetStackInjectRx(/*iface_index=*/0, data, static_cast<duetos::u64>(size));
    return 0;
}
