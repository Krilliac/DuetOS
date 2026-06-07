// Link stubs for kernel symbols the network-stack TUs reference
// (NIC registry, Wi-Fi init, scheduler wait-queues, the Linux
// pipe layer pulled in transitively by socket.cpp) but that the
// L2/L3 ingest fuzzer does not exercise: NetStackInjectRx parses
// the frame and dispatches to the ARP / IPv4 / ICMP / UDP / TCP
// byte walkers; the socket/pipe/scheduler machinery is the
// syscall side, never reached from a raw RX frame. Real headers
// are included for exact signatures (they compile in the
// stack.cpp TU already).

#include "debug/probes.h"
#include "drivers/net/net.h"
#include "net/wifi.h"
#include "sched/sched.h"
#include "subsystems/linux/syscall_pipe.h"

namespace duetos::drivers::net
{
u64 NicCount()
{
    return 0;
}
const NicInfo& Nic(u64)
{
    // NicCount() == 0, so callers never reach here; a static
    // zero-initialised instance satisfies the reference return.
    static const NicInfo k_dummy{};
    return k_dummy;
}
} // namespace duetos::drivers::net

namespace duetos::net
{
void WifiInit() {}
} // namespace duetos::net

namespace duetos::sched
{
Task* SchedCreate(TaskEntry, void*, const char*, TaskPriority)
{
    return nullptr;
}
void SchedSleepTicks(u64) {}
void WaitQueueBlock(WaitQueue*) {}
bool WaitQueueBlockTimeout(WaitQueue*, u64)
{
    return false;
}
Task* WaitQueueWakeOne(WaitQueue*)
{
    return nullptr;
}
u64 WaitQueueWakeAll(WaitQueue*)
{
    return 0;
}
} // namespace duetos::sched

namespace duetos::subsystems::linux::internal
{
i32 PipeAlloc()
{
    return -1;
}
i64 PipeRead(u32, u64, u64)
{
    return -1;
}
i64 PipeWrite(u32, u64, u64)
{
    return -1;
}
// Kernel-buffer pipe I/O — socket.cpp's stream send/recv funnel
// through these. The frame fuzzer drives the RX parse path, not the
// loopback stream, so a no-op (no bytes moved) satisfies the link.
i64 PipeReadKernel(u32, u8*, u64)
{
    return -1;
}
i64 PipeWriteKernel(u32, const u8*, u64)
{
    return -1;
}
void PipeReleaseRead(u32) {}
void PipeReleaseWrite(u32) {}
bool PipeReadReady(u32)
{
    return false;
}
bool PipeWriteReady(u32)
{
    return false;
}
} // namespace duetos::subsystems::linux::internal

namespace duetos::debug
{
// ipv6.cpp's Ipv6SelfTest() fires KBP_PROBE on a failed sub-check; the
// frame fuzzer never runs the self-test, so a no-op satisfies the link.
void ProbeFire(ProbeId, u64, u64) {}
} // namespace duetos::debug

namespace duetos::core
{
// Kernel CSPRNG. tcp_timer.cpp seeds the ISN secret and stack.cpp's DNS
// query draws the transaction id / ephemeral source port from this
// (security hardening ML-02 / ML-03). The fuzzer drives the RX parse path,
// where randomness quality is irrelevant — a deterministic LCG keeps fuzz
// crashes reproducible while satisfying the link.
u64 RandomU64()
{
    static u64 s = 0x9E3779B97F4A7C15ull;
    s = s * 6364136223846793005ull + 1442695040888963407ull;
    return s;
}
} // namespace duetos::core
