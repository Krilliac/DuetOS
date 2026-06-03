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
