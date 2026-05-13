#include "drivers/virtio/virtio.h"
#include "drivers/virtio/virtio_pci.h"

#include "log/klog.h"
#include "mm/frame_allocator.h"
#include "mm/page.h"

/*
 * virtio-console — paravirtualised serial.
 *
 * Spec: virtio 1.0 §5.3. Two-queue minimum for one port:
 *
 *   queue 0  receiveq    host → guest input (keyboard / pipe)
 *   queue 1  transmitq   guest → host output (log / stdout)
 *
 * Multi-port (`VIRTIO_CONSOLE_F_MULTIPORT`) adds two control
 * queues + per-port queue pairs. v0 stays single-port, TX-only —
 * the immediate value is "let the kernel forward its log to
 * QEMU's `-chardev` sink without leaning on the legacy
 * 16550 UART path", which the transmitq already provides.
 *
 * Buffers are raw bytes — no per-buffer header (unlike
 * virtio-net's 12-byte virtio_net_hdr). A single descriptor per
 * publish call, with `flags = 0` (driver-write only; device
 * doesn't write back). We poll the used ring before each post
 * to drain any old completions, then publish and poll for
 * THIS post's completion.
 *
 * Context: kernel. Allocation happens at probe time only; the
 * write path reuses the static TX scratch page so the runtime
 * is allocation-free. Single in-flight assumption matches
 * virtio-blk's v0 model — fine for the current single-CPU
 * boot-log workload, GAPped for SMP / concurrent emitters.
 */

namespace duetos::drivers::virtio
{

namespace
{

// Spec landmark — kept named so the future multiport slice
// reads against the same identifier the spec uses.
[[maybe_unused]] inline constexpr u64 kConsoleFeatureMultiport = 1ULL << 1;

struct ConsoleState
{
    bool up;
    u8 _pad[7];
    VirtioPciLayout layout;
    VirtioQueue txq;
    mm::PhysAddr tx_buf_phys;
    u8* tx_buf_virt;
};

constinit ConsoleState g_console = {};
inline constexpr u32 kTxBufLen = 256; // < 4 KiB page; one transmit at a time.

// Drain any already-completed used-ring entries. Called before
// each post so the descriptor index 0 doesn't collide with a
// stale completion. Cheap (just reads `used_hdr->idx`).
void DrainUsed(VirtioQueue* q)
{
    u32 head = 0;
    u32 used_len = 0;
    while (VirtioQueueTryPop(q, &head, &used_len))
    {
        // Discard — TX completions carry no caller-relevant info.
    }
}

} // namespace

bool VirtioConsoleProbe(const VirtioPciLayout& L)
{
    if (g_console.up)
    {
        KLOG_WARN("drivers/virtio/console", "second device detected; v0 supports only one");
        return false;
    }

    VirtioPciLayout layout = L;
    // We only ask for VERSION_1. Multiport adds control queues +
    // a richer feature surface; skipping it keeps v0 to two
    // queues. The device still works with multiport unselected —
    // it falls back to single-port single-emergency mode.
    if (!VirtioNegotiate(&layout, kFeatureVersion1))
    {
        KLOG_WARN("drivers/virtio/console", "feature negotiation failed");
        return false;
    }
    if (layout.num_queues < 2)
    {
        KLOG_WARN_V("drivers/virtio/console", "device exposes too few queues", static_cast<u64>(layout.num_queues));
        return false;
    }

    // queue_index 1 is the port-0 transmitq. We skip queue 0
    // (receiveq) for v0 — there's no consumer for host-typed
    // bytes today. The device tolerates an unconfigured RX
    // queue: it simply has nowhere to put inbound bytes, which
    // is correct for a TX-only log forwarder.
    if (!VirtioQueueSetup(&layout, &g_console.txq, /*queue_index=*/1, kVirtqDefaultSize))
    {
        KLOG_WARN("drivers/virtio/console", "transmitq setup failed");
        return false;
    }

    // Static TX scratch — one page is plenty for the line-at-a-
    // time write pattern. A consumer that wants to ship more
    // than 256 bytes per call splits the buffer at the caller.
    const mm::PhysAddr phys = mm::AllocateFrame();
    if (phys == mm::kNullFrame)
    {
        KLOG_WARN("drivers/virtio/console", "tx buffer alloc failed");
        return false;
    }
    g_console.tx_buf_phys = phys;
    g_console.tx_buf_virt = static_cast<u8*>(mm::PhysToVirt(phys));
    for (u32 i = 0; i < 4096; ++i)
        g_console.tx_buf_virt[i] = 0;
    g_console.layout = layout;
    g_console.up = true;

    KLOG_INFO_V("drivers/virtio/console", "attached (TX-only port 0)", static_cast<u64>(layout.num_queues));
    // Hello-world emit so the boot log on the HOST side carries
    // a grep-able sentinel proving the round-trip works without
    // anyone calling VirtioConsoleWrite from the rest of the
    // kernel yet.
    static const char kHello[] = "[duetos] virtio-console online\n";
    VirtioConsoleWrite(kHello, sizeof(kHello) - 1);
    return true;
}

bool VirtioConsoleWrite(const char* buf, u32 len)
{
    if (!g_console.up || buf == nullptr || len == 0)
        return false;
    if (len > kTxBufLen)
        len = kTxBufLen;

    // Drain stale completions (single in-flight model: any
    // outstanding completion is from a previous post we never
    // bothered to consume).
    DrainUsed(&g_console.txq);

    for (u32 i = 0; i < len; ++i)
        g_console.tx_buf_virt[i] = static_cast<u8>(buf[i]);

    VirtqDesc* d = const_cast<VirtqDesc*>(g_console.txq.desc);
    d[0].addr = g_console.tx_buf_phys;
    d[0].len = len;
    d[0].flags = 0; // driver-write only; device doesn't touch.
    d[0].next = 0;

    VirtioQueuePublish(&g_console.layout, &g_console.txq, /*desc_head=*/0);
    for (u32 spin = 0; spin < 2000000; ++spin)
    {
        u32 head = 0;
        u32 used_len = 0;
        if (VirtioQueueTryPop(&g_console.txq, &head, &used_len))
            return true;
        asm volatile("pause" ::: "memory");
    }
    KLOG_WARN("drivers/virtio/console", "TX completion poll timed out");
    return false;
}

} // namespace duetos::drivers::virtio
