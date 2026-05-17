#include "drivers/virtio/virtio.h"
#include "drivers/virtio/virtio_pci.h"

#include "log/klog.h"
#include "mm/frame_allocator.h"
#include "mm/page.h"
#include "util/random.h"

/*
 * virtio-rng — entropy provider.
 *
 * Real driver: one virtqueue (requestq). Driver pushes a single
 * device-writable descriptor pointing at a kernel-owned buffer;
 * device fills it with hardware/host entropy and signals via the
 * used ring. We poll the used ring (no IRQ in v0); when the
 * completion lands, the buffer contents are guaranteed-fresh
 * entropy bytes the kernel can mix into its pool.
 *
 * v0 lands the full request/response round-trip, mixes the
 * pulled bytes into the kernel entropy pool via
 * `core::RandomMix`, and logs the first 8 bytes per attach
 * as a grep-able boot-log sentinel. The mix is XOR-fold-only
 * so a misbehaving QEMU device can never weaken the pool.
 */

namespace duetos::drivers::virtio
{

namespace
{
constinit VirtioQueue g_rng_q = {};
constinit bool g_entropy_pulled = false;

bool PullEntropy(VirtioPciLayout* L, VirtioQueue* q)
{
    // Allocate one page as the device-write buffer. virtio-rng has
    // no per-request header — the device just writes random bytes
    // into the supplied buffer.
    const mm::PhysAddr buf_phys = mm::AllocateFrame();
    if (buf_phys == mm::kNullFrame)
    {
        KLOG_WARN("drivers/virtio/rng", "entropy buffer alloc failed");
        return false;
    }
    void* buf_virt = mm::PhysToVirt(buf_phys);
    u8* buf = static_cast<u8*>(buf_virt);
    constexpr u32 kBufLen = 64;
    for (u32 i = 0; i < kBufLen; ++i)
        buf[i] = 0;

    // Fill descriptor 0: device-writable, points at our buffer.
    q->desc[0].addr = buf_phys;
    q->desc[0].len = kBufLen;
    q->desc[0].flags = kVirtqDescWrite;
    q->desc[0].next = 0;

    // Publish + notify, then poll for completion. virtio-rng on
    // QEMU completes instantly; cap the poll at ~10ms equivalent
    // (1M `pause` iterations) so a stuck device doesn't hang
    // boot.
    VirtioQueuePublish(L, q, /*desc_head=*/0);
    for (u32 spin = 0; spin < 1000000; ++spin)
    {
        u32 head = 0;
        u32 used_len = 0;
        if (VirtioQueueTryPop(q, &head, &used_len))
        {
            // Feed the pulled bytes into the kernel entropy pool.
            // RandomMix only XOR-folds in, so even if QEMU's
            // virtio-rng misbehaves and returns all zeros, the
            // pool's existing TSC/HPET seed is unaffected.
            const u32 mix_len = (used_len < kBufLen) ? used_len : kBufLen;
            ::duetos::core::RandomMix(buf, mix_len);
            // Sample the first 8 bytes so the boot log carries a
            // grep-able non-zero, non-repeating signature.
            u64 sample = 0;
            for (u32 i = 0; i < 8; ++i)
                sample = (sample << 8) | buf[i];
            KLOG_INFO_2V("drivers/virtio/rng", "entropy pulled + mixed", "bytes", static_cast<u64>(mix_len),
                         "sample-u64", sample);
            return true;
        }
        asm volatile("pause" ::: "memory");
    }
    KLOG_WARN("drivers/virtio/rng", "entropy poll timed out");
    return false;
}
} // namespace

bool VirtioRngProbe(const VirtioPciLayout& L)
{
    VirtioPciLayout layout = L;
    if (!VirtioNegotiate(&layout, kFeatureVersion1))
    {
        KLOG_WARN("drivers/virtio/rng", "feature negotiation failed");
        return false;
    }

    if (!VirtioQueueSetup(&layout, &g_rng_q, /*queue_index=*/0, kVirtqDefaultSize))
    {
        KLOG_WARN("drivers/virtio/rng", "requestq setup failed");
        return false;
    }
    // Queues are up — make the spec §3.1.1 step-8 DRIVER_OK
    // transition before issuing any requests.
    VirtioMarkDriverOk(&layout);

    if (PullEntropy(&layout, &g_rng_q))
        g_entropy_pulled = true;
    KLOG_INFO_V("drivers/virtio/rng", "attached", static_cast<u64>(g_entropy_pulled ? 1 : 0));
    return true;
}

} // namespace duetos::drivers::virtio
