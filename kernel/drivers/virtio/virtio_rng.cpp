#include "drivers/virtio/virtio.h"
#include "drivers/virtio/virtio_pci.h"

#include "log/klog.h"

/*
 * virtio-rng — entropy provider.
 *
 * Real driver: one virtqueue (requestq). Driver pushes a
 * descriptor pointing at a kernel-owned page; device fills it
 * with hardware/host entropy and signals via the used ring.
 * Kernel pushes the bytes into the entropy pool, which is the
 * one virtio device that gives the kernel something useful even
 * before a single user-mode process exists.
 *
 * v0 (this file): completes feature negotiation (no rng-specific
 * features today — only VERSION_1) and logs the attach. Queue
 * allocation + the actual entropy pull is STUBBED until the
 * shared transport gains a VirtioQueueSetup helper.
 */

namespace duetos::drivers::virtio
{

bool VirtioRngProbe(const VirtioPciLayout& L)
{
    VirtioPciLayout layout = L;
    if (!VirtioNegotiate(&layout, kFeatureVersion1))
    {
        KLOG_WARN("drivers/virtio/rng", "feature negotiation failed");
        return false;
    }
    KLOG_INFO_V("drivers/virtio/rng", "attached (no entropy pulled yet)", static_cast<u64>(layout.num_queues));
    // STUB: a real driver allocates a virtqueue here and posts a
    // descriptor pointing at the entropy buffer. Until the shared
    // transport hosts queue setup, virtio-rng cannot pull entropy
    // — RandomInit's existing seed path is unaffected.
    return true;
}

} // namespace duetos::drivers::virtio
