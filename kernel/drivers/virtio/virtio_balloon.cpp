#include "drivers/virtio/virtio.h"
#include "drivers/virtio/virtio_pci.h"

#include "log/klog.h"

/*
 * virtio-balloon — hypervisor-controlled memory pressure.
 *
 * Spec: virtio 1.0 §5.5. The host changes its desired guest
 * memory footprint by writing `num_pages` (the target page
 * count to inflate to) into device_cfg + 0; the driver reads
 * that target, allocates the requested pages from the guest
 * pool, and posts their guest-physical PFNs through the
 * inflateq (queue 0). Pages handed back via deflateq (queue 1).
 * An optional statsq (queue 2) carries host-pollable guest
 * memory statistics.
 *
 * v0 (this file): probe + feature negotiate + read num_pages /
 * actual from device_cfg + log them. No queue setup, no
 * inflate/deflate dispatch yet. The point of v0 is twofold:
 *
 *   - Make balloon devices SHOW UP in the boot log + the
 *     fabric's `VirtioStats` instead of being silently ignored.
 *   - Lay the device_cfg-layout groundwork so the next slice
 *     just adds the queues + the inflate handler.
 *
 * Once the queues land, the inflate handler reads the current
 * num_pages, computes the delta against `actual`, allocates
 * pages via `mm::AllocateFrame`, writes their PFNs to the
 * inflateq, and bumps `actual`. The deflate handler runs the
 * reverse path on host-issued shrink. Both are spec-pure; the
 * complexity is policy ("when does the kernel agree to give up
 * memory?" / "how do we avoid OOM-induced thrash?") — that
 * lands with a real hypervisor workload, not as a bare driver.
 */

namespace duetos::drivers::virtio
{

namespace
{
// Optional feature bits — landmarks for the next slice. Marked
// maybe_unused so the v0 probe doesn't warn on the unused
// constants.
[[maybe_unused]] inline constexpr u64 kBalloonFeatureMustTellHost = 1ULL << 0;
[[maybe_unused]] inline constexpr u64 kBalloonFeatureStatsVq = 1ULL << 1;
[[maybe_unused]] inline constexpr u64 kBalloonFeatureDeflateOnOom = 1ULL << 2;

struct BalloonState
{
    bool up;
    u8 _pad[7];
    VirtioPciLayout layout;
    VirtioQueue inflateq; // queue 0
    VirtioQueue deflateq; // queue 1
};

constinit BalloonState g_balloon = {};
} // namespace

bool VirtioBalloonProbe(const VirtioPciLayout& L)
{
    VirtioPciLayout layout = L;
    if (!VirtioNegotiate(&layout, kFeatureVersion1))
    {
        KLOG_WARN("drivers/virtio/balloon", "feature negotiation failed");
        return false;
    }

    // device_cfg layout (virtio 1.0 §5.5.4):
    //   u32 num_pages    target page count to inflate to
    //   u32 actual       driver's currently-reported count
    u32 num_pages = 0;
    u32 actual = 0;
    if (layout.device_cfg != nullptr)
    {
        num_pages = *reinterpret_cast<volatile u32*>(layout.device_cfg + 0);
        actual = *reinterpret_cast<volatile u32*>(layout.device_cfg + 4);
    }
    // Set up inflateq + deflateq so the device sees a
    // fully-configured driver. Without queues, the device's
    // status hangs at FEATURES_OK and host-side balloon
    // commands silently fail. With queues but no PFN dispatch,
    // the host's requests sit in the inflateq waiting for a
    // driver-supplied descriptor — that's the v0 "we noticed
    // but won't reclaim yet" semantics.
    if (!VirtioQueueSetup(&layout, &g_balloon.inflateq, /*queue_index=*/0, kVirtqDefaultSize))
    {
        KLOG_WARN("drivers/virtio/balloon", "inflateq setup failed");
        return false;
    }
    if (!VirtioQueueSetup(&layout, &g_balloon.deflateq, /*queue_index=*/1, kVirtqDefaultSize))
    {
        KLOG_WARN("drivers/virtio/balloon", "deflateq setup failed");
        return false;
    }
    g_balloon.layout = layout;
    g_balloon.up = true;

    KLOG_INFO_2V("drivers/virtio/balloon", "attached", "num-pages-target", static_cast<u64>(num_pages), "actual",
                 static_cast<u64>(actual));
    // GAP: per-call PFN dispatch + policy. The queues are
    // installed; the host can see a properly-configured device.
    // What's missing is the inflate handler that, on host
    // request, allocates pages and writes their PFNs into
    // inflateq descriptors. The policy ("when do we agree?")
    // lands with a real hypervisor workload.
    return true;
}

} // namespace duetos::drivers::virtio
