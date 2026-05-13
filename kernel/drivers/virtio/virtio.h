#pragma once

#include "drivers/virtio/virtio_pci.h"
#include "util/types.h"

/*
 * DuetOS — VirtIO driver fabric.
 *
 * `VirtioInit` walks every PCI device exposed by the PCI
 * enumeration pass, picks out modern VirtIO functions (vendor
 * 0x1AF4, device 0x1040..0x107F), and dispatches to the per-
 * class probe entry — virtio-rng / virtio-blk / virtio-net /
 * virtio-console for v0. Each per-class probe is responsible
 * for completing feature negotiation and any queue setup it
 * needs.
 *
 * Why VirtIO is in tree even though Intel/AMD/NVIDIA GPU and
 * NVMe / AHCI drivers exist: every cloud/QEMU/CI environment
 * runs guests against VirtIO devices, not real PCH NICs or
 * NVMe controllers. Without VirtIO support, the only useful
 * smoke target is bare metal — every developer who boots into
 * QEMU sees `[net] no NICs attached` because e1000 isn't the
 * default. virtio-net + virtio-blk + virtio-rng + virtio-
 * console fix that for v0.
 *
 * The boot-time stats are exposed via `VirtioStats` so the
 * shell `lspci` / future `lsvirtio` and the wiki Drivers page
 * can show what was found at-a-glance.
 */

namespace duetos::drivers::virtio
{

struct VirtioStats
{
    u32 probed_total; // virtio PCI functions visited
    u32 attached;     // probed_total minus skipped / failed
    u32 by_class[16]; // count per VirtioClass enum value (sparse)
    bool init_done;
    u8 _pad[3];
};

/// One-shot init. Idempotent — second call is a no-op. Safe to
/// call before any per-driver init; per-class drivers register
/// their probes here.
void VirtioInit();

/// Read-back accessor — used by `lspci` / the boot-summary
/// printer + the wiki sync to report what came online.
VirtioStats GetStats();

// Per-class probes. Each returns true on a successful attach,
// false on skip / failure. Called from the dispatch table in
// virtio.cpp; exposed in the header so future per-class shell
// commands can re-probe an individual device for diagnostics.
bool VirtioRngProbe(const VirtioPciLayout& L);
bool VirtioBlkProbe(const VirtioPciLayout& L);
bool VirtioNetProbe(const VirtioPciLayout& L);
bool VirtioConsoleProbe(const VirtioPciLayout& L);
bool VirtioBalloonProbe(const VirtioPciLayout& L);

/// Forward a byte buffer over the attached virtio-console TX
/// queue. No-op if the device wasn't found (returns false). The
/// host renders the bytes on its `-chardev` sink — typically a
/// QEMU stdout pipe or a log file. Cheap diagnostic surface for
/// long-running boots and CI.
bool VirtioConsoleWrite(const char* buf, u32 len);

} // namespace duetos::drivers::virtio
