#pragma once

#include "../../core/types.h"

/*
 * CustomOS NVMe driver — v0.
 *
 * Minimum viable driver for the "SSD path" — M.2 NVMe is the
 * dominant storage form factor for modern PCs, and QEMU's
 * `-device nvme` exercises the same register + queue model as
 * real silicon (PCIe class 0x01 / subclass 0x08 / prog_if 0x02).
 *
 * Scope limits (v0):
 *   - Polling-mode only. No IRQ wiring. Each I/O busy-waits
 *     on the completion queue's phase tag flip. Fine for a
 *     boot-time self-test + initial filesystem bring-up;
 *     MSI-X wiring lands when a workload cares about CPU
 *     time during I/O.
 *   - One admin queue pair (QID 0) + one I/O queue pair
 *     (QID 1). No per-CPU queues, no interrupt coalescing.
 *   - Namespace 1 only. NVMe supports 1..65535; NSID=1 is the
 *     only namespace QEMU exposes by default and covers every
 *     consumer-class SSD.
 *   - 512-byte or 4 KiB sector support (whichever the
 *     namespace reports via LBA Format 0). No multi-format
 *     namespaces.
 *   - Single-frame transfers (PRP1 only). No PRP lists, so
 *     the per-command payload caps at one page (4 KiB).
 *     Higher layers split large transfers into page-sized
 *     commands.
 *   - No write path beyond `NvmeWrite` — there's no write
 *     coalescing, no FUA flag, no Flush command. Writes hit
 *     the device immediately.
 *
 * Discovery + bring-up sequence:
 *   1. PCI scan for {class 0x01, subclass 0x08, prog_if 0x02}.
 *   2. BAR0 -> MapMmio; read CAP, VS, derive doorbell stride.
 *   3. Reset (CC.EN=0, wait CSTS.RDY=0).
 *   4. Allocate admin SQ + CQ (one 4 KiB frame each).
 *   5. Program AQA, ASQ, ACQ. Enable (CC.EN=1, wait RDY=1).
 *   6. Identify Controller (CNS=1) + Identify Namespace
 *      (CNS=0, NSID=1). Derive namespace size + LBA size.
 *   7. Create I/O CQ then I/O SQ (queue id 1).
 *   8. Register as a BlockDevice via the block layer.
 *
 * Context: kernel. `NvmeInit` runs once at boot after
 * PciEnumerate + BlockLayerInit. Safe no-op when no NVMe
 * controller is present.
 */

namespace customos::drivers::storage
{

/// Discover and bring up the first NVMe controller on the PCI
/// bus. Registers the controller's namespace 1 as a block device
/// on success. Logs one banner line per phase so boot-log grep
/// can follow progress. No-op when no NVMe controller exists.
void NvmeInit();

/// Boot-time self-test: if an NVMe block device exists, reads
/// LBA 0 and asserts the first 8 bytes match the marker
/// `tools/qemu/run.sh` seeded into the scratch disk image
/// ("CUSTOMOS"). Prints one PASS/FAIL line to COM1. If no NVMe
/// device is present (no controller or register failed), logs
/// "skipped" — not a test failure.
void NvmeSelfTest();

} // namespace customos::drivers::storage
