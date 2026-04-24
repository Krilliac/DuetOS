#pragma once

#include "../../core/types.h"

/*
 * DuetOS NVMe driver — v0.
 *
 * Minimum viable driver for the "SSD path" — M.2 NVMe is the
 * dominant storage form factor for modern PCs, and QEMU's
 * `-device nvme` exercises the same register + queue model as
 * real silicon (PCIe class 0x01 / subclass 0x08 / prog_if 0x02).
 *
 * Scope limits (v0):
 *   - Polling-mode only. No IRQ wiring. Each I/O busy-waits
 *     on the completion queue's phase tag flip, with an
 *     HPET-based deadline derived from CAP.TO. Fine for a
 *     boot-time self-test + initial filesystem bring-up;
 *     MSI-X wiring lands when a workload cares about CPU
 *     time during I/O.
 *   - One admin queue pair (QID 0) + one I/O queue pair
 *     (QID 1), each sized against CAP.MQES (capped at 64
 *     entries so both queues fit on one 4 KiB page each).
 *     No per-CPU queues, no interrupt coalescing.
 *   - Namespace 1 only. NVMe supports 1..65535; NSID=1 is the
 *     only namespace QEMU exposes by default and covers every
 *     consumer-class SSD.
 *   - 512-byte or 4 KiB sector support (whichever the
 *     namespace reports via LBA Format 0). No multi-format
 *     namespaces.
 *   - Multi-page transfers via PRP1 + PRP2 (two pages) or
 *     PRP1 + single-level PRP list (up to 16 pages per
 *     command, bounded by the staging buffer + MDTS from
 *     Identify Controller). Chained PRP lists not yet
 *     implemented — a single list page covers 2 MiB of
 *     payload, well above our staging cap.
 *   - All I/O goes through a pre-allocated 64 KiB contiguous
 *     staging buffer (physically contiguous by construction,
 *     required because user buffers aren't guaranteed to be).
 *     Read = device-to-staging + staging-to-user memcpy;
 *     write = user-to-staging memcpy + staging-to-device.
 *   - No write path beyond `NvmeWrite` — there's no write
 *     coalescing, no FUA flag, no Flush command. Writes hit
 *     the device immediately.
 *
 * Real-hardware hardening (present, differs from QEMU-only v0):
 *   - CAP.MPSMIN / MPSMAX validated against the host 4 KiB page
 *     size before CC.MPS is programmed. A controller that
 *     refuses 4 KiB fails init cleanly rather than locking up.
 *   - CAP.TO honoured as the upper bound on every CSTS.RDY
 *     transition (spec says this is the wall-clock limit the
 *     controller is allowed). Replaces the fixed pause-loop
 *     budget that happened to be ~1 second on a modern CPU.
 *   - NVMe completion status (SC + SCT + DNR/M bits) logged on
 *     every failed command so a real-disk error surfaces with
 *     enough information to triage without a bus analyser.
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

namespace duetos::drivers::storage
{

/// Discover and bring up the first NVMe controller on the PCI
/// bus. Registers the controller's namespace 1 as a block device
/// on success. Logs one banner line per phase so boot-log grep
/// can follow progress. No-op when no NVMe controller exists.
void NvmeInit();

/// Boot-time self-test: if an NVMe block device exists, reads
/// LBA 0 and asserts the first 8 bytes match the marker
/// `tools/qemu/run.sh` seeded into the scratch disk image
/// ("DUETOS"). Prints one PASS/FAIL line to COM1. If no NVMe
/// device is present (no controller or register failed), logs
/// "skipped" — not a test failure.
void NvmeSelfTest();

} // namespace duetos::drivers::storage
