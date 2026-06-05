#pragma once

#include "util/types.h"

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
/// Idempotent: returns early when the controller is already
/// online (the fault-domain restart path runs Teardown first).
void NvmeInit();

/// Free the controller's DMA-backed queues, staging buffer, and
/// PRP list, then reset every cached field so a subsequent
/// `NvmeInit` re-walks PCI cleanly. The MMIO mapping for BAR0
/// and the block-layer handle leak (same caveat ahci / pci /
/// framebuffer document for their MMIO mappings + block
/// handles). Idempotent.
void NvmeTeardown();

/// Boot-time self-test: if an NVMe block device exists, reads
/// LBA 0 and asserts the first 8 bytes match the marker
/// `tools/qemu/run.sh` seeded into the scratch disk image
/// ("DUETOS"). Prints one PASS/FAIL line to COM1. If no NVMe
/// device is present (no controller or register failed), logs
/// "skipped" — not a test failure.
void NvmeSelfTest();

/// Translate an NVMe status-code-type / status-code pair into a
/// short human-readable name. SCT 0 = Generic Command Status,
/// SCT 1 = Command Specific Status, SCT 2 = Media and Data
/// Integrity Errors, SCT 7 = Vendor specific. The most common
/// codes (success, invalid opcode, internal error, LBA out of
/// range, etc.) get explicit names; anything we haven't catalogued
/// returns "unknown" so callers can still print the raw (sct, sc)
/// pair.
const char* NvmeStatusName(u8 sct, u8 sc);

/// Translate an NVMe admin-set opcode (set 0) or NVM-set opcode
/// (set 1) to its name. `set` matches the I/O queue convention:
/// 0 = admin queue, 1 = an NVM I/O queue. Returns "unknown" for
/// codes outside the small subset this driver issues.
const char* NvmeOpcodeName(u8 set, u8 opcode);

// -------------------------------------------------------------
// Panic-time surface.
//
// The polled-completion path in the regular I/O loop already
// works without scheduler / IRQ / slab dependencies — it
// busy-waits on the CQ phase tag, no allocations along the way.
// The only thing missing for crash-dump persistence is a
// stable LBA range to write into and a thin wrapper that
// chunks an arbitrary byte buffer through the per-command
// staging cap. Both live here so the diag/minidump module can
// reach them without pulling in the block layer.
//
// Reservation policy: crash dumps are written ONLY into a GPT
// partition DuetOS positively owns — one the installer laid with
// kDuetCrashDumpTypeGuid (discovered via GptFindCrashDumpRegion and
// bounds-checked by GptCrashDumpRegionSane). There is no "tail of the
// namespace" fallback: on a disk DuetOS didn't partition (a real
// machine's SSD with Windows/Linux installed) the namespace tail is
// the user's data + the backup GPT, and writing there corrupts the
// partition table. No owned region → no disk persistence (the
// serial/debugcon copy of the dump still emits). `kNvmeDumpReserved-
// Sectors` is now only the MINIMUM size an owned crash-dump partition
// must be, not a tail offset.
// -------------------------------------------------------------

inline constexpr u64 kNvmeDumpReservedSectors = 8192; // 4 MiB at 512B sectors

/// True iff an NVMe namespace was discovered + brought up. Read
/// as a precondition by the panic path before calling
/// NvmePanicWriteDump.
bool NvmeAvailable();

/// Sector size of namespace 1 (512 or 4096 in v0). 0 if no
/// namespace.
u32 NvmeNamespaceSectorSize();

/// Sector count of namespace 1. 0 if no namespace.
u64 NvmeNamespaceSectorCount();

/// First LBA of the reserved crash-dump region — the start of the
/// DuetOS-owned kDuetCrashDumpTypeGuid partition, bounds-checked sane.
/// Returns 0 when no namespace OR no owned/sane region exists (e.g. a
/// disk DuetOS didn't partition); a 0 return means "skip disk
/// persistence". Callers MUST treat 0 as "no reservation".
u64 NvmeDumpReservedLba();

/// Write `len` bytes of `bytes` to the reserved crash-dump
/// region starting at `NvmeDumpReservedLba()`. Splits the
/// buffer into per-command chunks bounded by the staging
/// buffer + MDTS, copies each chunk into the staging buffer,
/// issues a polled NVM Write, and walks to the next chunk.
/// Returns true iff EVERY command completed without error.
///
/// Safe to call from panic / trap context: no allocations,
/// no locks, no scheduler dependencies. The driver's existing
/// SubmitAndWait already polls on the CQ phase tag with an
/// HPET-bounded deadline. Worst case at panic time is the
/// HPET deadline fires and we report a partial write — the
/// debugcon copy of the same bytes is still on the host.
bool NvmePanicWriteDump(const u8* bytes, u64 len);

/// True iff the most recent `NvmePanicWriteDump` call
/// succeeded. Reset to false on every call. Used by the
/// `lastdump` shell command to confirm whether a dump
/// landed on the reserved region this boot.
bool NvmePanicWriteSucceededLast();

/// Number of bytes the most recent `NvmePanicWriteDump`
/// successfully wrote. Even on a partial write this counts
/// the bytes that DID land — useful for triage when a real
/// disk hits a write error part-way through.
u64 NvmePanicLastWriteBytes();

/// First LBA of the reserved fix-journal region — the second
/// half of the crash-dump reservation. The minidump owns the
/// first half (2 MiB at v0); the fix journal owns the back half.
/// 0 if no namespace.
u64 NvmeFixJournalReservedLba();

/// Same contract as `NvmePanicWriteDump`, but writes to the
/// second half of the reserved region — used by the panic path
/// to durably persist the in-RAM fix journal before halting.
/// Capped at half the reserved size (2 MiB at v0); fix journal
/// payloads are bounded at 128 KiB so this is comfortable.
bool NvmePanicWriteFixJournal(const u8* bytes, u64 len);

} // namespace duetos::drivers::storage
