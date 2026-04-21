#pragma once

#include "../../core/types.h"

/*
 * CustomOS AHCI storage driver.
 *
 * v0: discovery-only (landed earlier).
 * v1 (this commit): single-port READ DMA EXT + BlockDevice wrapper.
 *
 * Scope of v1:
 *   - Walks every AHCI controller found on the PCI bus (not just
 *     the first) and every SATA-signatured port within each.
 *   - Brings each ready SATA port online: stops the command
 *     engine, allocates per-port command list (1 KiB, 4 KiB
 *     aligned) + FIS receive area (256 B, 256 B aligned) + a
 *     single command table (256 B — CFIS + PRDT[0]), programs
 *     PxCLB / PxFB, re-enables FRE + ST, waits for the engine
 *     to report running.
 *   - Issues ATA IDENTIFY DEVICE (0xEC) to learn the drive's
 *     LBA count + sector size. Reports via the block layer.
 *   - Implements BlockDeviceRead via READ DMA EXT (ATA 0x25)
 *     on command slot 0 with a single PRD. Caps at 8 sectors
 *     per call (4 KiB at 512 B, 32 KiB at 4 KiB — well under
 *     the AHCI PRD limit, and enough for any current caller;
 *     larger transfers split in the block layer).
 *   - Polling-mode completion. Each I/O spins on PxCI until the
 *     slot's bit clears, or PxIS.TFES indicates a task-file
 *     error. No MSI, no IRQ, no NCQ.
 *
 * Not in scope for v1:
 *   - Write path. ATAPI (CD-ROM). Port multipliers. Multiple
 *     simultaneous in-flight commands. Power management.
 *   - Hotplug. Sleeping-controller wake-up sequences.
 *   - MBR fallback — callers reach us through the block layer,
 *     which the GPT parser already consumes.
 *
 * Context: kernel. AhciInit runs once at boot, after
 * PciEnumerate + BlockLayerInit.
 */

namespace customos::drivers::storage
{

/// Discover every AHCI controller + online every attached SATA
/// drive. For each drive, register it as a block device (name
/// "sata0", "sata1", ...) so higher layers (GPT parser, FAT32)
/// consume it through the same interface as NVMe / the RAM
/// backend. Safe to call exactly once; double-init is a kernel
/// bug (trapped via an internal flag).
void AhciInit();

/// Boot-time self-test: if any SATA drive is registered, read
/// LBA 0 and assert the 0x55AA boot signature at offset 510/511.
/// Matches the NVMe self-test contract so boot-log grep can
/// confirm every storage backend read-path works end-to-end.
/// No-op + log "skipped" if no SATA drive is registered.
void AhciSelfTest();

} // namespace customos::drivers::storage
