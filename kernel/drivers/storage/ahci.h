#pragma once

#include "../../core/types.h"

/*
 * AHCI controller discovery — v0.
 *
 * Scoped to "find the device, map its registers, log what ports have
 * attached devices." No DMA, no command list, no IDENTIFY, no sector
 * I/O — those are the next commits, each with their own scope doc
 * entry. Landing discovery first lets every subsequent AHCI slice
 * build on a tested "we can talk to the HBA" foundation.
 *
 * Depends on:
 *   drivers/pci     — find the AHCI device + BAR5 size probe
 *   mm/paging       — MapMmio the HBA register window
 *   core/klog       — structured log output per-port
 *
 * Context: kernel. `AhciInit` runs once at boot, after PciEnumerate.
 */

namespace customos::drivers::storage
{

/// Look up the AHCI controller via PCI class 0x01/0x06/0x01 (mass
/// storage / SATA / AHCI programming interface), map its BAR5 register
/// window via MapMmio, and log HBA-level + per-port diagnostics. No-op
/// (with a Warn log) if no AHCI controller is found.
///
/// Safe to call exactly once. A future commit extends this into the
/// full command-list + FIS + IDENTIFY bring-up path.
void AhciInit();

} // namespace customos::drivers::storage
