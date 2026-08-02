#pragma once

#include "util/types.h"
#include "drivers/net/net.h"

/*
 * Broadcom Wi-Fi inventory shell.
 *
 * Broadcom backend selection can require subsystem identity and backplane
 * enumeration; BAR0 is not a universal fixed ChipCommon window. Candidate
 * IDs live in nic_ids.h, but Bcm43xxMatches returns false until an exact
 * safe-probe profile exists. The dormant body cannot touch MMIO, load
 * firmware, publish driver_online, or start a watcher.
 */

namespace duetos::drivers::net
{

/// Functional admission gate. Uses the complete PCI identity and currently
/// returns false for every candidate.
bool Bcm43xxMatches(const NicInfo& n);

/// Dormant implementation entry; fails closed while no safe profile exists.
bool Bcm43xxBringUp(NicInfo& n);

/// Compatibility no-op; no wireless worker is launched.
void Bcm43xxStartWatch(NicInfo& n);

struct Bcm43xxStats
{
    u32 adapters_bound;
    u32 watch_polls;
    u32 unexpected_dead_polls;
    u32 chip_info;      // last bound NIC's CORE_INFO
    u16 chip_id_field;  // bits[15:0]
    u16 chip_rev_field; // bits[19:16]
};

Bcm43xxStats Bcm43xxStatsRead();

} // namespace duetos::drivers::net
