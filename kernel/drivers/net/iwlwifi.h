#pragma once

#include "util/types.h"
#include "drivers/net/net.h"

/*
 * Intel Wi-Fi inventory shell.
 *
 * Candidate IDs are classified by nic_ids.h, but this backend currently has
 * no safe-probe profile. IwlwifiMatches therefore returns false and the
 * dormant bring-up body cannot map BAR0, read CSR_HW_REV, upload firmware,
 * publish driver_online, or launch a liveness worker. Keep the declarations
 * while parser/scaffold tests are migrated; none represents functional
 * hardware support.
 */

namespace duetos::drivers::net
{

/// Functional admission gate. Currently false for every candidate.
bool IwlwifiMatches(u16 vendor_id, u16 device_id);

/// Dormant implementation entry; fails closed while no safe profile exists.
bool IwlwifiBringUp(NicInfo& n);

/// Compatibility no-op; no wireless worker is launched.
void IwlwifiStartWatch(NicInfo& n);

struct IwlwifiStats
{
    u32 adapters_bound;        // total iwlwifi NICs that came online
    u32 watch_polls;           // iwlwifi-watch task wake count
    u32 unexpected_dead_polls; // polls where MMIO went 0xFFFFFFFF
    u32 hw_rev;                // last bound NIC's HW_REV dword
};

IwlwifiStats IwlwifiStatsRead();

} // namespace duetos::drivers::net
