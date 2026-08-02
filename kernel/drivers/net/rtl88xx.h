#pragma once

#include "util/types.h"
#include "drivers/net/net.h"

/*
 * Realtek Wi-Fi inventory shell.
 *
 * nic_ids.h records exact rtlwifi/rtw88/rtw89 candidates and BAR metadata,
 * but no family has a safe-probe profile. Rtl88xxMatches therefore returns
 * false and the dormant implementation cannot access MMIO, upload firmware,
 * publish driver_online, or start a watcher. These declarations preserve
 * parser/scaffold compatibility; they do not claim hardware support.
 */

namespace duetos::drivers::net
{

/// Functional admission gate. Currently false for every candidate.
bool Rtl88xxMatches(u16 vendor_id, u16 device_id);

/// Dormant implementation entry; fails closed while no safe profile exists.
bool Rtl88xxBringUp(NicInfo& n);

/// Compatibility no-op; no wireless worker is launched.
void Rtl88xxStartWatch(NicInfo& n);

struct Rtl88xxStats
{
    u32 adapters_bound;
    u32 watch_polls;
    u32 unexpected_dead_polls;
    u32 sys_cfg1; // last bound NIC's SYS_CFG1
    u32 sys_cfg2;
};

Rtl88xxStats Rtl88xxStatsRead();

} // namespace duetos::drivers::net
