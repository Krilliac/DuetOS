#pragma once

#include "util/types.h"

/*
 * DuetOS — NIC MAC / link telemetry reader, v0.
 *
 * READ-ONLY. Surfaces the per-NIC identity (vendor/device/family), the
 * MAC address, and the link state that the vendor probes already read
 * into the NIC registry (drivers/net/net.h `NicInfo`). It issues no new
 * device writes — the MAC came from the e1000 RAL/RAH receive-address
 * registers (read at probe), never written. Per the hardware-safety
 * contract the NIC NVM/MAC is read-only; this reader does not change
 * that.
 *
 * The MAC-from-registers decode is also exposed as a pure helper so the
 * self-test can verify the byte ordering without hardware.
 *
 * Context: kernel.
 */

namespace duetos::drivers::net
{

/// Decode a MAC address from the e1000 Receive-Address Low/High dwords.
/// RAL holds MAC bytes 0..3 (little-endian); RAH bits 0..15 hold bytes
/// 4..5. `out` must have room for 6 bytes.
void NicMacFromRalRah(u32 ral, u32 rah, u8 out[6]);

/// Log a one-line summary per discovered NIC at boot (family, MAC,
/// link). No-ops cleanly when no NICs were discovered.
void NicTelemetryProbe();

/// Pure-math self-test of NicMacFromRalRah. Panics on mismatch; emits
/// one "[nic-telemetry-selftest] PASS" line.
void NicTelemetrySelfTest();

} // namespace duetos::drivers::net
