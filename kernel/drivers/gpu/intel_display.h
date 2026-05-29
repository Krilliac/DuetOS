#pragma once

#include "drivers/gpu/gpu.h"
#include "util/types.h"

/*
 * DuetOS — Intel iGPU display detect (Gen9–Gen12), v0.
 *
 * The "cheapest useful" display slice: read a connected panel's EDID
 * over the GMBUS (the I2C-over-DDC controller in the PCH) so the OS
 * can enumerate the monitor's preferred mode. This is the detect/
 * enumerate half — actually *lighting* a second display needs the full
 * PLL → pipe → transcoder → plane path (PLL coefficient math), which is
 * deferred. For the already-lit panel, v0 keeps the firmware GOP mode.
 *
 * The GMBUS command-word encoder is proven at compile time
 * (static_assert) + a device-independent self-test. The GMBUS read
 * SEQUENCE (GmbusReadEdid / IntelDisplayProbe) touches the BAR and is
 * gated on a live Intel device — unverified on silicon (no Intel model
 * in QEMU). DP-over-AUX EDID is a separate transport, out of v0 scope.
 */

namespace duetos::drivers::gpu::intel
{

// GMBUS registers (Gen9 PCH-split; base PCH_DISPLAY_BASE 0xC0000 + 0x5100).
inline constexpr u64 kGmbus0 = 0xC5100; // clock + port select
inline constexpr u64 kGmbus1 = 0xC5104; // command / status
inline constexpr u64 kGmbus2 = 0xC5108; // status
inline constexpr u64 kGmbus3 = 0xC510C; // data buffer (4 bytes/word)

inline constexpr u32 kGmbusSwRdy = 1u << 30;
inline constexpr u32 kGmbusCycleWait = 1u << 25;
inline constexpr u32 kGmbusCycleStop = 4u << 25;
inline constexpr u32 kGmbusByteCountShift = 16;
inline constexpr u32 kGmbusSlaveAddrShift = 1;
inline constexpr u32 kGmbusSlaveRead = 1u << 0;
inline constexpr u32 kGmbusHwRdy = 1u << 11;
inline constexpr u32 kGmbusSatoer = 1u << 10; // NAK / slave-timeout error
inline constexpr u32 kEdidDdcSlave = 0x50;    // 7-bit DDC EDID address

// GMBUS1 read-cycle command word: SW_RDY | CYCLE_WAIT | byte_count |
// (7-bit slave << 1) | READ. Pure — self-tested.
constexpr u32 EncodeGmbus1Read(u32 slave7, u32 byte_count)
{
    return kGmbusSwRdy | kGmbusCycleWait | ((byte_count & 0x1FFu) << kGmbusByteCountShift) |
           ((slave7 & 0x7Fu) << kGmbusSlaveAddrShift) | kGmbusSlaveRead;
}

// Read up to `len` EDID bytes from DDC pin `pin` into `buf` via GMBUS.
// Returns the number of bytes read (0 on failure / NAK). MMIO, gated.
u32 GmbusReadEdid(const GpuInfo& g, u32 pin, u8* buf, u32 len);

// Gated probe: walk the common DDC pins, read 128 EDID bytes from each,
// and log which pin (if any) returned a valid EDID header. Real-HW only.
void IntelDisplayProbe(const GpuInfo& g);

// Pure boot self-test of the GMBUS command encoder. Device-independent;
// PASSes under QEMU. Emits `[gpu/intel/disp] selftest PASS`.
void IntelDisplaySelfTest();

} // namespace duetos::drivers::gpu::intel
