#pragma once

#include "util/types.h"

/*
 * DuetOS — SPI flash (BIOS) controller status reader, v0.
 *
 * READ-ONLY. Locates the Intel PCH SPI flash controller and reports
 * the flash-configuration lock + descriptor state from its HSFSTS
 * register. It NEVER writes the SPI controller or the flash — writing
 * platform SPI flash bricks the board (wiki/security/Hardware-Safety.md),
 * so this only READS the lock/WP status that firmware left.
 *
 * Path supported: the modern (Skylake / Sunrise-Point and later) SPI
 * controller exposed as a PCI function at 0:1f.5 (class 0x0C, subclass
 * 0x80), whose BAR0 IS the SPIBAR; HSFSTS_CTL is at SPIBAR+0x04, with
 * FDV (Flash Descriptor Valid, bit 14) and FLOCKDN (Flash Configuration
 * Lock-Down, bit 15).
 *
 * GAPs (v0, deliberate):
 *   - Legacy PCH (ICH9-era, e.g. QEMU q35) put SPIBAR behind the LPC
 *     bridge's RCBA (0:1f.0 config 0xF0, SPIBAR = RCBA + 0x3800). That
 *     path is detected-only (lpc_present) — the RCBA decode is GAP'd.
 *   - JEDEC chip-ID (RDID 0x9F) needs a hardware-sequencing flash cycle
 *     and is not issued.
 *
 * Under QEMU q35 (ICH9) there is no 0:1f.5 SPI function, so hsfs_read is
 * false and the reader reports the LPC bridge present with the live HSFS
 * GAP'd. On real Skylake+ hardware the lock/descriptor bits are read.
 *
 * Context: kernel — runs after PciEnumerate().
 */

namespace duetos::arch
{

struct SpiFlashReading
{
    bool valid;          // a PCH SPI controller OR LPC bridge was found
    bool spi_controller; // 0:1f.5-style SPI function (class 0x0C/0x80) found
    bool lpc_present;    // Intel LPC bridge (class 0x06/0x01) found
    u16 vendor_id;       // of whichever device matched
    u16 device_id;       //
    u8 bus;              //
    u8 dev;              //
    u8 func;             //
    u64 spibar_phys;     // BAR0 of the SPI controller (0 if none)
    bool hsfs_read;      // HSFSTS was mapped + read
    u32 hsfs_raw;        // raw HSFSTS_CTL dword
    bool flockdn;        // Flash Configuration Lock-Down (bit 15)
    bool fdv;            // Flash Descriptor Valid (bit 14)
};

/// Decode the FDV / FLOCKDN bits from an HSFSTS_CTL dword. Exposed for
/// the self-test.
void SpiHsfsDecode(u32 hsfs, bool* out_fdv, bool* out_flockdn);

/// Locate the PCH SPI/LPC device and, on the modern path, read HSFSTS.
/// Zeroed (valid=false) when neither device is present.
SpiFlashReading SpiFlashRead();

/// Sample once + log a one-line summary at boot.
void SpiFlashProbe();

/// Pure-math self-test of SpiHsfsDecode. Panics on mismatch; emits one
/// "[spi-flash-selftest] PASS" line.
void SpiFlashSelfTest();

} // namespace duetos::arch
