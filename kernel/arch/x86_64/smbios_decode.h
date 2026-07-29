#pragma once

#include "util/types.h"

/*
 * DuetOS — SMBIOS Type 17 (Memory Device) field decoders.
 *
 * FREESTANDING on purpose. These are pure functions over a
 * firmware-supplied byte buffer — no kernel headers, no allocation, no
 * globals — so `tests/host/test_smbios_type17.cpp` can exercise them
 * against synthetic records on the build host. The kernel-side caller
 * is `kernel/arch/x86_64/smbios.cpp`.
 *
 * The encodings below are the fiddly part of Type 17 and the reason
 * this logic is worth testing rather than eyeballing: the size field
 * alone has five distinct cases and switches between kilobyte and
 * megabyte units on a single bit.
 *
 * Bounds contract: every function takes the record's `Length` header
 * byte and refuses to read past it, so a short (older-spec) record
 * degrades to "unknown" rather than reading adjacent structures.
 * Callers must still guarantee that `fmt[0 .. length)` is in bounds —
 * the Rust structure walker does that before these are reached.
 *
 * Field offsets follow the SMBIOS spec §7.18 (DSP0134).
 */

namespace duetos::arch::smbios_decode
{

// Type 17 formatted-area offsets we decode.
inline constexpr u32 kType17OffsetSize = 0x0C;            // WORD
inline constexpr u32 kType17OffsetFormFactor = 0x0E;      // BYTE
inline constexpr u32 kType17OffsetDeviceLocator = 0x10;   // BYTE (string idx)
inline constexpr u32 kType17OffsetBankLocator = 0x11;     // BYTE (string idx)
inline constexpr u32 kType17OffsetMemoryType = 0x12;      // BYTE
inline constexpr u32 kType17OffsetSpeed = 0x15;           // WORD  (2.3+)
inline constexpr u32 kType17OffsetManufacturer = 0x17;    // BYTE (string idx)
inline constexpr u32 kType17OffsetPartNumber = 0x1A;      // BYTE (string idx)
inline constexpr u32 kType17OffsetExtendedSize = 0x1C;    // DWORD (2.7+)
inline constexpr u32 kType17OffsetConfiguredSpeed = 0x20; // WORD (2.7+)

// Sentinel values the spec assigns special meaning.
inline constexpr u16 kSizeEmptySlot = 0x0000;   // slot exists, no module
inline constexpr u16 kSizeUnknown = 0xFFFF;     // firmware doesn't know
inline constexpr u16 kSizeUseExtended = 0x7FFF; // see Extended Size
inline constexpr u16 kSpeedUnknown = 0xFFFF;

/// Little-endian u16 load. Firmware buffers carry no alignment
/// guarantee, so this is deliberately byte-wise.
inline u16 ReadU16(const u8* fmt, u32 off)
{
    return static_cast<u16>(static_cast<u16>(fmt[off]) | (static_cast<u16>(fmt[off + 1]) << 8));
}

/// Little-endian u32 load.
inline u32 ReadU32(const u8* fmt, u32 off)
{
    return static_cast<u32>(fmt[off]) | (static_cast<u32>(fmt[off + 1]) << 8) | (static_cast<u32>(fmt[off + 2]) << 16) |
           (static_cast<u32>(fmt[off + 3]) << 24);
}

/// True when the record describes a slot with no module fitted.
/// Distinct from "unknown size" — an empty slot is a fact worth
/// rendering ("DIMM_B2 — empty"), unknown is an absence of data.
inline bool MemorySlotIsEmpty(const u8* fmt, u8 length)
{
    if (length < kType17OffsetSize + 2)
        return false;
    return ReadU16(fmt, kType17OffsetSize) == kSizeEmptySlot;
}

/// Decode the Size field into bytes (SMBIOS §7.18.5).
///
///   0x0000       -> empty slot                      -> 0
///   0xFFFF       -> unknown                         -> 0
///   0x7FFF       -> use Extended Size (DWORD, MB)
///   bit 15 set   -> low 15 bits are KILObytes
///   bit 15 clear -> low 15 bits are MEGAbytes
///
/// Returns 0 for both "empty" and "unknown"; use `MemorySlotIsEmpty`
/// to tell them apart.
inline u64 DecodeMemorySizeBytes(const u8* fmt, u8 length)
{
    if (length < kType17OffsetSize + 2)
        return 0;
    const u16 raw = ReadU16(fmt, kType17OffsetSize);
    if (raw == kSizeEmptySlot || raw == kSizeUnknown)
        return 0;
    if (raw == kSizeUseExtended)
    {
        // Extended Size is SMBIOS 2.7+. Bit 31 is reserved; the
        // remaining 31 bits are a megabyte count.
        if (length < kType17OffsetExtendedSize + 4)
            return 0;
        const u64 ext_mb = ReadU32(fmt, kType17OffsetExtendedSize) & 0x7FFFFFFFULL;
        return ext_mb * 1024ULL * 1024ULL;
    }
    const u64 value = raw & 0x7FFFU;
    const bool in_kilobytes = (raw & 0x8000U) != 0;
    return in_kilobytes ? (value * 1024ULL) : (value * 1024ULL * 1024ULL);
}

/// Decode the effective module speed in MT/s.
///
/// Prefers "Configured Memory Speed" (0x20, SMBIOS 2.7+) — the rate the
/// module is actually clocked at — over "Speed" (0x15), which is the
/// module's rated maximum. A DDR4-3200 kit running at stock JEDEC 2133
/// reports 3200 in the latter and 2133 in the former; the configured
/// rate is what a Task Manager should show. Returns 0 for unknown.
inline u32 DecodeMemorySpeedMts(const u8* fmt, u8 length)
{
    if (length >= kType17OffsetConfiguredSpeed + 2)
    {
        const u16 configured = ReadU16(fmt, kType17OffsetConfiguredSpeed);
        if (configured != 0 && configured != kSpeedUnknown)
            return configured;
    }
    if (length >= kType17OffsetSpeed + 2)
    {
        const u16 rated = ReadU16(fmt, kType17OffsetSpeed);
        if (rated != 0 && rated != kSpeedUnknown)
            return rated;
    }
    return 0;
}

/// Human-readable SMBIOS memory type (Type 17 offset 0x12). Covers the
/// values a commodity x86_64 box can actually report; anything else
/// degrades to "unknown" rather than a fabricated name.
inline const char* MemoryTypeName(u8 t)
{
    switch (t)
    {
    case 0x02:
        return "unknown";
    case 0x0F:
        return "SDRAM";
    case 0x12:
        return "DDR";
    case 0x13:
        return "DDR2";
    case 0x18:
        return "DDR3";
    case 0x1A:
        return "DDR4";
    case 0x1E:
        return "LPDDR3";
    case 0x1F:
        return "LPDDR4";
    case 0x22:
        return "DDR5";
    case 0x23:
        return "LPDDR5";
    default:
        return "unknown";
    }
}

/// Human-readable form factor (Type 17 offset 0x0E).
inline const char* MemoryFormFactorName(u8 f)
{
    switch (f)
    {
    case 0x09:
        return "DIMM";
    case 0x0D:
        return "SODIMM";
    case 0x0F:
        return "onboard";
    default:
        return "unknown";
    }
}

} // namespace duetos::arch::smbios_decode
