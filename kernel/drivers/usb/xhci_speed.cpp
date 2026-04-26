/*
 * DuetOS — xHCI driver: speed-derived helpers.
 *
 * Pure-logic translations of USB speed code → controller defaults.
 * Sibling TU; consumed by xhci.cpp's Address Device + HID setup
 * paths (and any future xhci_enum/xhci_hid TU). No controller
 * state, no MMIO — just the small numeric tables the spec defines.
 */

#include "xhci_internal.h"

namespace duetos::drivers::usb::xhci::internal
{

// EP0 max-packet-size default derived from PORTSC-reported speed.
// Low/Full: 8. High: 64. Super+: 512. These are the values the xHCI
// spec recommends using in the Input Context before the device's
// actual descriptor is available — the controller will either
// accept them outright or ask us to re-submit with the corrected
// value (which we handle lazily in v0: if a device needs a
// different MPS0, the GET_DESCRIPTOR read of 18 bytes still works
// because MPS0 just bounds the per-packet payload).
u32 DefaultMaxPacketSize0(u8 speed)
{
    switch (speed)
    {
    case 4: // Super Speed
    case 5: // Super Speed+
        return 512;
    case 3: // High Speed
        return 64;
    default: // Low / Full / unknown
        return 8;
    }
}

// Translate raw USB bInterval (spec differs per speed) into the
// xHCI Interval field (ep context DW0 bits 16..23), which is
// always encoded as 2^interval × 125 µs. We map conservatively:
// - Low/Full-speed interrupt: bInterval is in 1 ms units, so
//   Interval = log2(bInterval * 8). Clip to [3, 15].
// - High-speed and above: bInterval is already a log2 value
//   in 125 µs microframes; Interval = bInterval - 1.
// Keyboards send reports on change + at bInterval cadence; at
// 16 ms (our worst-case) the ReadEvent loop still keeps up.
u32 HidXhciInterval(u8 speed, u8 bInterval)
{
    if (bInterval == 0)
        return 3; // spec-illegal for interrupt endpoints; pick sane default
    if (speed >= 3)
    {
        // HS / SS / SS+: already log2-encoded in USB units.
        u32 v = u32(bInterval - 1);
        if (v > 15)
            v = 15;
        return v;
    }
    // LS / FS: linear ms. Walk up to log2(bInterval * 8).
    u32 microframes = u32(bInterval) * 8;
    u32 log = 0;
    while ((1u << log) < microframes)
        ++log;
    if (log > 15)
        log = 15;
    return log;
}

} // namespace duetos::drivers::usb::xhci::internal
