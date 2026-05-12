// DuetOS PCI / PCIe capability walker C FFI — hand-written.
// Mirrors kernel/drivers/pci/caps_rust/src/lib.rs.
//
// The C++ caller at kernel/drivers/pci/pci.cpp pre-materialises the
// device's configuration space into a flat byte buffer (256 bytes
// for legacy config, 4096 for ECAM-mapped devices) before handing
// it to either walker. Rust owns every offset arithmetic step and
// every chain-cycle bound.

#pragma once

#include "util/types.h"

namespace duetos::drivers::pci::caps_rust
{

struct DuetosPciCap
{
    u8 cap_id;
    u8 next_offset; // 0 = end-of-list; otherwise validated [0x40, 0xFF]
    u16 _pad0;
    u16 offset; // byte offset of this header within `config`
    u16 _pad1;
    u8 ok;
    u8 _pad2[3];
};

struct DuetosPciExtCap
{
    u16 cap_id; // 0x0001 AER, 0x000F ATS, 0x0010 SR-IOV, …
    u8 version;
    u8 _pad0;
    u16 next_offset; // 0 = end-of-list; otherwise validated [0x100, 0xFFF]
    u16 _pad1;
    u16 offset;
    u16 _pad2;
    u8 ok;
    u8 _pad3[3];
};

extern "C"
{
    /// Decode one standard cap header at `off`. Returns true with
    /// the {cap_id, next_offset} pair populated; `next_offset` is
    /// the validated advance (0 on end-of-list / self-loop /
    /// out-of-range pointer).
    bool duetos_pci_caps_parse_standard_at(const u8* config, usize config_len, usize off, DuetosPciCap* out);

    /// Walk the standard capability chain for `cap_id`. Hop-capped
    /// at 48 iterations to bound pathological cycles. Returns the
    /// first matching header on success.
    bool duetos_pci_caps_find_standard(const u8* config, usize config_len, u8 cap_id, DuetosPciCap* out);

    /// Decode one PCIe extended cap header at `off`. The packed
    /// 32-bit shape is (cap_id:16 | version:4 | next:12); the
    /// walker enforces dword alignment, in-range pointer bounds,
    /// and the all-zero "no ext caps" sentinel.
    bool duetos_pci_caps_parse_extended_at(const u8* config, usize config_len, usize off, DuetosPciExtCap* out);

    /// Walk the PCIe extended capability chain for `cap_id`. Hop-
    /// capped at 256 iterations.
    bool duetos_pci_caps_find_extended(const u8* config, usize config_len, u16 cap_id, DuetosPciExtCap* out);
}

} // namespace duetos::drivers::pci::caps_rust
