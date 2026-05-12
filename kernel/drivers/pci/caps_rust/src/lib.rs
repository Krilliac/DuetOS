//! DuetOS PCI / PCIe capability list walkers.
//!
//! Walks two attacker-controlled capability chains a PCI device
//! exposes through its configuration space:
//!
//!   - Standard capability list (8-bit "next" pointers, head at
//!     offset 0x34). Used by every modern PCI driver in the kernel.
//!   - PCIe extended capability list (12-bit "next" pointers, head
//!     at offset 0x100).
//!
//! The walker sees a `config[0..len]` byte slice the caller has
//! pre-validated as readable (the kernel maps standard 256-byte
//! config or full 4096-byte ECAM, depending on call site). Every
//! pointer read clamps to that slice; cycles are bounded by a hop
//! cap.

#![no_std]

use core::{ptr, slice};

// ---------- C-ABI out-structs ----------

/// One standard capability header (4 bytes shape: id, next, payload[2]).
/// `offset` is the byte offset within `config` where this header lives;
/// it lets the caller index further bytes within the validated bound.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct DuetosPciCap {
    /// Cap-ID byte (0x01 PM, 0x05 MSI, 0x10 PCIe, 0x11 MSI-X, …).
    pub cap_id: u8,
    /// Offset of the next cap (0 = end-of-list), already low-2-bits
    /// masked, already bounded.
    pub next_offset: u8,
    pub _pad0: u16,
    /// Byte offset of this header within `config`.
    pub offset: u16,
    pub _pad1: u16,
    pub ok: u8,
    pub _pad2: [u8; 3],
}

/// One PCIe extended capability header (4 bytes shape: id:16, rev:4, next:12).
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct DuetosPciExtCap {
    /// 16-bit ext-cap ID (0x0001 AER, 0x000F ATS, 0x0010 SR-IOV, …).
    pub cap_id: u16,
    /// Capability version (low 4 bits of the second word).
    pub version: u8,
    pub _pad0: u8,
    /// Offset of the next ext-cap (0 = end-of-list), already
    /// bounded.
    pub next_offset: u16,
    pub _pad1: u16,
    /// Byte offset of this header within `config`.
    pub offset: u16,
    pub _pad2: u16,
    pub ok: u8,
    pub _pad3: [u8; 3],
}

// ---------- constants ----------

/// Where the standard capability-list head pointer lives in a
/// header-type-0 config space (PCI spec §6.7).
pub const PCI_STD_CAP_HEAD_OFFSET: usize = 0x34;
/// Low two bits of every cap pointer are reserved and must be
/// masked off before use.
pub const PCI_STD_CAP_PTR_MASK: u8 = 0xFC;
/// Standard caps live in the first 256 bytes of config space.
/// Anything past that is either an extended cap or a malformed
/// pointer.
pub const PCI_STD_CONFIG_SIZE: usize = 256;
/// Maximum number of distinct standard caps the spec allows. Each
/// cap header is 4 bytes minimum, so 48 fits within the 192-byte
/// region (0x40..0xFF) caps can live in.
pub const PCI_STD_CAP_HOP_CAP: usize = 48;

/// First PCIe extended capability lives at offset 0x100 in ECAM.
pub const PCIE_EXT_CAP_HEAD_OFFSET: usize = 0x100;
/// Full ECAM (extended config) region is 4096 bytes.
pub const PCIE_ECAM_SIZE: usize = 4096;
/// Maximum number of distinct extended caps; analogous to the
/// standard cap hop cap, sized for the 3840-byte ECAM tail.
pub const PCIE_EXT_CAP_HOP_CAP: usize = 256;

// ---------- helpers ----------

fn slice_from_raw<'a>(p: *const u8, len: usize) -> Option<&'a [u8]> {
    if p.is_null() {
        return None;
    }
    // SAFETY: FFI contract pins `p` as valid for `len` bytes.
    Some(unsafe { slice::from_raw_parts(p, len) })
}

fn out_init<'a, T: Default + Copy>(out: *mut T) -> Option<&'a mut T> {
    if out.is_null() {
        return None;
    }
    // SAFETY: FFI contract pins `out` as a writable T-sized region.
    unsafe {
        ptr::write(out, T::default());
        Some(&mut *out)
    }
}

#[inline]
fn load_u32_le(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
}

// ---------- standard cap walker ----------

fn parse_standard_cap_at(config: &[u8], off: usize, out: &mut DuetosPciCap) -> bool {
    // Header is 4 bytes: cap_id, next_ptr, payload[2]. Real caps
    // can extend past 4 bytes, but the chain walker only needs
    // the first two. Standard caps live in [0x40, 0xFF].
    if !(0x40..PCI_STD_CONFIG_SIZE).contains(&off) {
        return false;
    }
    if off + 2 > config.len() {
        return false;
    }
    let cap_id = config[off];
    let raw_next = config[off + 1];
    let next = raw_next & PCI_STD_CAP_PTR_MASK;
    // Spec: next == 0 ⇒ end of list. Anything outside [0x40, 0xFF]
    // is malformed; clamp to 0 so callers see end-of-list.
    let next_offset = if next == 0 || (next as usize) < 0x40 || (next as usize) >= PCI_STD_CONFIG_SIZE {
        0
    } else if next as usize == off {
        // Self-loop — refuse to advance.
        0
    } else {
        next
    };
    out.cap_id = cap_id;
    out.next_offset = next_offset;
    out.offset = off as u16;
    out.ok = 1;
    true
}

fn find_standard_cap(config: &[u8], cap_id: u8, out: &mut DuetosPciCap) -> bool {
    // PCI status register bit 4 at offset 0x06 = "Capabilities List
    // present". The caller has already confirmed that bit (or
    // doesn't care to enforce it on QEMU's emulation); we only
    // need the head pointer.
    if config.len() < PCI_STD_CAP_HEAD_OFFSET + 1 {
        return false;
    }
    let head = config[PCI_STD_CAP_HEAD_OFFSET] & PCI_STD_CAP_PTR_MASK;
    if head == 0 || (head as usize) < 0x40 {
        return false;
    }
    let mut cursor = head as usize;
    let mut visited_first: Option<usize> = None;
    for _ in 0..PCI_STD_CAP_HOP_CAP {
        let mut cap = DuetosPciCap::default();
        if !parse_standard_cap_at(config, cursor, &mut cap) {
            return false;
        }
        if cap.cap_id == cap_id {
            *out = cap;
            return true;
        }
        // Cycle detection on the second hop. The fixed hop cap is
        // already a backstop, but catching obvious A-B-A cycles
        // early lets the walker exit faster on the malformed case.
        if let Some(first) = visited_first {
            if cap.next_offset as usize == first {
                return false;
            }
        } else {
            visited_first = Some(cursor);
        }
        if cap.next_offset == 0 {
            return false;
        }
        cursor = cap.next_offset as usize;
    }
    false
}

// ---------- PCIe extended cap walker ----------

fn parse_extended_cap_at(config: &[u8], off: usize, out: &mut DuetosPciExtCap) -> bool {
    // ECAM header is 4 bytes: dword = (cap_id: 16 | version: 4 | next_offset: 12).
    if off < PCIE_EXT_CAP_HEAD_OFFSET || off + 4 > config.len() {
        return false;
    }
    // PCIe alignment: ext caps are dword-aligned.
    if off & 0x3 != 0 {
        return false;
    }
    let word = load_u32_le(config, off);
    let cap_id = (word & 0xFFFF) as u16;
    let version = ((word >> 16) & 0xF) as u8;
    let raw_next = ((word >> 20) & 0xFFF) as u16;
    // Per PCIe §7.9: cap_id == 0 AND next == 0 AND version == 0
    // signals "no extended caps". A caller that walked here from
    // 0x100 sees that as a clean "ext-cap list empty" state.
    if cap_id == 0 && version == 0 && raw_next == 0 {
        out.cap_id = 0;
        out.version = 0;
        out.next_offset = 0;
        out.offset = off as u16;
        out.ok = 1;
        return true;
    }
    // Single clamp: 0 (end-of-list), out-of-range, mis-aligned,
    // and self-loop all fold to 0. Keep them in one boolean so
    // clippy doesn't flag the chain.
    let next_in_bounds = (raw_next as usize) >= PCIE_EXT_CAP_HEAD_OFFSET
        && (raw_next as usize) < PCIE_ECAM_SIZE
        && (raw_next & 0x3 == 0)
        && (raw_next as usize) != off;
    let next_offset = if raw_next != 0 && next_in_bounds { raw_next } else { 0 };
    out.cap_id = cap_id;
    out.version = version;
    out.next_offset = next_offset;
    out.offset = off as u16;
    out.ok = 1;
    true
}

fn find_extended_cap(config: &[u8], cap_id: u16, out: &mut DuetosPciExtCap) -> bool {
    if config.len() < PCIE_EXT_CAP_HEAD_OFFSET + 4 {
        return false;
    }
    let mut cursor = PCIE_EXT_CAP_HEAD_OFFSET;
    for _ in 0..PCIE_EXT_CAP_HOP_CAP {
        let mut cap = DuetosPciExtCap::default();
        if !parse_extended_cap_at(config, cursor, &mut cap) {
            return false;
        }
        // The all-zero header at the first hop means "no ext caps".
        if cap.cap_id == 0 && cap.version == 0 && cap.next_offset == 0 {
            return false;
        }
        if cap.cap_id == cap_id {
            *out = cap;
            return true;
        }
        if cap.next_offset == 0 {
            return false;
        }
        cursor = cap.next_offset as usize;
    }
    false
}

// ---------- FFI entry points ----------

/// Decode one standard capability header at `off` within the
/// configuration-space slice. Returns true on a valid header with
/// `out->{cap_id, next_offset, offset}` populated. The
/// `next_offset` value is the caller-safe advance — 0 when the
/// chain ends, the device reported a self-loop, or the pointer
/// fell outside the canonical [0x40, 0xFF] range.
#[no_mangle]
pub extern "C" fn duetos_pci_caps_parse_standard_at(
    config: *const u8,
    config_len: usize,
    off: usize,
    out: *mut DuetosPciCap,
) -> bool {
    let Some(dst) = out_init(out) else {
        return false;
    };
    let Some(slice) = slice_from_raw(config, config_len) else {
        return false;
    };
    parse_standard_cap_at(slice, off, dst)
}

/// Walk the standard capability list looking for the first cap
/// with `cap_id`. Hop-capped at `PCI_STD_CAP_HOP_CAP` (48) to bound
/// pathological cycles or runaway chains.
#[no_mangle]
pub extern "C" fn duetos_pci_caps_find_standard(
    config: *const u8,
    config_len: usize,
    cap_id: u8,
    out: *mut DuetosPciCap,
) -> bool {
    let Some(dst) = out_init(out) else {
        return false;
    };
    let Some(slice) = slice_from_raw(config, config_len) else {
        return false;
    };
    find_standard_cap(slice, cap_id, dst)
}

/// Decode one PCIe extended capability header at `off`. The 4-byte
/// header packs (cap_id:16 | version:4 | next:12). `next_offset` is
/// the caller-safe advance — 0 on end-of-list, mis-alignment, out-
/// of-range pointer, or self-loop.
#[no_mangle]
pub extern "C" fn duetos_pci_caps_parse_extended_at(
    config: *const u8,
    config_len: usize,
    off: usize,
    out: *mut DuetosPciExtCap,
) -> bool {
    let Some(dst) = out_init(out) else {
        return false;
    };
    let Some(slice) = slice_from_raw(config, config_len) else {
        return false;
    };
    parse_extended_cap_at(slice, off, dst)
}

/// Walk the PCIe extended capability list looking for the first
/// cap with `cap_id`. Hop-capped at `PCIE_EXT_CAP_HOP_CAP` (256)
/// to bound pathological cycles.
#[no_mangle]
pub extern "C" fn duetos_pci_caps_find_extended(
    config: *const u8,
    config_len: usize,
    cap_id: u16,
    out: *mut DuetosPciExtCap,
) -> bool {
    let Some(dst) = out_init(out) else {
        return false;
    };
    let Some(slice) = slice_from_raw(config, config_len) else {
        return false;
    };
    find_extended_cap(slice, cap_id, dst)
}

// ---------- hosted tests ----------

#[cfg(test)]
mod tests {
    use super::*;
    extern crate alloc;

    fn make_std_config_with_chain(chain: &[(u8, u8)]) -> [u8; 256] {
        // chain[0] becomes the head at offset 0x40; subsequent entries
        // are laid out 8 bytes apart in increasing offset order.
        let mut cfg = [0u8; 256];
        // Status register bit-4 set ("caps list present"); status reg
        // is at offset 0x06 (LE 16-bit).
        cfg[6] = 0x10;
        if chain.is_empty() {
            return cfg;
        }
        let head = 0x40u8;
        cfg[0x34] = head;
        for (i, (cap_id, _)) in chain.iter().enumerate() {
            let here = 0x40 + (i as u8) * 8;
            let next = if i + 1 < chain.len() {
                0x40 + ((i + 1) as u8) * 8
            } else {
                0
            };
            cfg[here as usize] = *cap_id;
            cfg[here as usize + 1] = next;
        }
        cfg
    }

    #[test]
    fn standard_find_msix_in_chain() {
        let cfg = make_std_config_with_chain(&[(0x01, 0x48), (0x05, 0x50), (0x11, 0x00)]);
        let mut out = DuetosPciCap::default();
        assert!(find_standard_cap(&cfg, 0x11, &mut out));
        assert_eq!(out.cap_id, 0x11);
        assert_eq!(out.offset, 0x50);
        assert_eq!(out.ok, 1);
    }

    #[test]
    fn standard_find_missing_returns_false() {
        let cfg = make_std_config_with_chain(&[(0x01, 0x48), (0x05, 0x00)]);
        let mut out = DuetosPciCap::default();
        assert!(!find_standard_cap(&cfg, 0x11, &mut out));
        assert_eq!(out.ok, 0);
    }

    #[test]
    fn standard_no_caps_present_returns_false() {
        let cfg = [0u8; 256]; // status bit 4 clear, head=0
        let mut out = DuetosPciCap::default();
        assert!(!find_standard_cap(&cfg, 0x05, &mut out));
    }

    #[test]
    fn standard_self_loop_rejects() {
        let mut cfg = [0u8; 256];
        cfg[6] = 0x10;
        cfg[0x34] = 0x40;
        cfg[0x40] = 0x05; // MSI
        cfg[0x41] = 0x40; // points to itself
        let mut out = DuetosPciCap::default();
        // The cap with id 0x05 IS at 0x40 — we find it on the first
        // visit. So search for a missing ID to hit the loop logic.
        assert!(!find_standard_cap(&cfg, 0x11, &mut out));
    }

    #[test]
    fn standard_out_of_range_next_rejects() {
        let mut cfg = [0u8; 256];
        cfg[6] = 0x10;
        cfg[0x34] = 0x40;
        cfg[0x40] = 0x05;
        cfg[0x41] = 0x20; // < 0x40 — malformed
        let mut out = DuetosPciCap::default();
        // First cap (MSI) is decoded fine and matches if asked.
        assert!(find_standard_cap(&cfg, 0x05, &mut out));
        // Missing ID won't be found — chain terminates at the bad ptr.
        assert!(!find_standard_cap(&cfg, 0x11, &mut out));
    }

    #[test]
    fn standard_unaligned_low_bits_masked() {
        // Spec: low two bits of cap pointer are reserved. A device
        // setting them must not derail the walker.
        let mut cfg = [0u8; 256];
        cfg[6] = 0x10;
        cfg[0x34] = 0x41; // head=0x40 + reserved bit
        cfg[0x40] = 0x11; // MSI-X
        cfg[0x41] = 0x00;
        let mut out = DuetosPciCap::default();
        assert!(find_standard_cap(&cfg, 0x11, &mut out));
        assert_eq!(out.offset, 0x40);
    }

    #[test]
    fn standard_head_below_floor_rejects() {
        let mut cfg = [0u8; 256];
        cfg[6] = 0x10;
        cfg[0x34] = 0x20; // < 0x40
        let mut out = DuetosPciCap::default();
        assert!(!find_standard_cap(&cfg, 0x05, &mut out));
    }

    fn make_ecam_with_extended_chain(chain: &[(u16, u8)]) -> alloc::vec::Vec<u8> {
        use alloc::vec::Vec;
        let mut cfg: Vec<u8> = alloc::vec![0u8; 4096];
        if chain.is_empty() {
            return cfg;
        }
        // First ext-cap header lives at 0x100; subsequent entries are
        // laid out 16 bytes apart.
        for (i, (cap_id, version)) in chain.iter().enumerate() {
            let here = 0x100usize + i * 16;
            let next: u16 = if i + 1 < chain.len() {
                (0x100usize + (i + 1) * 16) as u16
            } else {
                0
            };
            let word = u32::from(*cap_id) | (u32::from(*version) << 16) | (u32::from(next) << 20);
            cfg[here..here + 4].copy_from_slice(&word.to_le_bytes());
        }
        cfg
    }

    #[test]
    fn extended_find_aer() {
        let cfg = make_ecam_with_extended_chain(&[(0x0001, 1), (0x000F, 1), (0x0010, 1)]); // AER, ATS, SR-IOV
        let mut out = DuetosPciExtCap::default();
        assert!(find_extended_cap(&cfg, 0x0001, &mut out));
        assert_eq!(out.cap_id, 0x0001);
        assert_eq!(out.version, 1);
        assert_eq!(out.offset, 0x100);
    }

    #[test]
    fn extended_find_sriov_at_chain_tail() {
        let cfg = make_ecam_with_extended_chain(&[(0x0001, 1), (0x000F, 1), (0x0010, 1)]);
        let mut out = DuetosPciExtCap::default();
        assert!(find_extended_cap(&cfg, 0x0010, &mut out));
        assert_eq!(out.cap_id, 0x0010);
        assert_eq!(out.offset, 0x120);
    }

    #[test]
    fn extended_find_missing_returns_false() {
        let cfg = make_ecam_with_extended_chain(&[(0x0001, 1)]);
        let mut out = DuetosPciExtCap::default();
        assert!(!find_extended_cap(&cfg, 0x0010, &mut out));
    }

    #[test]
    fn extended_all_zero_at_head_means_empty() {
        let cfg = alloc::vec![0u8; 4096];
        let mut out = DuetosPciExtCap::default();
        assert!(!find_extended_cap(&cfg, 0x0001, &mut out));
    }

    #[test]
    fn extended_unaligned_next_terminates() {
        let mut cfg: alloc::vec::Vec<u8> = alloc::vec![0u8; 4096];
        // Build a head ext-cap with next=0x101 (unaligned). Walker
        // must clamp to "end of list" rather than fall off the rails.
        let word: u32 = 0x0001 | (1 << 16) | (0x101 << 20);
        cfg[0x100..0x104].copy_from_slice(&word.to_le_bytes());
        let mut out = DuetosPciExtCap::default();
        assert!(find_extended_cap(&cfg, 0x0001, &mut out));
        assert_eq!(out.next_offset, 0);
    }

    #[test]
    fn extended_self_loop_rejects() {
        let mut cfg: alloc::vec::Vec<u8> = alloc::vec![0u8; 4096];
        // Build a head ext-cap with next = 0x100 (self).
        let word: u32 = 0x0001 | (1 << 16) | (0x100 << 20);
        cfg[0x100..0x104].copy_from_slice(&word.to_le_bytes());
        let mut out = DuetosPciExtCap::default();
        // The cap with cap_id 0x0001 IS at 0x100, so search for
        // a missing ID to exercise the loop logic.
        assert!(!find_extended_cap(&cfg, 0x0010, &mut out));
    }

    #[test]
    fn extended_out_of_range_next_terminates() {
        let mut cfg: alloc::vec::Vec<u8> = alloc::vec![0u8; 4096];
        let word: u32 = 0x0001 | (1 << 16) | (0x1000 << 20); // > 4096
        cfg[0x100..0x104].copy_from_slice(&word.to_le_bytes());
        let mut out = DuetosPciExtCap::default();
        assert!(find_extended_cap(&cfg, 0x0001, &mut out));
        assert_eq!(out.next_offset, 0);
    }

    #[test]
    fn extended_short_config_rejects() {
        let cfg = alloc::vec![0u8; 0x100]; // standard config only, no ECAM
        let mut out = DuetosPciExtCap::default();
        assert!(!find_extended_cap(&cfg, 0x0001, &mut out));
    }

    #[test]
    fn standard_parse_at_low_offset_rejects() {
        let cfg = make_std_config_with_chain(&[(0x05, 0)]);
        let mut out = DuetosPciCap::default();
        // 0x20 is below the 0x40 cap-region floor.
        assert!(!parse_standard_cap_at(&cfg, 0x20, &mut out));
    }

    #[test]
    fn standard_parse_at_out_of_range_offset_rejects() {
        let cfg = [0u8; 64];
        let mut out = DuetosPciCap::default();
        // 0x40 is within the cap region but past end of slice.
        assert!(!parse_standard_cap_at(&cfg, 0x40, &mut out));
    }
}
