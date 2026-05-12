//! DuetOS net-protocol byte-walkers.
//!
//! Two parsers, both consume slices that came in off the wire
//! (DHCPv4 options stream, DNSv1 name field). The crate is a
//! thin FFI shim around safe-Rust slice traversal; every
//! integer arithmetic step uses `checked_add` so a malformed
//! packet can't underflow or wrap into a successful pass.
//!
//! C++ callers live in `kernel/net/stack.cpp`; FFI shape pins
//! the contract verbatim (see `include/parsers_rust.h`).

#![no_std]

use core::{ptr, slice};

// ---------- internal helpers ----------
//
// Every raw-pointer dereference is concentrated in these helpers so
// the `pub extern "C"` entry points are clippy-clean (and so a
// future "no unsafe outside the FFI wall" audit only needs to look
// at this section).

/// Reconstruct a slice from a `(ptr, len)` FFI pair, returning
/// `None` if `ptr` is null.
fn slice_from_raw<'a>(ptr: *const u8, len: usize) -> Option<&'a [u8]> {
    if ptr.is_null() {
        return None;
    }
    // SAFETY: caller's FFI contract is that `ptr` is valid for `len`
    // bytes when non-null. The lifetime parameter is bound to the
    // scope of the FFI call frame — we never store the slice past
    // the call.
    Some(unsafe { slice::from_raw_parts(ptr, len) })
}

/// Write the DHCP miss outputs (`out_data = null`, `out_len = 0`)
/// then return `false`. Encapsulates the only raw-pointer write the
/// DHCP entry point performs on the miss path.
fn dhcp_clear_outputs(out_data: *mut *const u8, out_len: *mut u8) -> bool {
    if out_data.is_null() || out_len.is_null() {
        return false;
    }
    // SAFETY: out-pointers checked non-null above; FFI contract
    // pins them as writable.
    unsafe {
        ptr::write(out_data, ptr::null());
        ptr::write(out_len, 0);
    }
    true
}

/// Write the DHCP hit outputs (pointer to first value byte + value
/// length). Caller has already validated the value fits in u8.
fn dhcp_write_hit(out_data: *mut *const u8, out_len: *mut u8, value: &[u8]) {
    debug_assert!(!out_data.is_null());
    debug_assert!(!out_len.is_null());
    debug_assert!(value.len() <= u8::MAX as usize);
    // SAFETY: debug_assertions document invariants the caller must
    // hold; FFI contract pins the out-pointers as writable.
    unsafe {
        ptr::write(out_data, value.as_ptr());
        ptr::write(out_len, value.len() as u8);
    }
}

// ---------- DHCPv4 ----------

const DHCP_OPT_PAD: u8 = 0;
const DHCP_OPT_END: u8 = 255;

/// Find the first occurrence of `opt_code` in a DHCPv4 options
/// stream and return its value as a sub-slice of `opts`.
///
/// The walker handles the two RFC 2132 short options (PAD = 0,
/// END = 255) explicitly. Any malformed length / truncated tail
/// returns `None` without panic, even on attacker input.
fn dhcp_find_option(opts: &[u8], opt_code: u8) -> Option<&[u8]> {
    let mut i: usize = 0;
    while i < opts.len() {
        let c = opts[i];
        i = i.checked_add(1)?;
        if c == DHCP_OPT_PAD {
            continue;
        }
        if c == DHCP_OPT_END {
            return None;
        }
        // Every other tag carries a 1-byte length followed by `len`
        // value bytes. Reject a truncated header AND a truncated
        // body — both indicate a buggy or hostile sender.
        if i >= opts.len() {
            return None;
        }
        let l = opts[i] as usize;
        i = i.checked_add(1)?;
        let end = i.checked_add(l)?;
        if end > opts.len() {
            return None;
        }
        if c == opt_code {
            return Some(&opts[i..end]);
        }
        i = end;
    }
    None
}

/// FFI: locate `opt_code` in `opts` and return its value via the
/// out-pointers. Returns `true` on hit, `false` on miss / invalid.
///
/// Mirrors the contract of the previous C++ `DhcpFindOption` so
/// the call sites can swap one for the other with no semantic
/// change.
#[no_mangle]
pub extern "C" fn duetos_parsers_dhcp_find_option(
    opts: *const u8,
    opts_len: usize,
    opt_code: u8,
    out_data: *mut *const u8,
    out_len: *mut u8,
) -> bool {
    // Pre-zero the outputs so a miss / invalid-input path leaves
    // well-defined sentinels in the caller's locals.
    if !dhcp_clear_outputs(out_data, out_len) {
        return false;
    }
    let Some(buf) = slice_from_raw(opts, opts_len) else {
        return false;
    };
    let Some(value) = dhcp_find_option(buf, opt_code) else {
        return false;
    };
    // RFC 2132 caps option-length at 255 bytes because the length
    // field is a single u8; `dhcp_find_option` already rejected
    // anything longer.
    dhcp_write_hit(out_data, out_len, value);
    true
}

// ---------- DNSv1 ----------

/// Maximum number of name-walk iterations before we give up. RFC
/// 1035 caps a fully-uncompressed name at 255 bytes, which is at
/// most 128 labels; the cap below leaves plenty of headroom while
/// still bailing on a pathological compression-pointer loop.
const DNS_NAME_GUARD: u32 = 1024;

/// Skip past a DNS name in an RR stream and return the offset of
/// the first byte after it. Handles both raw label sequences and
/// RFC 1035 §4.1.4 compression pointers ((b & 0xC0) == 0xC0).
///
/// On truncation, invalid label length, or guard exhaustion the
/// function returns `len` so the caller treats it as "rest of
/// packet is unusable" — same convention the previous C++ helper
/// used.
fn dns_skip_name(buf: &[u8], mut offset: usize) -> usize {
    let len = buf.len();
    for _ in 0..DNS_NAME_GUARD {
        if offset >= len {
            return len;
        }
        let b = buf[offset];
        if b == 0 {
            return offset.saturating_add(1).min(len.saturating_add(1));
        }
        if (b & 0xC0) == 0xC0 {
            // Compression pointer — 2-byte field, jumps elsewhere in
            // the packet. We do NOT follow the jump because the
            // caller only wants to advance past THIS occurrence;
            // walking the pointee is an answer-name-materialisation
            // job and isn't in v0 scope.
            return offset.checked_add(2).filter(|&e| e <= len).unwrap_or(len);
        }
        if b > 63 {
            return len; // invalid label length per RFC 1035 §4.1.4
        }
        // Advance past the length byte + label bytes.
        let next = offset.checked_add(1).and_then(|x| x.checked_add(b as usize));
        match next {
            Some(n) if n <= len => offset = n,
            _ => return len,
        }
    }
    len
}

/// FFI: skip past a DNS name and return the offset of the byte
/// after it (or `len` on any failure).
///
/// Mirrors the contract of the previous C++ `DnsSkipName`.
#[no_mangle]
pub extern "C" fn duetos_parsers_dns_skip_name(buf: *const u8, offset: usize, len: usize) -> usize {
    let Some(slice) = slice_from_raw(buf, len) else {
        return len;
    };
    if offset > slice.len() {
        return len;
    }
    dns_skip_name(slice, offset)
}

// ---------- hosted tests ----------
//
// These run under `cargo test --target <host>`; the kernel build
// uses `--target x86_64-unknown-none` and skips the test target
// (libtest needs std). Both halves stay in this file so the test
// helpers can reach the internal walkers directly.

#[cfg(test)]
mod tests {
    use super::*;

    // --- DHCP ---

    #[test]
    fn dhcp_finds_first_match() {
        // [option=53 (msg type), len=1, value=2 (OFFER)]
        // [option=54 (server id), len=4, value=10.0.0.1]
        // [option=255 (end)]
        let opts = [53, 1, 2, 54, 4, 10, 0, 0, 1, 255];
        let v = dhcp_find_option(&opts, 53).unwrap();
        assert_eq!(v, &[2]);
        let v = dhcp_find_option(&opts, 54).unwrap();
        assert_eq!(v, &[10, 0, 0, 1]);
    }

    #[test]
    fn dhcp_pad_then_end_returns_none() {
        let opts = [0, 0, 0, 255];
        assert!(dhcp_find_option(&opts, 53).is_none());
    }

    #[test]
    fn dhcp_truncated_length_byte_rejects() {
        // Tag 53 with length field truncated.
        let opts = [53];
        assert!(dhcp_find_option(&opts, 53).is_none());
    }

    #[test]
    fn dhcp_truncated_value_rejects() {
        // Tag 53, claims length=4 but only 2 bytes follow.
        let opts = [53, 4, 1, 2];
        assert!(dhcp_find_option(&opts, 53).is_none());
    }

    #[test]
    fn dhcp_max_length_value_ok() {
        let mut opts = [0u8; 1 + 1 + 255];
        opts[0] = 99;
        opts[1] = 255;
        let v = dhcp_find_option(&opts, 99).unwrap();
        assert_eq!(v.len(), 255);
    }

    #[test]
    fn dhcp_missing_code_returns_none_without_end() {
        // [tag=1 len=4 val=0,0,0,0] — no END marker; loop terminates
        // when it falls off the end of the slice.
        let opts = [1, 4, 0, 0, 0, 0];
        assert!(dhcp_find_option(&opts, 53).is_none());
    }

    #[test]
    fn dhcp_empty_returns_none() {
        let opts: [u8; 0] = [];
        assert!(dhcp_find_option(&opts, 53).is_none());
    }

    // --- DNS ---

    #[test]
    fn dns_skips_raw_labels() {
        // "duetos.org" = [6] d u e t o s [3] o r g [0]
        let buf = [6, b'd', b'u', b'e', b't', b'o', b's', 3, b'o', b'r', b'g', 0, 0xff];
        let off = dns_skip_name(&buf, 0);
        assert_eq!(off, 12); // points at the trailing 0xff
    }

    #[test]
    fn dns_handles_compression_pointer() {
        // Compression pointer to offset 0x0042 = [0xC0 0x42].
        let buf = [0xC0, 0x42, 0xff];
        let off = dns_skip_name(&buf, 0);
        assert_eq!(off, 2);
    }

    #[test]
    fn dns_truncated_compression_pointer_returns_len() {
        // Single byte starting a pointer with nothing after it.
        let buf = [0xC0];
        let off = dns_skip_name(&buf, 0);
        assert_eq!(off, buf.len());
    }

    #[test]
    fn dns_invalid_label_length_returns_len() {
        // 64 is illegal (top two bits are 01, not 00 or 11).
        let buf = [64, 0, 0, 0];
        let off = dns_skip_name(&buf, 0);
        assert_eq!(off, buf.len());
    }

    #[test]
    fn dns_pointer_loop_terminates() {
        // Two-byte pointer that points at itself: 0xC0 0x00.
        let buf = [0xC0, 0x00];
        let off = dns_skip_name(&buf, 0);
        // We do NOT follow the jump, so we just advance past the
        // 2-byte pointer field. Either way we don't hang.
        assert_eq!(off, 2);
    }

    #[test]
    fn dns_terminator_only() {
        let buf = [0u8];
        let off = dns_skip_name(&buf, 0);
        assert_eq!(off, 1);
    }

    #[test]
    fn dns_offset_past_buf_returns_len() {
        let buf = [1u8, b'a', 0];
        let off = dns_skip_name(&buf, 99);
        // The skip helper returns `len` on out-of-range offset.
        assert_eq!(off, buf.len());
    }
}
