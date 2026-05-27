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

// ---------- TCP options ----------
//
// RFC 793 + 9293 §3.1: an options stream lives in TCP-header bytes
// 20..(data_offset × 4). Each option is either a single-byte short
// option (EOL = 0, NOP = 1) or a TLV (kind, length-incl-header,
// value). The walker iterates the stream and invokes a callback
// for each option; the C++ caller decides what to do with each.
//
// No current consumer in DuetOS — `kernel/net/stack.cpp` extracts
// the fixed TCP fields and ignores options. The walker is here so
// future code can pull MSS / window-scale / SACK / timestamps out
// of incoming SYN segments via a single FFI call.

/// TCP option kinds that carry no length / value byte (each is a
/// single-byte short option).
const TCP_OPT_END_OF_LIST: u8 = 0;
const TCP_OPT_NOP: u8 = 1;
/// Maximum number of options we'll iterate before bailing. The
/// 40-byte options field at most carries 20-ish TLVs; the cap is
/// generous + saturates on a malicious option-of-length-0 spin.
const TCP_OPT_GUARD: u32 = 64;

/// Single TCP option as decoded by `tcp_walk_options`. `kind` is
/// the RFC-assigned number (2 = MSS, 3 = WindowScale, 4 = SACK
/// Permitted, 5 = SACK, 8 = Timestamps, ...). `value_off` and
/// `value_len` describe the value sub-slice; `value_len` is 0 for
/// short options.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct DuetosTcpOption {
    pub kind: u8,
    pub _pad: u8,
    pub value_len: u16,
    pub value_off: u32,
}

/// Callback shape: returns `true` to continue iteration, `false` to
/// stop. The C++ caller stores the cookie pointer; the Rust crate
/// passes it back unchanged.
pub type DuetosTcpOptionCallback = extern "C" fn(*mut core::ffi::c_void, DuetosTcpOption) -> bool;

fn walk_tcp_options(opts: &[u8], cb: DuetosTcpOptionCallback, cookie: *mut core::ffi::c_void) -> u32 {
    let mut visited: u32 = 0;
    let mut i: usize = 0;
    while i < opts.len() && visited < TCP_OPT_GUARD {
        let kind = opts[i];
        if kind == TCP_OPT_END_OF_LIST {
            return visited;
        }
        if kind == TCP_OPT_NOP {
            // Single-byte option, no length / value.
            let opt = DuetosTcpOption {
                kind,
                _pad: 0,
                value_len: 0,
                value_off: i as u32,
            };
            visited = visited.saturating_add(1);
            if !cb(cookie, opt) {
                return visited;
            }
            i = i.saturating_add(1);
            continue;
        }
        // TLV option: kind + length + (length-2) value bytes.
        // length is total option size INCLUDING the kind+length
        // header, so length must be >= 2.
        let Some(len_off) = i.checked_add(1) else {
            return visited;
        };
        if len_off >= opts.len() {
            return visited;
        }
        let opt_len = opts[len_off] as usize;
        if opt_len < 2 {
            // Malformed — every TLV must carry at least the
            // header. Bail rather than risk an infinite loop on
            // length-0 options.
            return visited;
        }
        let Some(end) = i.checked_add(opt_len) else {
            return visited;
        };
        if end > opts.len() {
            return visited;
        }
        let opt = DuetosTcpOption {
            kind,
            _pad: 0,
            value_len: (opt_len - 2) as u16,
            value_off: (i + 2) as u32,
        };
        visited = visited.saturating_add(1);
        if !cb(cookie, opt) {
            return visited;
        }
        i = end;
    }
    visited
}

/// FFI: walk the TCP-options stream `opts` (typically TCP-header
/// bytes 20..(data_offset × 4)). For each option the crate calls
/// `cb(cookie, option)`. Returning `false` from the callback
/// stops iteration. Returns the number of options visited
/// (capped at `TCP_OPT_GUARD = 64`).
///
/// Malformed options (length < 2, length > remaining stream) abort
/// iteration without panic; a hostile peer sending a length-0 TLV
/// can't pin the kernel in a loop.
#[no_mangle]
pub extern "C" fn duetos_parsers_tcp_walk_options(
    opts: *const u8,
    opts_len: usize,
    cb: DuetosTcpOptionCallback,
    cookie: *mut core::ffi::c_void,
) -> u32 {
    let Some(slice) = slice_from_raw(opts, opts_len) else {
        return 0;
    };
    walk_tcp_options(slice, cb, cookie)
}

/// Aggregated parsed-options view used by the v1 TCP receiver.
/// Mirrors the C++ `ParsedOptions` struct in
/// kernel/net/tcp_segment.cpp. Fields are zero-initialised; only
/// the option kinds the receiver recognises are populated. SACK
/// blocks themselves are not captured here — the receiver-side
/// SACK consumer only needs the `sack_permitted` negotiation
/// flag; the sender-side scoreboard (RFC 6675 NextSeg/IsLost)
/// that consumes inbound SACK blocks is its own future slice.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct DuetosTcpParsedOptions {
    pub mss: u16,
    pub wscale: u8,
    pub has_wscale: bool,
    pub sack_permitted: bool,
    pub has_timestamp: bool,
    pub _pad0: [u8; 2],
    pub tsval: u32,
    pub tsecr: u32,
}

const TCP_OPT_KIND_MSS: u8 = 2;
const TCP_OPT_KIND_WINDOW_SCALE: u8 = 3;
const TCP_OPT_KIND_SACK_PERMITTED: u8 = 4;
const TCP_OPT_KIND_TIMESTAMP: u8 = 8;

fn parse_tcp_options(opts: &[u8], out: &mut DuetosTcpParsedOptions) {
    let mut i: usize = 0;
    // Cap loop iterations the same way `walk_tcp_options` does so a
    // hostile peer sending length-0 TLVs can't pin the kernel in a
    // loop even if our length-check has a latent off-by-one bug.
    let mut visited: u32 = 0;
    while i < opts.len() && visited < TCP_OPT_GUARD {
        let kind = opts[i];
        if kind == TCP_OPT_END_OF_LIST {
            return;
        }
        if kind == TCP_OPT_NOP {
            i = i.saturating_add(1);
            visited = visited.saturating_add(1);
            continue;
        }
        // TLV: need kind + len + (len-2) value bytes.
        let Some(len_off) = i.checked_add(1) else { return; };
        if len_off >= opts.len() {
            return;
        }
        let opt_len = opts[len_off] as usize;
        if opt_len < 2 {
            return;
        }
        let Some(end) = i.checked_add(opt_len) else { return; };
        if end > opts.len() {
            return;
        }
        match kind {
            TCP_OPT_KIND_MSS if opt_len == 4 => {
                out.mss = (u16::from(opts[i + 2]) << 8) | u16::from(opts[i + 3]);
            }
            TCP_OPT_KIND_WINDOW_SCALE if opt_len == 3 => {
                out.has_wscale = true;
                // RFC 7323 §2.3: shift count must be capped at 14.
                // Saturate here so the caller never sees a wscale
                // that would shift past the u32 boundary on apply.
                let shift = opts[i + 2];
                out.wscale = if shift > 14 { 14 } else { shift };
            }
            TCP_OPT_KIND_SACK_PERMITTED if opt_len == 2 => {
                out.sack_permitted = true;
            }
            TCP_OPT_KIND_TIMESTAMP if opt_len == 10 => {
                out.has_timestamp = true;
                out.tsval = (u32::from(opts[i + 2]) << 24)
                    | (u32::from(opts[i + 3]) << 16)
                    | (u32::from(opts[i + 4]) << 8)
                    | u32::from(opts[i + 5]);
                out.tsecr = (u32::from(opts[i + 6]) << 24)
                    | (u32::from(opts[i + 7]) << 16)
                    | (u32::from(opts[i + 8]) << 8)
                    | u32::from(opts[i + 9]);
            }
            _ => {
                // Ignore unknown / unsupported kinds + malformed
                // lengths; the negotiated set above is what the
                // v1 receiver needs.
            }
        }
        i = end;
        visited = visited.saturating_add(1);
    }
}

/// FFI: parse the recognised RFC-track options from a TCP-options
/// byte stream into the populated `*out`. Returns true iff the
/// inputs were non-null; the actual options stream's
/// well-formed-ness is reflected in the populated struct (a
/// malformed stream simply leaves later fields at default).
#[no_mangle]
pub extern "C" fn duetos_parsers_tcp_parse_options(
    opts: *const u8,
    opts_len: usize,
    out: *mut DuetosTcpParsedOptions,
) -> bool {
    if out.is_null() {
        return false;
    }
    // SAFETY: caller's contract is that out is writable; zero-
    // initialise via the Default impl so partial parses don't
    // leak stale fields.
    unsafe {
        core::ptr::write(out, DuetosTcpParsedOptions::default());
    }
    let Some(slice) = slice_from_raw(opts, opts_len) else {
        // Null opts buffer is a no-op success — caller already
        // sees a zero-initialised struct, which mirrors what the
        // C++ ParseOptions returned on an empty options field.
        return true;
    };
    // SAFETY: out is non-null + writable (just initialised).
    let out_ref = unsafe { &mut *out };
    parse_tcp_options(slice, out_ref);
    true
}

// ---------- IPv4 header ----------

/// One's-complement Internet checksum over a byte slice (RFC 1071).
/// 16-bit big-endian words summed with end-around carry, then the
/// 1's-complement of the low 16 bits is returned. A computed
/// checksum of `0` (i.e. the input ALREADY contains the on-the-wire
/// checksum field) means the stored value matches.
fn ipv4_header_checksum(buf: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i: usize = 0;
    while i + 2 <= buf.len() {
        let word = (u16::from(buf[i]) << 8) | u16::from(buf[i + 1]);
        sum = sum.wrapping_add(u32::from(word));
        i += 2;
    }
    if i < buf.len() {
        // Odd trailing byte — pad with 0 in the low half.
        sum = sum.wrapping_add(u32::from(buf[i]) << 8);
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// Validate an IPv4 header at the start of `buf`. Checks:
///   - buffer holds at least 20 bytes (minimum IHL = 5)
///   - version field == 4
///   - IHL field in [5, 15]
///   - declared header byte count (IHL × 4) doesn't overrun the buffer
///   - total_length field doesn't overrun the buffer
///   - one's-complement checksum over the header bytes is zero
///     (i.e. the stored checksum matches the data)
///
/// All length arithmetic is `checked_mul`/`checked_add`-style — a
/// hostile peer can't drive IHL or total_length into an overflow
/// that wraps to a smaller "fits the buffer" value. Pure compute,
/// no mutation, no allocation.
fn ipv4_header_valid(buf: &[u8]) -> bool {
    if buf.len() < 20 {
        return false;
    }
    let version = buf[0] >> 4;
    let ihl = (buf[0] & 0x0F) as usize;
    if version != 4 {
        return false;
    }
    if ihl < 5 {
        return false;
    }
    let header_bytes = match ihl.checked_mul(4) {
        Some(v) => v,
        None => return false,
    };
    if header_bytes > buf.len() {
        return false;
    }
    let total_len = ((u16::from(buf[2]) << 8) | u16::from(buf[3])) as usize;
    if total_len > buf.len() {
        return false;
    }
    ipv4_header_checksum(&buf[..header_bytes]) == 0
}

/// FFI: compute the IPv4 one's-complement Internet checksum (RFC
/// 1071) over `buf[0..len)`. Returns 0 on a null buffer (caller
/// distinguishes via a sentinel since 0 is also a legitimate
/// "matches stored" result — the typical caller pattern is
/// "if buf is unknown to be non-null, validate it first").
#[no_mangle]
pub extern "C" fn duetos_parsers_ipv4_header_checksum(buf: *const u8, len: usize) -> u16 {
    let Some(slice) = slice_from_raw(buf, len) else {
        return 0;
    };
    ipv4_header_checksum(slice)
}

/// FFI: validate an IPv4 header at the start of `buf`. Returns
/// `true` iff the header is structurally well-formed AND the
/// stored checksum matches.
#[no_mangle]
pub extern "C" fn duetos_parsers_ipv4_header_valid(buf: *const u8, len: usize) -> bool {
    let Some(slice) = slice_from_raw(buf, len) else {
        return false;
    };
    ipv4_header_valid(slice)
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

    // --- TCP options ---

    extern crate alloc;
    use alloc::vec::Vec;
    use core::cell::RefCell;

    /// Test fixture: a thread-local Vec the callback pushes options
    /// into. Using a `RefCell` keeps the callback `extern "C"` safe.
    /// Each test borrows the fixture for the call window only.
    fn collect(opts: &[u8]) -> Vec<DuetosTcpOption> {
        // RefCell lives in a static via thread_local! — we'd use one
        // here but no_std hosted-test-only convenience makes a plain
        // RefCell + raw pointer simpler.
        let collected: RefCell<Vec<DuetosTcpOption>> = RefCell::new(Vec::new());
        extern "C" fn cb(cookie: *mut core::ffi::c_void, opt: DuetosTcpOption) -> bool {
            // SAFETY: cookie was set up below as a `&RefCell<Vec<…>>`
            // pointer that outlives the call.
            let cell: &RefCell<Vec<DuetosTcpOption>> = unsafe { &*(cookie as *const RefCell<Vec<DuetosTcpOption>>) };
            cell.borrow_mut().push(opt);
            true
        }
        let cookie = &collected as *const _ as *mut core::ffi::c_void;
        walk_tcp_options(opts, cb, cookie);
        collected.into_inner()
    }

    #[test]
    fn tcp_opts_empty_returns_zero() {
        let opts: [u8; 0] = [];
        let got = collect(&opts);
        assert!(got.is_empty());
    }

    #[test]
    fn tcp_opts_eol_terminates() {
        let opts = [TCP_OPT_END_OF_LIST, 99, 99];
        let got = collect(&opts);
        assert!(got.is_empty());
    }

    #[test]
    fn tcp_opts_nop_iterates() {
        let opts = [TCP_OPT_NOP, TCP_OPT_NOP, TCP_OPT_END_OF_LIST];
        let got = collect(&opts);
        assert_eq!(got.len(), 2);
        assert!(got.iter().all(|o| o.kind == TCP_OPT_NOP && o.value_len == 0));
    }

    #[test]
    fn tcp_opts_mss_decodes() {
        // MSS option: kind=2, length=4, value = u16 BE = 1460.
        let opts = [2, 4, 0x05, 0xB4, TCP_OPT_END_OF_LIST];
        let got = collect(&opts);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].kind, 2);
        assert_eq!(got[0].value_len, 2);
        assert_eq!(got[0].value_off, 2);
    }

    #[test]
    fn tcp_opts_zero_length_tlv_rejected() {
        // Hostile: kind=42, length=0 — would loop forever in a naive
        // walker. We bail.
        let opts = [42, 0, 0xff];
        let got = collect(&opts);
        assert!(got.is_empty());
    }

    #[test]
    fn tcp_opts_truncated_length_rejected() {
        let opts = [42];
        let got = collect(&opts);
        assert!(got.is_empty());
    }

    #[test]
    fn tcp_opts_truncated_value_rejected() {
        // Claims length=8 but only 3 bytes follow.
        let opts = [42, 8, 1, 2];
        let got = collect(&opts);
        assert!(got.is_empty());
    }

    #[test]
    fn tcp_opts_guard_caps_iteration() {
        // 64+ NOPs in a row — should stop at the guard and return
        // exactly 64 collected options.
        let mut opts = [TCP_OPT_NOP; 100];
        opts[99] = TCP_OPT_END_OF_LIST; // unreachable but documented intent
        let got = collect(&opts);
        assert_eq!(got.len(), TCP_OPT_GUARD as usize);
    }

    #[test]
    fn tcp_opts_callback_can_stop_iteration() {
        let opts = [TCP_OPT_NOP, TCP_OPT_NOP, TCP_OPT_NOP, TCP_OPT_END_OF_LIST];
        // Use a callback that stops after the first option.
        let count: RefCell<u32> = RefCell::new(0);
        extern "C" fn cb(cookie: *mut core::ffi::c_void, _opt: DuetosTcpOption) -> bool {
            // SAFETY: cookie is a `&RefCell<u32>` that outlives the call.
            let cell: &RefCell<u32> = unsafe { &*(cookie as *const RefCell<u32>) };
            *cell.borrow_mut() += 1;
            false // stop after the first option
        }
        let cookie = &count as *const _ as *mut core::ffi::c_void;
        let visited = walk_tcp_options(&opts, cb, cookie);
        assert_eq!(visited, 1);
        assert_eq!(*count.borrow(), 1);
    }

    // --- IPv4 header ---

    fn build_minimal_ipv4_header() -> [u8; 20] {
        // Minimum header: version=4, IHL=5, total_len=20. Checksum
        // computed below.
        let mut h = [0u8; 20];
        h[0] = 0x45; // version=4 IHL=5
        // total length = 20
        h[2] = 0;
        h[3] = 20;
        // TTL + protocol just to keep the checksum non-zero.
        h[8] = 64;
        h[9] = 17; // UDP
        // src/dst zeros — fine.
        // Compute checksum over the header.
        let cs = ipv4_header_checksum(&h);
        h[10] = (cs >> 8) as u8;
        h[11] = cs as u8;
        h
    }

    #[test]
    fn ipv4_minimum_header_ok() {
        let h = build_minimal_ipv4_header();
        assert!(ipv4_header_valid(&h));
    }

    #[test]
    fn ipv4_wrong_version_rejects() {
        let mut h = build_minimal_ipv4_header();
        h[0] = 0x65; // version=6, IHL=5
        assert!(!ipv4_header_valid(&h));
    }

    #[test]
    fn ipv4_ihl_too_small_rejects() {
        let mut h = build_minimal_ipv4_header();
        h[0] = 0x44; // version=4, IHL=4 (invalid — minimum is 5)
        assert!(!ipv4_header_valid(&h));
    }

    #[test]
    fn ipv4_short_buffer_rejects() {
        let h = build_minimal_ipv4_header();
        assert!(!ipv4_header_valid(&h[..19]));
    }

    #[test]
    fn ipv4_bad_checksum_rejects() {
        let mut h = build_minimal_ipv4_header();
        h[10] ^= 0xFF; // corrupt the checksum field
        assert!(!ipv4_header_valid(&h));
    }

    #[test]
    fn ipv4_ihl_overruns_buffer_rejects() {
        // IHL = 15 (max), header would need 60 bytes but the buffer
        // is only 20.
        let mut h = build_minimal_ipv4_header();
        h[0] = 0x4F; // version=4, IHL=15
        assert!(!ipv4_header_valid(&h));
    }

    #[test]
    fn ipv4_total_len_overruns_buffer_rejects() {
        let mut h = build_minimal_ipv4_header();
        h[2] = 0xFF;
        h[3] = 0xFF; // total_len = 65535, buffer is 20
        // Recompute checksum so we're only testing the total_len check.
        h[10] = 0;
        h[11] = 0;
        let cs = ipv4_header_checksum(&h);
        h[10] = (cs >> 8) as u8;
        h[11] = cs as u8;
        assert!(!ipv4_header_valid(&h));
    }

    #[test]
    fn ipv4_checksum_known_value() {
        // RFC 1071 example: header bytes 0x45 0x00 0x00 0x73
        // 0x00 0x00 0x40 0x00 0x40 0x11 0xb8 0x61 0xc0 0xa8 0x00 0x01
        // 0xc0 0xa8 0x00 0xc7 with stored checksum 0xb861. Computing
        // over the header with the checksum field already filled in
        // gives 0 (the standard "matches" sentinel).
        let h = [
            0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0xb8, 0x61, 0xc0, 0xa8, 0x00, 0x01, 0xc0, 0xa8,
            0x00, 0xc7,
        ];
        assert_eq!(ipv4_header_checksum(&h), 0);
    }

    // --- TCP ParsedOptions ---

    fn parse_opts(buf: &[u8]) -> DuetosTcpParsedOptions {
        let mut p = DuetosTcpParsedOptions::default();
        let ok = duetos_parsers_tcp_parse_options(buf.as_ptr(), buf.len(), &mut p);
        assert!(ok);
        p
    }

    #[test]
    fn tcp_parse_mss() {
        // MSS = 1460 (0x05B4)
        let opts = [TCP_OPT_KIND_MSS, 4, 0x05, 0xB4];
        let p = parse_opts(&opts);
        assert_eq!(p.mss, 1460);
    }

    #[test]
    fn tcp_parse_window_scale_clamped() {
        // Shift count 99 (> 14) must clamp to 14.
        let opts = [TCP_OPT_NOP, TCP_OPT_KIND_WINDOW_SCALE, 3, 99];
        let p = parse_opts(&opts);
        assert!(p.has_wscale);
        assert_eq!(p.wscale, 14);
    }

    #[test]
    fn tcp_parse_sack_permitted() {
        let opts = [TCP_OPT_NOP, TCP_OPT_NOP, TCP_OPT_KIND_SACK_PERMITTED, 2];
        let p = parse_opts(&opts);
        assert!(p.sack_permitted);
    }

    #[test]
    fn tcp_parse_timestamps() {
        // Kind=8, len=10, tsval=0x01020304, tsecr=0x0A0B0C0D.
        let opts = [TCP_OPT_KIND_TIMESTAMP, 10, 0x01, 0x02, 0x03, 0x04, 0x0A, 0x0B, 0x0C, 0x0D];
        let p = parse_opts(&opts);
        assert!(p.has_timestamp);
        assert_eq!(p.tsval, 0x01020304);
        assert_eq!(p.tsecr, 0x0A0B0C0D);
    }

    #[test]
    fn tcp_parse_chained_syn_options() {
        // Common SYN: MSS 1460, NOP NOP SACK-Permitted, NOP WindowScale 7, NOP NOP TSval+TSecr.
        let opts = [
            TCP_OPT_KIND_MSS, 4, 0x05, 0xB4,
            TCP_OPT_NOP, TCP_OPT_NOP, TCP_OPT_KIND_SACK_PERMITTED, 2,
            TCP_OPT_NOP, TCP_OPT_KIND_WINDOW_SCALE, 3, 7,
            TCP_OPT_NOP, TCP_OPT_NOP, TCP_OPT_KIND_TIMESTAMP, 10,
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        ];
        let p = parse_opts(&opts);
        assert_eq!(p.mss, 1460);
        assert!(p.sack_permitted);
        assert!(p.has_wscale);
        assert_eq!(p.wscale, 7);
        assert!(p.has_timestamp);
        assert_eq!(p.tsval, 0x11223344);
        assert_eq!(p.tsecr, 0x55667788);
    }

    #[test]
    fn tcp_parse_end_of_list_stops_walk() {
        // EOL kind=0 ends the walk; later bytes are ignored.
        let opts = [
            TCP_OPT_KIND_MSS, 4, 0x05, 0xB4,
            TCP_OPT_END_OF_LIST,
            // These shouldn't be parsed — after EOL.
            TCP_OPT_KIND_TIMESTAMP, 10, 1, 2, 3, 4, 5, 6, 7, 8,
        ];
        let p = parse_opts(&opts);
        assert_eq!(p.mss, 1460);
        assert!(!p.has_timestamp);
    }

    #[test]
    fn tcp_parse_length_zero_terminates() {
        // Malformed TLV with len=0 must not pin the parser. The
        // walker bails immediately.
        let opts = [TCP_OPT_KIND_MSS, 0, 0x05, 0xB4];
        let p = parse_opts(&opts);
        assert_eq!(p.mss, 0); // never populated; we bailed before the read.
    }

    #[test]
    fn tcp_parse_length_overruns_stream() {
        // Declared len=10 but only 4 bytes follow the kind/len pair.
        let opts = [TCP_OPT_KIND_TIMESTAMP, 10, 1, 2];
        let p = parse_opts(&opts);
        assert!(!p.has_timestamp);
    }

    #[test]
    fn tcp_parse_unknown_kind_skipped() {
        // Kind=99 with len=4 — parser must skip past, not fail.
        let opts = [99u8, 4, 0xDE, 0xAD, TCP_OPT_KIND_MSS, 4, 0x05, 0xB4];
        let p = parse_opts(&opts);
        assert_eq!(p.mss, 1460); // walker advanced past the unknown.
    }

    #[test]
    fn tcp_parse_wrong_size_mss_ignored() {
        // MSS kind with wrong len (5 instead of 4) — ignore the value.
        let opts = [TCP_OPT_KIND_MSS, 5, 0x05, 0xB4, 0x00];
        let p = parse_opts(&opts);
        assert_eq!(p.mss, 0);
    }

    #[test]
    fn tcp_parse_null_out_rejects() {
        let opts = [TCP_OPT_NOP];
        let ok = duetos_parsers_tcp_parse_options(opts.as_ptr(), opts.len(), core::ptr::null_mut());
        assert!(!ok);
    }

    #[test]
    fn tcp_parse_empty_stream_ok() {
        let opts: [u8; 0] = [];
        let mut p = DuetosTcpParsedOptions::default();
        // Empty options is valid (e.g., established segment with no opts).
        let ok = duetos_parsers_tcp_parse_options(opts.as_ptr(), 0, &mut p);
        assert!(ok);
        assert_eq!(p.mss, 0);
    }
}
