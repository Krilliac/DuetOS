// DuetOS net-parsers C FFI — hand-written. Mirrors
// kernel/net/parsers_rust/src/lib.rs.
//
// Bindgen / cbindgen are forbidden — the contract is readable here
// and verified at compile time on the C++ side.
//
// Both functions are pure: no allocation, no I/O, no global state.
// Inputs are borrowed for the duration of the call; the Rust crate
// never retains the buffer or out-pointers past the call.

#pragma once

#include "util/types.h"

namespace duetos::net::parsers
{

extern "C"
{
    /// Locate `opt_code` in a DHCPv4 options stream. On hit, writes
    /// a pointer + length to the value sub-slice into `out_data` /
    /// `out_len` and returns `true`. Returns `false` (and writes
    /// nullptr / 0 to the out-pointers) on miss, truncated stream,
    /// or invalid input.
    ///
    /// `opts` is the byte range AFTER the 4-byte DHCP magic cookie
    /// at offset 240 of a BOOTP frame. RFC 2132 PAD (0) + END (255)
    /// short-tags are handled internally.
    ///
    /// The returned `*out_data` pointer borrows from `opts`; do
    /// not retain it past the lifetime of `opts`.
    bool duetos_parsers_dhcp_find_option(const u8* opts, usize opts_len, u8 opt_code, const u8** out_data, u8* out_len);

    /// Skip past a DNS name starting at `buf[offset]` and return
    /// the offset of the first byte after the name. Handles RFC
    /// 1035 §4.1.4 compression pointers (a 2-byte field jumps to
    /// another offset in the packet, but this function only
    /// advances past the local 2-byte field — it does NOT walk
    /// the pointee).
    ///
    /// On truncation, illegal label length, or pathological
    /// compression-pointer loops the function returns `len` so the
    /// caller can stop parsing without a re-entrancy check of its
    /// own.
    usize duetos_parsers_dns_skip_name(const u8* buf, usize offset, usize len);
}

/// One TCP option as decoded by the walker. `value_off` and
/// `value_len` reference the value sub-slice of the original
/// `opts` buffer (not the absolute TCP segment).
struct DuetosTcpOption
{
    u8 kind;
    u8 _pad;
    u16 value_len;
    u32 value_off;
};

/// Callback shape: returns `true` to continue iteration, `false`
/// to stop. The Rust crate passes `cookie` back unchanged.
using DuetosTcpOptionCallback = bool (*)(void* cookie, DuetosTcpOption opt);

extern "C"
{
    /// Walk a TCP options stream (typically TCP-header bytes
    /// `20..(data_offset × 4)`). For each option the crate calls
    /// `cb(cookie, option)`. Iteration stops on:
    ///   - the EOL (kind=0) short option,
    ///   - a malformed TLV (length < 2 or length > remaining stream),
    ///   - the callback returning `false`,
    ///   - the 64-iteration guard cap.
    ///
    /// Returns the number of options visited. Currently NO C++
    /// caller — the function is here for a future TCP slice that
    /// honours MSS / window-scale / SACK / timestamps. Keeping
    /// the parser ready avoids re-deriving the option-walk every
    /// time a new option needs to be honoured.
    u32 duetos_parsers_tcp_walk_options(const u8* opts, usize opts_len, DuetosTcpOptionCallback cb, void* cookie);
}

/// Aggregated TCP options the v1 receiver recognises. Mirrors the
/// internal `ParsedOptions` struct in
/// kernel/net/tcp_segment.cpp. Use `duetos_parsers_tcp_parse_options`
/// to populate from a raw options byte stream.
struct DuetosTcpParsedOptions
{
    u16 mss;
    u8 wscale;
    bool has_wscale;
    bool sack_permitted;
    bool has_timestamp;
    u8 _pad0[2];
    u32 tsval;
    u32 tsecr;
};

extern "C"
{
    /// Parse the recognised RFC-track options (MSS, WindowScale,
    /// SackPermitted, Timestamps) from a TCP options byte stream.
    /// Returns true iff `out` is non-null. Malformed or empty
    /// streams leave `*out` at its default-zeroed state. Hostile
    /// inputs (length-0 TLV spin, truncated tail) are absorbed;
    /// the walker caps iterations at TCP_OPT_GUARD = 64.
    bool duetos_parsers_tcp_parse_options(const u8* opts, usize opts_len, DuetosTcpParsedOptions* out);

    /// One's-complement Internet checksum (RFC 1071) over `buf`.
    /// 16-bit big-endian words summed with end-around carry, then
    /// the 1's-complement of the low 16 bits is returned. If the
    /// input already contains the on-the-wire checksum field, a
    /// computed value of `0` means the stored checksum matches.
    u16 duetos_parsers_ipv4_header_checksum(const u8* buf, usize len);

    /// Validate an IPv4 header at the start of `buf`. Returns true
    /// iff the version field == 4, IHL is in [5, 15], the header-
    /// byte count and total_length both fit within `len`, and the
    /// stored checksum matches the bytes. Pure compute, no I/O.
    bool duetos_parsers_ipv4_header_valid(const u8* buf, usize len);
}

} // namespace duetos::net::parsers
