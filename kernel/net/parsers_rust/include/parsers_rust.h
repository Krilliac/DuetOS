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

} // namespace duetos::net::parsers
