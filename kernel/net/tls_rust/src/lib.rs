//! DuetOS TLS 1.2 record + handshake parsers.
//!
//! Pure no_std byte walkers over untrusted server-supplied TLS
//! bytes. Five entry points are exposed to the C++ caller in
//! `kernel/net/tls.cpp`:
//!
//! * `duetos_tls_peek_record` — 5-byte record header
//! * `duetos_tls_peek_handshake` — 4-byte handshake header
//! * `duetos_tls_parse_server_hello` — ServerHello body
//! * `duetos_tls_parse_certificate_leaf` — Certificate-message body
//! * `duetos_tls_parse_server_hello_done` — ServerHelloDone body
//!
//! The parser core uses bounds-checked slice traversal with no
//! unchecked indexing; the `unsafe` blocks are confined to the FFI
//! wall where a `*const u8 + len` is converted to a `&[u8]`. Every
//! length comparison uses `usize` arithmetic so a hostile peer
//! cannot drive a `u32` length close to `u32::MAX` into a sign-
//! flip overflow.
//!
//! Behaviour MUST match the prior C++ implementation in tls.cpp
//! 1:1 — the existing `fuzz_tls` harness pins the contract and
//! the `TlsSelfTest` boot sentinel verifies known-good fixtures.

#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]

use core::{ptr, slice};

// TLS 1.2 protocol constants. Mirrors kVersionTls12 +
// kCipherTlsRsaAes128GcmSha256 + kServerRandomBytes in tls.h.
const VERSION_TLS12: u16 = 0x0303;
const CIPHER_TLS_RSA_AES128_GCM_SHA256: u16 = 0x009C;
const SERVER_RANDOM_BYTES: usize = 32;

/// Record-layer header. C++ caller copies this into its own
/// `RecordView` struct (declared in `tls.h`).
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct DuetosTlsRecordView {
    pub content_type: u8,
    pub version: u16,
    pub length: u16,
    /// Points at the first byte AFTER the 5-byte record header,
    /// inside the caller-supplied buffer. Valid only while the
    /// caller's buffer is live.
    pub payload: *const u8,
}

/// Handshake-layer header.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct DuetosTlsHandshakeView {
    pub kind: u8,
    pub length: u32,
    /// Points at the first byte AFTER the 4-byte handshake header.
    pub body: *const u8,
}

// SAFETY: Convert a (ptr, len) pair from the C ABI into a Rust
// slice. Null ptr or zero len returns None. The caller's
// contract is that `ptr` is readable for `len` bytes; the parsers
// only index through bounds-checked slice operations after this
// point.
fn buf_as_slice<'a>(buf: *const u8, len: u32) -> Option<&'a [u8]> {
    if buf.is_null() {
        return None;
    }
    if len == 0 {
        return Some(&[]);
    }
    // SAFETY: caller guarantees `buf .. buf + len` is readable.
    Some(unsafe { slice::from_raw_parts(buf, len as usize) })
}

fn load_u16_be(buf: &[u8], offset: usize) -> u16 {
    (u16::from(buf[offset]) << 8) | u16::from(buf[offset + 1])
}

fn load_u24_be(buf: &[u8], offset: usize) -> u32 {
    (u32::from(buf[offset]) << 16) | (u32::from(buf[offset + 1]) << 8) | u32::from(buf[offset + 2])
}

/// Parse one TLS record header out of `buf[0..len)`. Returns
/// `true` and populates `*out` on success. Does NOT validate
/// that the payload bytes are present in `buf` — that's the
/// caller's job. Matches `TlsPeekRecord` semantics.
///
/// # Safety
/// `buf` must point to at least `len` readable bytes; `out` must
/// point to a writable `DuetosTlsRecordView`.
#[no_mangle]
pub unsafe extern "C" fn duetos_tls_peek_record(buf: *const u8, len: u32, out: *mut DuetosTlsRecordView) -> bool {
    if out.is_null() {
        return false;
    }
    let Some(s) = buf_as_slice(buf, len) else {
        return false;
    };
    if s.len() < 5 {
        return false;
    }
    let view = DuetosTlsRecordView {
        content_type: s[0],
        version: load_u16_be(s, 1),
        length: load_u16_be(s, 3),
        // SAFETY: `s[5..]` is in bounds (checked above); the
        // raw pointer is valid for the same lifetime as the
        // caller's input.
        payload: unsafe { buf.add(5) },
    };
    // SAFETY: `out` is a valid pointer per the FFI contract.
    unsafe { ptr::write(out, view) };
    true
}

/// Parse one TLS handshake header out of `buf[0..len)`. Matches
/// `TlsPeekHandshake`: returns `false` if the declared body
/// length doesn't fit in the remaining buffer (this differs from
/// `TlsPeekRecord`, which leaves length validation to the caller).
///
/// # Safety
/// `buf` must point to at least `len` readable bytes; `out` must
/// point to a writable `DuetosTlsHandshakeView`.
#[no_mangle]
pub unsafe extern "C" fn duetos_tls_peek_handshake(buf: *const u8, len: u32, out: *mut DuetosTlsHandshakeView) -> bool {
    if out.is_null() {
        return false;
    }
    let Some(s) = buf_as_slice(buf, len) else {
        return false;
    };
    if s.len() < 4 {
        return false;
    }
    let body_len = load_u24_be(s, 1);
    // The body must fit in `len - 4`. Use checked_sub so a
    // bogus s.len() < 4 path (already excluded above) couldn't
    // wrap-around regardless.
    let remaining = match (s.len() as u32).checked_sub(4) {
        Some(v) => v,
        None => return false,
    };
    if body_len > remaining {
        return false;
    }
    let view = DuetosTlsHandshakeView {
        kind: s[0],
        length: body_len,
        // SAFETY: `s[4..]` is in bounds (checked above).
        body: unsafe { buf.add(4) },
    };
    // SAFETY: caller-provided `out`.
    unsafe { ptr::write(out, view) };
    true
}

/// Parse a ServerHello body (RFC 5246 §7.4.1.3). Matches
/// `TlsParseServerHello`:
///
///   ProtocolVersion server_version;       // 2 bytes
///   Random          random;               // 32 bytes
///   SessionID       session_id<0..32>;    // 1-byte length + body
///   CipherSuite     cipher_suite;         // 2 bytes
///   CompressionMethod compression_method; // 1 byte
///   Extension       extensions<0..2^16-1>; // optional, 2-byte len + body
///
/// Rejects any cipher other than TLS_RSA_WITH_AES_128_GCM_SHA256.
/// Rejects any compression other than null.
///
/// # Safety
/// `body` readable for `len` bytes; `server_random` writable for
/// 32 bytes; `out_cipher` writable for a `u16`.
#[no_mangle]
pub unsafe extern "C" fn duetos_tls_parse_server_hello(
    body: *const u8,
    len: u32,
    server_random: *mut u8,
    out_cipher: *mut u16,
) -> bool {
    if server_random.is_null() || out_cipher.is_null() {
        return false;
    }
    let Some(s) = buf_as_slice(body, len) else {
        return false;
    };
    // 2 (version) + 32 (random) + 1 (sid len) + 2 (cipher) + 1 (comp) = 38
    const MIN_LEN: usize = 2 + SERVER_RANDOM_BYTES + 1 + 2 + 1;
    if s.len() < MIN_LEN {
        return false;
    }
    if load_u16_be(s, 0) != VERSION_TLS12 {
        return false;
    }
    // SAFETY: `server_random` is writable for 32 bytes per
    // FFI contract; `s[2..34]` is in bounds (checked above).
    unsafe { ptr::copy_nonoverlapping(s[2..].as_ptr(), server_random, SERVER_RANDOM_BYTES) };
    let mut off: usize = 2 + SERVER_RANDOM_BYTES;
    let sid_len = s[off] as usize;
    off += 1;
    if sid_len > 32 || off + sid_len + 2 + 1 > s.len() {
        return false;
    }
    off += sid_len;
    let cipher = load_u16_be(s, off);
    off += 2;
    if cipher != CIPHER_TLS_RSA_AES128_GCM_SHA256 {
        return false;
    }
    let compression = s[off];
    off += 1;
    if compression != 0 {
        return false;
    }
    // Extensions are optional. If `off` reached `s.len()`, the
    // server omitted them. Otherwise the 2-byte length prefix
    // must be present AND fit.
    if off < s.len() {
        if off + 2 > s.len() {
            return false;
        }
        let ext_len = load_u16_be(s, off) as usize;
        off += 2;
        if off + ext_len > s.len() {
            return false;
        }
    }
    // SAFETY: `out_cipher` is a valid pointer per FFI contract.
    unsafe { ptr::write(out_cipher, cipher) };
    true
}

/// Parse a Certificate message body (RFC 5246 §7.4.2):
///
///   opaque ASN.1Cert<1..2^24-1>;
///   struct { ASN.1Cert certificate_list<0..2^24-1>; } Certificate;
///
/// 3-byte total list length, then a stream of `[3-byte cert
/// length | cert bytes]` entries. Returns a slice over the LEAF
/// certificate (first entry).
///
/// # Safety
/// `body` readable for `len` bytes; `out_leaf_der` writable for a
/// `*const u8`; `out_leaf_len` writable for a `u32`.
#[no_mangle]
pub unsafe extern "C" fn duetos_tls_parse_certificate_leaf(
    body: *const u8,
    len: u32,
    out_leaf_der: *mut *const u8,
    out_leaf_len: *mut u32,
) -> bool {
    if out_leaf_der.is_null() || out_leaf_len.is_null() {
        return false;
    }
    let Some(s) = buf_as_slice(body, len) else {
        return false;
    };
    if s.len() < 6 {
        return false;
    }
    let list_len = load_u24_be(s, 0);
    // list_len + 3 (the 3-byte length prefix) must fit in the
    // body. Use checked_add so an attacker-controlled list_len
    // close to u32::MAX can't wrap into a smaller value that
    // accidentally fits.
    let total_expected = match list_len.checked_add(3) {
        Some(v) => v as usize,
        None => return false,
    };
    if total_expected > s.len() {
        return false;
    }
    if list_len < 3 {
        return false;
    }
    let leaf_len = load_u24_be(s, 3);
    if leaf_len == 0 {
        return false;
    }
    let leaf_plus_prefix = match leaf_len.checked_add(3) {
        Some(v) => v,
        None => return false,
    };
    if leaf_plus_prefix > list_len {
        return false;
    }
    // SAFETY: `body[6..]` is in bounds (checked above) and the
    // pointer is valid for the same lifetime as the caller's
    // input. The out-pointers are caller-provided.
    unsafe {
        ptr::write(out_leaf_der, body.add(6));
        ptr::write(out_leaf_len, leaf_len);
    }
    true
}

/// Confirm a ServerHelloDone message body is well-formed.
/// Body must be exactly 0 bytes.
///
/// # Safety
/// `_body` is unused; `len` is the count. No memory is read.
#[no_mangle]
pub unsafe extern "C" fn duetos_tls_parse_server_hello_done(_body: *const u8, len: u32) -> bool {
    len == 0
}

// ---------------------------------------------------------------------------
// Host-only unit tests. Run via tools/dev/cargo-host-test.sh, which
// compiles this lib.rs with `rustc --test` against the host's libcore
// + libstd (the kernel build uses x86_64-unknown-none which can't host
// test binaries). Each test exercises one parser entry point on a
// hand-built byte stream that matches the wire format, then checks
// both the happy path and a handful of malformed inputs.
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    extern crate alloc;
    use super::*;
    use alloc::vec;
    use alloc::vec::Vec;
    use core::ptr;

    fn make_record_view() -> DuetosTlsRecordView {
        DuetosTlsRecordView::default()
    }

    fn make_handshake_view() -> DuetosTlsHandshakeView {
        DuetosTlsHandshakeView::default()
    }

    #[test]
    fn peek_record_ok() {
        // type=0x17 (Application Data), version=0x0303 (TLS 1.2),
        // length=0x0003, then 3 bytes payload.
        let buf = [0x17u8, 0x03, 0x03, 0x00, 0x03, b'h', b'i', b'!'];
        let mut v = make_record_view();
        let ok = unsafe { duetos_tls_peek_record(buf.as_ptr(), buf.len() as u32, &mut v) };
        assert!(ok);
        assert_eq!(v.content_type, 0x17);
        assert_eq!(v.version, 0x0303);
        assert_eq!(v.length, 3);
        // payload should point at byte 5 of the input.
        assert_eq!(v.payload, unsafe { buf.as_ptr().add(5) });
    }

    #[test]
    fn peek_record_short_buffer_rejects() {
        let buf = [0x17u8, 0x03, 0x03, 0x00]; // 4 bytes — header is 5.
        let mut v = make_record_view();
        assert!(!unsafe { duetos_tls_peek_record(buf.as_ptr(), buf.len() as u32, &mut v) });
    }

    #[test]
    fn peek_record_null_out_rejects() {
        let buf = [0x17u8, 0x03, 0x03, 0x00, 0x00];
        assert!(!unsafe { duetos_tls_peek_record(buf.as_ptr(), buf.len() as u32, ptr::null_mut()) });
    }

    #[test]
    fn peek_record_null_buf_rejects() {
        let mut v = make_record_view();
        assert!(!unsafe { duetos_tls_peek_record(ptr::null(), 5, &mut v) });
    }

    #[test]
    fn peek_handshake_ok() {
        // type=0x02 (ServerHello), length=0x000004, then 4 bytes body.
        let buf = [0x02u8, 0x00, 0x00, 0x04, 0xaa, 0xbb, 0xcc, 0xdd];
        let mut v = make_handshake_view();
        let ok = unsafe { duetos_tls_peek_handshake(buf.as_ptr(), buf.len() as u32, &mut v) };
        assert!(ok);
        assert_eq!(v.kind, 0x02);
        assert_eq!(v.length, 4);
        assert_eq!(v.body, unsafe { buf.as_ptr().add(4) });
    }

    #[test]
    fn peek_handshake_body_overflow_rejects() {
        // Declares 8-byte body but only 4 bytes follow header.
        let buf = [0x02u8, 0x00, 0x00, 0x08, 0xaa, 0xbb, 0xcc, 0xdd];
        let mut v = make_handshake_view();
        assert!(!unsafe { duetos_tls_peek_handshake(buf.as_ptr(), buf.len() as u32, &mut v) });
    }

    fn build_server_hello() -> Vec<u8> {
        let mut b = vec![0u8; 0];
        b.extend_from_slice(&[0x03, 0x03]); // version TLS 1.2
        b.extend((0..32u8).collect::<Vec<_>>()); // server_random
        b.push(0x00); // session_id length = 0
        b.extend_from_slice(&[0x00, 0x9C]); // cipher = TLS_RSA_WITH_AES_128_GCM_SHA256
        b.push(0x00); // compression = null
        b
    }

    #[test]
    fn parse_server_hello_ok_no_extensions() {
        let body = build_server_hello();
        let mut server_random = [0u8; 32];
        let mut cipher = 0u16;
        let ok = unsafe {
            duetos_tls_parse_server_hello(
                body.as_ptr(),
                body.len() as u32,
                server_random.as_mut_ptr(),
                &mut cipher,
            )
        };
        assert!(ok);
        assert_eq!(cipher, 0x009C);
        // server_random should be 0..31 (what we put in the body).
        for (i, v) in server_random.iter().enumerate() {
            assert_eq!(*v as usize, i);
        }
    }

    #[test]
    fn parse_server_hello_with_extensions_ok() {
        let mut body = build_server_hello();
        // Add a 0-length extensions block.
        body.extend_from_slice(&[0x00, 0x00]);
        let mut server_random = [0u8; 32];
        let mut cipher = 0u16;
        let ok = unsafe {
            duetos_tls_parse_server_hello(
                body.as_ptr(),
                body.len() as u32,
                server_random.as_mut_ptr(),
                &mut cipher,
            )
        };
        assert!(ok);
    }

    #[test]
    fn parse_server_hello_bad_cipher_rejects() {
        let mut body = build_server_hello();
        // Cipher lives at offset 35, 36 — flip to TLS_NULL_WITH_NULL_NULL.
        body[35] = 0x00;
        body[36] = 0x00;
        let mut server_random = [0u8; 32];
        let mut cipher = 0u16;
        let ok = unsafe {
            duetos_tls_parse_server_hello(
                body.as_ptr(),
                body.len() as u32,
                server_random.as_mut_ptr(),
                &mut cipher,
            )
        };
        assert!(!ok);
    }

    #[test]
    fn parse_server_hello_bad_compression_rejects() {
        let mut body = build_server_hello();
        body[37] = 0x01; // non-null compression
        let mut server_random = [0u8; 32];
        let mut cipher = 0u16;
        let ok = unsafe {
            duetos_tls_parse_server_hello(
                body.as_ptr(),
                body.len() as u32,
                server_random.as_mut_ptr(),
                &mut cipher,
            )
        };
        assert!(!ok);
    }

    #[test]
    fn parse_server_hello_bad_version_rejects() {
        let mut body = build_server_hello();
        body[0] = 0x03;
        body[1] = 0x02; // TLS 1.1
        let mut server_random = [0u8; 32];
        let mut cipher = 0u16;
        let ok = unsafe {
            duetos_tls_parse_server_hello(
                body.as_ptr(),
                body.len() as u32,
                server_random.as_mut_ptr(),
                &mut cipher,
            )
        };
        assert!(!ok);
    }

    #[test]
    fn parse_certificate_leaf_ok() {
        // Build: 3-byte total list length + 3-byte cert length + cert.
        let cert = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x42];
        let mut body = vec![0u8; 0];
        // list_len = 3 + cert.len()
        let list_len = 3 + cert.len() as u32;
        body.push((list_len >> 16) as u8);
        body.push((list_len >> 8) as u8);
        body.push(list_len as u8);
        // per-cert length
        let cl = cert.len() as u32;
        body.push((cl >> 16) as u8);
        body.push((cl >> 8) as u8);
        body.push(cl as u8);
        body.extend_from_slice(&cert);

        let mut leaf_ptr: *const u8 = ptr::null();
        let mut leaf_len: u32 = 0;
        let ok = unsafe {
            duetos_tls_parse_certificate_leaf(body.as_ptr(), body.len() as u32, &mut leaf_ptr, &mut leaf_len)
        };
        assert!(ok);
        assert_eq!(leaf_len, cert.len() as u32);
        assert_eq!(leaf_ptr, unsafe { body.as_ptr().add(6) });
    }

    #[test]
    fn parse_certificate_leaf_overflow_rejects() {
        // list_len claims a value larger than the actual body.
        let body = [0xFFu8, 0xFF, 0xFF, 0x00, 0x00, 0x05];
        let mut leaf_ptr: *const u8 = ptr::null();
        let mut leaf_len: u32 = 0;
        let ok = unsafe {
            duetos_tls_parse_certificate_leaf(body.as_ptr(), body.len() as u32, &mut leaf_ptr, &mut leaf_len)
        };
        assert!(!ok);
    }

    #[test]
    fn parse_certificate_leaf_zero_leaf_len_rejects() {
        // list_len = 3 (just the per-cert length, no cert bytes);
        // per-cert length = 0.
        let body = [0x00u8, 0x00, 0x03, 0x00, 0x00, 0x00];
        let mut leaf_ptr: *const u8 = ptr::null();
        let mut leaf_len: u32 = 0;
        let ok = unsafe {
            duetos_tls_parse_certificate_leaf(body.as_ptr(), body.len() as u32, &mut leaf_ptr, &mut leaf_len)
        };
        assert!(!ok);
    }

    #[test]
    fn parse_server_hello_done_zero_ok() {
        let ok = unsafe { duetos_tls_parse_server_hello_done(ptr::null(), 0) };
        assert!(ok);
    }

    #[test]
    fn parse_server_hello_done_nonzero_rejects() {
        let buf = [0x00u8];
        let ok = unsafe { duetos_tls_parse_server_hello_done(buf.as_ptr(), 1) };
        assert!(!ok);
    }
}
