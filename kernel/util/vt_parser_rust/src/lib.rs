//! DuetOS VT/ANSI escape parser — DEC ANSI state machine over an
//! untrusted PTY byte stream.
//!
//! Port of the C++ parser in kernel/util/vt_parser.cpp. The state
//! machine, UTF-8 decoder, CSI parameter accumulator, and OSC
//! string buffer all run in bounds-checked safe Rust; the FFI wall
//! is the only `unsafe` block (the raw-pointer conversions in the
//! three exported entry points + the callback invocations, which
//! are by-definition unsafe because the function pointer originates
//! in C).
//!
//! Behaviour MUST match the prior C++ implementation 1:1 — the
//! existing `fuzz_vt` harness pins the contract via differential
//! coverage, and the C++ `VtParserSelfTest` boot sentinel
//! exercises this crate through the same FFI.
//!
//! Threat model: a hostile user process feeds attacker-controlled
//! bytes through a PTY into the terminal widget. Misshapen escape
//! sequences (over-long OSC, partial UTF-8, lone continuation
//! bytes, lengths longer than the buffer, parameter overflow) must
//! be absorbed without a kernel read/write primitive.

#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]

use core::{ptr, slice};

// ---------------------------------------------------------------------------
// Protocol constants (mirror kernel/util/vt_parser.h).
// ---------------------------------------------------------------------------

const MAX_PARAMS: usize = 16;
const MAX_OSC_LEN: usize = 256;

const C_BEL: u8 = 0x07;
const C_BS: u8 = 0x08;
const C_HT: u8 = 0x09;
const C_LF: u8 = 0x0A;
const C_VT: u8 = 0x0B;
const C_FF: u8 = 0x0C;
const C_CR: u8 = 0x0D;
const C_ESC: u8 = 0x1B;
const C_DEL: u8 = 0x7F;

const UNICODE_REPLACEMENT: u32 = 0xFFFD;

// ---------------------------------------------------------------------------
// State enum — repr(u8) to match the C++ State enum layout exactly.
// ---------------------------------------------------------------------------

const STATE_GROUND: u8 = 0;
const STATE_ESCAPE: u8 = 1;
const STATE_CSI_ENTRY: u8 = 2;
const STATE_CSI_PARAM: u8 = 3;
const STATE_OSC_STRING: u8 = 4;
const STATE_OSC_ESCAPE: u8 = 5;

// ---------------------------------------------------------------------------
// FFI structs — bytes-for-bytes match kernel/util/vt_parser.h Parser
// + Callbacks. The C++ side allocates the struct; Rust operates on
// `&mut DuetosVtParser`.
// ---------------------------------------------------------------------------

#[repr(C)]
#[derive(Clone, Copy)]
pub struct DuetosVtCallbacks {
    pub cookie: *mut core::ffi::c_void,
    pub print: Option<extern "C" fn(*mut core::ffi::c_void, u32)>,
    pub execute: Option<extern "C" fn(*mut core::ffi::c_void, u8)>,
    pub csi: Option<extern "C" fn(*mut core::ffi::c_void, i8, i8, *const u16, u32)>,
    pub osc: Option<extern "C" fn(*mut core::ffi::c_void, u32, *const i8, u32)>,
}

impl Default for DuetosVtCallbacks {
    fn default() -> Self {
        Self {
            cookie: ptr::null_mut(),
            print: None,
            execute: None,
            csi: None,
            osc: None,
        }
    }
}

#[repr(C)]
pub struct DuetosVtParser {
    pub state: u8,
    pub utf8_bytes_remaining: u8,
    pub utf8_seq_len: u8,
    pub _pad0: u8,

    pub utf8_accum_cp: u32,
    pub utf8_buf: [u8; 4],

    pub params: [u16; MAX_PARAMS],
    pub nparams: u32,
    pub current_param: u32,
    pub current_param_set: bool,
    pub overflow_params: bool,
    pub private_marker: i8,
    pub _pad1: u8,

    pub osc_buf: [i8; MAX_OSC_LEN],
    pub osc_len: u32,
    pub osc_truncated: bool,
    pub _pad2: [u8; 3],

    pub cb: DuetosVtCallbacks,
}

// ---------------------------------------------------------------------------
// Parser logic. Every function takes `&mut DuetosVtParser` and
// operates on bounds-checked slices internally.
// ---------------------------------------------------------------------------

fn is_executable_c0(b: u8) -> bool {
    matches!(b, C_BEL | C_BS | C_HT | C_LF | C_VT | C_FF | C_CR)
}

fn is_csi_final(b: u8) -> bool {
    (0x40..=0x7E).contains(&b)
}

fn is_csi_private_marker(b: u8) -> bool {
    b == b'?' || b == b'>' || b == b'=' || b == b'<'
}

fn reset_csi(p: &mut DuetosVtParser) {
    for slot in p.params.iter_mut() {
        *slot = 0;
    }
    p.nparams = 0;
    p.current_param = 0;
    p.current_param_set = false;
    p.overflow_params = false;
    p.private_marker = 0;
}

fn reset_osc(p: &mut DuetosVtParser) {
    p.osc_len = 0;
    p.osc_truncated = false;
}

fn reset_utf8(p: &mut DuetosVtParser) {
    p.utf8_bytes_remaining = 0;
    p.utf8_seq_len = 0;
    p.utf8_accum_cp = 0;
    p.utf8_buf = [0; 4];
}

fn emit_print(p: &DuetosVtParser, cp: u32) {
    if let Some(f) = p.cb.print {
        // `extern "C" fn` is safe to call from Rust by definition;
        // the safety of what the C side does on the other side is
        // the C side's contract. Cookie is opaque to the parser.
        f(p.cb.cookie, cp);
    }
}

fn emit_execute(p: &DuetosVtParser, ctrl: u8) {
    if let Some(f) = p.cb.execute {
        f(p.cb.cookie, ctrl);
    }
}

fn emit_replacement_and_reset(p: &mut DuetosVtParser) {
    emit_print(p, UNICODE_REPLACEMENT);
    reset_utf8(p);
}

fn flush_pending_utf8(p: &mut DuetosVtParser) {
    if p.utf8_bytes_remaining != 0 {
        emit_replacement_and_reset(p);
    }
}

// Standalone UTF-8 decode for a *complete* sequence the state
// machine already validated as well-formed at the bit-pattern
// level. Returns the codepoint on success, U+FFFD on overlong /
// surrogate / out-of-range. Mirrors the project's util/unicode
// Utf8Decode rules.
fn utf8_decode_complete(buf: &[u8]) -> u32 {
    match buf.len() {
        1 => u32::from(buf[0]),
        2 => {
            let cp = (u32::from(buf[0] & 0x1F) << 6) | u32::from(buf[1] & 0x3F);
            if cp < 0x80 {
                return UNICODE_REPLACEMENT;
            } // overlong
            cp
        }
        3 => {
            let cp = (u32::from(buf[0] & 0x0F) << 12) | (u32::from(buf[1] & 0x3F) << 6) | u32::from(buf[2] & 0x3F);
            if cp < 0x800 {
                return UNICODE_REPLACEMENT;
            } // overlong
            if (0xD800..=0xDFFF).contains(&cp) {
                return UNICODE_REPLACEMENT;
            } // surrogate
            cp
        }
        4 => {
            let cp = (u32::from(buf[0] & 0x07) << 18)
                | (u32::from(buf[1] & 0x3F) << 12)
                | (u32::from(buf[2] & 0x3F) << 6)
                | u32::from(buf[3] & 0x3F);
            if cp < 0x10000 {
                return UNICODE_REPLACEMENT;
            } // overlong
            if cp > 0x10FFFF {
                return UNICODE_REPLACEMENT;
            } // out of range
            cp
        }
        _ => UNICODE_REPLACEMENT,
    }
}

fn feed_utf8_byte(p: &mut DuetosVtParser, b: u8) -> bool {
    // 7-bit ASCII: abort any partial sequence in flight, then emit.
    if b < 0x80 {
        flush_pending_utf8(p);
        emit_print(p, u32::from(b));
        return true;
    }

    // Always-invalid lead bytes: 0xC0..0xC1 (overlong 2-byte),
    // 0xF5..0xFF (codepoints > U+10FFFF).
    if b == 0xC0 || b == 0xC1 || b >= 0xF5 {
        if p.utf8_bytes_remaining != 0 {
            emit_replacement_and_reset(p);
        }
        emit_print(p, UNICODE_REPLACEMENT);
        return true;
    }

    if p.utf8_bytes_remaining == 0 {
        // New lead byte.
        if (b & 0xE0) == 0xC0 {
            p.utf8_seq_len = 2;
            p.utf8_bytes_remaining = 1;
        } else if (b & 0xF0) == 0xE0 {
            p.utf8_seq_len = 3;
            p.utf8_bytes_remaining = 2;
        } else if (b & 0xF8) == 0xF0 {
            p.utf8_seq_len = 4;
            p.utf8_bytes_remaining = 3;
        } else {
            // Lone continuation byte or other invalid form.
            emit_print(p, UNICODE_REPLACEMENT);
            return true;
        }
        p.utf8_buf[0] = b;
        return true;
    }

    // Continuation byte expected.
    if (b & 0xC0) != 0x80 {
        // Not a continuation; abandon partial sequence and
        // re-process this byte as a fresh lead.
        emit_replacement_and_reset(p);
        return feed_utf8_byte(p, b);
    }

    let idx = (p.utf8_seq_len - p.utf8_bytes_remaining) as usize;
    if idx < 4 {
        p.utf8_buf[idx] = b;
    }
    p.utf8_bytes_remaining -= 1;

    if p.utf8_bytes_remaining == 0 {
        let len = p.utf8_seq_len as usize;
        let cp = if len <= 4 {
            utf8_decode_complete(&p.utf8_buf[..len])
        } else {
            UNICODE_REPLACEMENT
        };
        emit_print(p, cp);
        reset_utf8(p);
    }
    true
}

fn param_add_digit(p: &mut DuetosVtParser, digit: u8) {
    if p.overflow_params {
        return;
    }
    if !p.current_param_set {
        p.current_param_set = true;
        p.current_param = 0;
    }
    let next = u64::from(p.current_param) * 10 + u64::from(digit);
    p.current_param = if next > 0xFFFF { 0xFFFF } else { next as u32 };
}

fn param_commit(p: &mut DuetosVtParser) {
    if p.nparams as usize >= MAX_PARAMS {
        p.overflow_params = true;
        return;
    }
    let idx = p.nparams as usize;
    p.params[idx] = p.current_param as u16;
    p.nparams += 1;
    p.current_param = 0;
    p.current_param_set = false;
}

fn dispatch_csi(p: &mut DuetosVtParser, final_byte: i8) {
    if p.current_param_set || (p.nparams > 0 && !p.current_param_set) {
        param_commit(p);
    }
    if let Some(f) = p.cb.csi {
        // params slice is contained inside `p.params` and valid
        // for `nparams` entries; calling extern "C" fn is safe.
        f(p.cb.cookie, final_byte, p.private_marker, p.params.as_ptr(), p.nparams);
    }
    reset_csi(p);
}

fn dispatch_osc(p: &mut DuetosVtParser) {
    let osc_cb = match p.cb.osc {
        Some(f) => f,
        None => {
            reset_osc(p);
            return;
        }
    };
    if p.osc_len == 0 {
        reset_osc(p);
        return;
    }
    // Parse leading numeric command up to the first ';'.
    let mut cmd: u32 = 0;
    let mut cmd_set = false;
    let mut i: u32 = 0;
    while i < p.osc_len {
        let c = p.osc_buf[i as usize] as u8;
        if c.is_ascii_digit() {
            cmd = cmd * 10 + u32::from(c - b'0');
            cmd_set = true;
            i += 1;
        } else {
            break;
        }
    }
    // Skip ';' if present.
    if i < p.osc_len && p.osc_buf[i as usize] as u8 == b';' {
        i += 1;
    }
    if !cmd_set {
        cmd = 0;
    }
    // The str slice is contained inside p.osc_buf and valid for
    // (osc_len - i) bytes; calling extern "C" fn is safe.
    let start = i as usize;
    let len_remaining = p.osc_len - i;
    osc_cb(p.cb.cookie, cmd, p.osc_buf[start..].as_ptr(), len_remaining);
    reset_osc(p);
}

fn osc_append(p: &mut DuetosVtParser, b: u8) {
    if (p.osc_len as usize) < MAX_OSC_LEN {
        p.osc_buf[p.osc_len as usize] = b as i8;
        p.osc_len += 1;
    } else {
        p.osc_truncated = true;
    }
}

fn feed_one_byte(p: &mut DuetosVtParser, b: u8) {
    match p.state {
        STATE_GROUND => {
            if b == C_ESC {
                flush_pending_utf8(p);
                reset_csi(p);
                reset_osc(p);
                p.state = STATE_ESCAPE;
                return;
            }
            if b == C_DEL {
                return;
            }
            if b < 0x20 {
                flush_pending_utf8(p);
                if is_executable_c0(b) {
                    emit_execute(p, b);
                }
                return;
            }
            let _ = feed_utf8_byte(p, b);
        }
        STATE_ESCAPE => {
            if b == C_ESC {
                // Double-ESC: stay in Escape.
                return;
            }
            if b == b'[' {
                reset_csi(p);
                p.state = STATE_CSI_ENTRY;
                return;
            }
            if b == b']' {
                reset_osc(p);
                p.state = STATE_OSC_STRING;
                return;
            }
            // Unrecognised ESC <byte> — drop silently.
            p.state = STATE_GROUND;
        }
        STATE_CSI_ENTRY => {
            if b == C_ESC {
                p.state = STATE_ESCAPE;
                return;
            }
            if is_csi_private_marker(b) {
                p.private_marker = b as i8;
                p.state = STATE_CSI_PARAM;
                return;
            }
            // Fall through to CSI_PARAM with this same byte.
            p.state = STATE_CSI_PARAM;
            feed_csi_param(p, b);
        }
        STATE_CSI_PARAM => {
            feed_csi_param(p, b);
        }
        STATE_OSC_STRING => {
            if b == C_BEL {
                dispatch_osc(p);
                p.state = STATE_GROUND;
                return;
            }
            if b == C_ESC {
                p.state = STATE_OSC_ESCAPE;
                return;
            }
            osc_append(p, b);
        }
        STATE_OSC_ESCAPE => {
            if b == b'\\' {
                dispatch_osc(p);
                p.state = STATE_GROUND;
                return;
            }
            // Bare ESC inside OSC — abort, treat as fresh ESC.
            reset_osc(p);
            p.state = STATE_ESCAPE;
            feed_one_byte(p, b);
        }
        _ => {
            // Unknown state — recover by jumping back to Ground.
            p.state = STATE_GROUND;
        }
    }
}

fn feed_csi_param(p: &mut DuetosVtParser, b: u8) {
    if b == C_ESC {
        p.state = STATE_ESCAPE;
        return;
    }
    if b.is_ascii_digit() {
        param_add_digit(p, b - b'0');
        return;
    }
    if b == b';' {
        param_commit(p);
        return;
    }
    if is_csi_final(b) {
        dispatch_csi(p, b as i8);
        p.state = STATE_GROUND;
    }
    // Anything else dropped silently (intermediates, lingering controls).
}

// ---------------------------------------------------------------------------
// FFI entry points.
// ---------------------------------------------------------------------------

/// Initialize the parser, installing `cb` and resetting every
/// state field.
///
/// # Safety
/// `p` must point to a writable `DuetosVtParser`; `cb` may be null
/// to install all-null callbacks (which silently drop every event).
#[no_mangle]
pub unsafe extern "C" fn duetos_vt_parser_init(p: *mut DuetosVtParser, cb: *const DuetosVtCallbacks) {
    if p.is_null() {
        return;
    }
    // SAFETY: caller's contract is that `p` is a writable
    // DuetosVtParser. We initialize through a &mut.
    let parser = unsafe { &mut *p };
    parser.cb = if cb.is_null() {
        DuetosVtCallbacks::default()
    } else {
        // SAFETY: caller's contract is that `cb` is readable.
        unsafe { *cb }
    };
    duetos_vt_parser_reset_inner(parser);
}

/// Reset state without re-installing callbacks.
///
/// # Safety
/// `p` must point to a writable `DuetosVtParser`.
#[no_mangle]
pub unsafe extern "C" fn duetos_vt_parser_reset(p: *mut DuetosVtParser) {
    if p.is_null() {
        return;
    }
    // SAFETY: caller's contract is that `p` is a writable
    // DuetosVtParser.
    duetos_vt_parser_reset_inner(unsafe { &mut *p });
}

fn duetos_vt_parser_reset_inner(p: &mut DuetosVtParser) {
    p.state = STATE_GROUND;
    reset_utf8(p);
    reset_csi(p);
    reset_osc(p);
}

/// Feed `len` bytes to the parser. Drives callbacks synchronously.
/// Returns the number of bytes consumed (always equal to `len`).
///
/// # Safety
/// `p` must point to a writable `DuetosVtParser`; `bytes` must be
/// readable for `len` bytes.
#[no_mangle]
pub unsafe extern "C" fn duetos_vt_parser_feed(p: *mut DuetosVtParser, bytes: *const u8, len: u32) -> u32 {
    if p.is_null() {
        return 0;
    }
    // SAFETY: caller's contracts as documented above.
    let parser = unsafe { &mut *p };
    if bytes.is_null() || len == 0 {
        return 0;
    }
    // SAFETY: caller's contract that `bytes` is readable for `len` bytes.
    let s = unsafe { slice::from_raw_parts(bytes, len as usize) };
    for &b in s {
        feed_one_byte(parser, b);
    }
    len
}

// ---------------------------------------------------------------------------
// Host-only unit tests.
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    extern crate alloc;
    use super::*;
    use alloc::vec;
    use alloc::vec::Vec;
    use core::cell::RefCell;

    struct Capture {
        prints: RefCell<Vec<u32>>,
        executes: RefCell<Vec<u8>>,
        csi_calls: RefCell<Vec<(i8, i8, Vec<u16>)>>,
        osc_calls: RefCell<Vec<(u32, Vec<u8>)>>,
    }

    impl Capture {
        fn new() -> Self {
            Self {
                prints: RefCell::new(Vec::new()),
                executes: RefCell::new(Vec::new()),
                csi_calls: RefCell::new(Vec::new()),
                osc_calls: RefCell::new(Vec::new()),
            }
        }
    }

    extern "C" fn cap_print(cookie: *mut core::ffi::c_void, cp: u32) {
        // SAFETY: tests pass a &Capture as cookie; lifetime out-lives the call.
        let c: &Capture = unsafe { &*(cookie as *const Capture) };
        c.prints.borrow_mut().push(cp);
    }

    extern "C" fn cap_execute(cookie: *mut core::ffi::c_void, ctrl: u8) {
        let c: &Capture = unsafe { &*(cookie as *const Capture) };
        c.executes.borrow_mut().push(ctrl);
    }

    extern "C" fn cap_csi(
        cookie: *mut core::ffi::c_void,
        final_byte: i8,
        private_marker: i8,
        params: *const u16,
        nparams: u32,
    ) {
        let c: &Capture = unsafe { &*(cookie as *const Capture) };
        let p = if params.is_null() || nparams == 0 {
            Vec::new()
        } else {
            // SAFETY: parser invariant guarantees params is valid for nparams.
            let s = unsafe { slice::from_raw_parts(params, nparams as usize) };
            s.to_vec()
        };
        c.csi_calls.borrow_mut().push((final_byte, private_marker, p));
    }

    extern "C" fn cap_osc(cookie: *mut core::ffi::c_void, cmd: u32, str_ptr: *const i8, str_len: u32) {
        let c: &Capture = unsafe { &*(cookie as *const Capture) };
        let s = if str_ptr.is_null() || str_len == 0 {
            Vec::new()
        } else {
            // SAFETY: parser invariant guarantees str_ptr is valid for str_len.
            let bytes = unsafe { slice::from_raw_parts(str_ptr as *const u8, str_len as usize) };
            bytes.to_vec()
        };
        c.osc_calls.borrow_mut().push((cmd, s));
    }

    fn new_parser(cap: &Capture) -> DuetosVtParser {
        // Build a parser via the FFI. Caller owns the storage.
        let mut p = unsafe { core::mem::zeroed::<DuetosVtParser>() };
        let cb = DuetosVtCallbacks {
            cookie: cap as *const _ as *mut core::ffi::c_void,
            print: Some(cap_print),
            execute: Some(cap_execute),
            csi: Some(cap_csi),
            osc: Some(cap_osc),
        };
        unsafe { duetos_vt_parser_init(&mut p, &cb) };
        p
    }

    fn feed(p: &mut DuetosVtParser, s: &[u8]) {
        unsafe { duetos_vt_parser_feed(p, s.as_ptr(), s.len() as u32) };
    }

    #[test]
    fn print_ascii() {
        let cap = Capture::new();
        let mut p = new_parser(&cap);
        feed(&mut p, b"hi");
        assert_eq!(*cap.prints.borrow(), vec![b'h' as u32, b'i' as u32]);
    }

    #[test]
    fn execute_c0() {
        let cap = Capture::new();
        let mut p = new_parser(&cap);
        feed(&mut p, b"\x07\x08\x0a");
        assert_eq!(*cap.executes.borrow(), vec![0x07, 0x08, 0x0a]);
    }

    #[test]
    fn csi_simple() {
        let cap = Capture::new();
        let mut p = new_parser(&cap);
        feed(&mut p, b"\x1b[3;5H");
        let calls = cap.csi_calls.borrow();
        assert_eq!(calls.len(), 1);
        let (final_b, priv_m, ref params) = calls[0];
        assert_eq!(final_b as u8, b'H');
        assert_eq!(priv_m, 0);
        assert_eq!(params, &vec![3u16, 5u16]);
    }

    #[test]
    fn csi_private_marker() {
        let cap = Capture::new();
        let mut p = new_parser(&cap);
        feed(&mut p, b"\x1b[?25h");
        let calls = cap.csi_calls.borrow();
        assert_eq!(calls.len(), 1);
        let (final_b, priv_m, ref params) = calls[0];
        assert_eq!(final_b as u8, b'h');
        assert_eq!(priv_m as u8, b'?');
        assert_eq!(params, &vec![25u16]);
    }

    #[test]
    fn csi_no_params() {
        let cap = Capture::new();
        let mut p = new_parser(&cap);
        feed(&mut p, b"\x1b[H");
        let calls = cap.csi_calls.borrow();
        assert_eq!(calls.len(), 1);
        let (final_b, _, ref params) = calls[0];
        assert_eq!(final_b as u8, b'H');
        assert_eq!(params.len(), 0);
    }

    #[test]
    fn csi_param_overflow_clamped() {
        let cap = Capture::new();
        let mut p = new_parser(&cap);
        // 999999 should clamp to u16::MAX
        feed(&mut p, b"\x1b[999999m");
        let calls = cap.csi_calls.borrow();
        assert_eq!(calls.len(), 1);
        let (_, _, ref params) = calls[0];
        assert_eq!(params, &vec![0xFFFFu16]);
    }

    #[test]
    fn osc_set_title() {
        let cap = Capture::new();
        let mut p = new_parser(&cap);
        feed(&mut p, b"\x1b]0;hello\x07");
        let calls = cap.osc_calls.borrow();
        assert_eq!(calls.len(), 1);
        let (cmd, ref s) = calls[0];
        assert_eq!(cmd, 0);
        assert_eq!(s, b"hello");
    }

    #[test]
    fn osc_string_terminator() {
        let cap = Capture::new();
        let mut p = new_parser(&cap);
        // ST = ESC \\
        feed(&mut p, b"\x1b]2;world\x1b\\");
        let calls = cap.osc_calls.borrow();
        assert_eq!(calls.len(), 1);
        let (cmd, ref s) = calls[0];
        assert_eq!(cmd, 2);
        assert_eq!(s, b"world");
    }

    #[test]
    fn osc_truncation_on_oversize() {
        let cap = Capture::new();
        let mut p = new_parser(&cap);
        // Send an OSC longer than MAX_OSC_LEN (256).
        let mut buf = Vec::new();
        buf.extend_from_slice(b"\x1b]52;");
        for _ in 0..400 {
            buf.push(b'A');
        }
        buf.push(C_BEL);
        feed(&mut p, &buf);
        let calls = cap.osc_calls.borrow();
        assert_eq!(calls.len(), 1);
        // The payload starts with "52;AAA..."; after stripping "52;",
        // we should see osc_len-3 bytes of 'A' (truncated at MAX_OSC_LEN).
        let (_, ref s) = calls[0];
        // s.len() <= 253 (256 minus "52;")
        assert!(s.len() <= MAX_OSC_LEN - 3);
        assert!(s.iter().all(|&b| b == b'A'));
    }

    #[test]
    fn utf8_two_byte_sequence() {
        let cap = Capture::new();
        let mut p = new_parser(&cap);
        // U+00E9 (é) = 0xC3 0xA9
        feed(&mut p, &[0xC3, 0xA9]);
        assert_eq!(*cap.prints.borrow(), vec![0xE9u32]);
    }

    #[test]
    fn utf8_three_byte_sequence() {
        let cap = Capture::new();
        let mut p = new_parser(&cap);
        // U+20AC (€) = 0xE2 0x82 0xAC
        feed(&mut p, &[0xE2, 0x82, 0xAC]);
        assert_eq!(*cap.prints.borrow(), vec![0x20ACu32]);
    }

    #[test]
    fn utf8_overlong_rejects() {
        let cap = Capture::new();
        let mut p = new_parser(&cap);
        // Overlong encoding of '/' as 2-byte: 0xC0 0xAF — but 0xC0
        // is in the always-invalid lead range, so the parser
        // emits one REPLACEMENT (no partial sequence in flight to
        // abandon) and consumes the byte. The 0xAF is then a lone
        // continuation, which the parser ALSO emits as REPLACEMENT.
        feed(&mut p, &[0xC0, 0xAF]);
        assert_eq!(*cap.prints.borrow(), vec![UNICODE_REPLACEMENT, UNICODE_REPLACEMENT]);
    }

    #[test]
    fn utf8_partial_sequence_aborted_by_ascii() {
        let cap = Capture::new();
        let mut p = new_parser(&cap);
        // 0xE2 starts a 3-byte sequence, but 'A' interrupts.
        feed(&mut p, &[0xE2, b'A']);
        // Expect REPLACEMENT then 'A'.
        assert_eq!(*cap.prints.borrow(), vec![UNICODE_REPLACEMENT, b'A' as u32]);
    }

    #[test]
    fn del_is_dropped() {
        let cap = Capture::new();
        let mut p = new_parser(&cap);
        feed(&mut p, &[b'a', C_DEL, b'b']);
        assert_eq!(*cap.prints.borrow(), vec![b'a' as u32, b'b' as u32]);
        assert_eq!(cap.executes.borrow().len(), 0);
    }

    #[test]
    fn unknown_escape_sequence_dropped() {
        let cap = Capture::new();
        let mut p = new_parser(&cap);
        // ESC X is unrecognised → drop silently.
        feed(&mut p, b"\x1bXfoo");
        assert_eq!(*cap.prints.borrow(), vec![b'f' as u32, b'o' as u32, b'o' as u32]);
        assert_eq!(cap.csi_calls.borrow().len(), 0);
        assert_eq!(cap.osc_calls.borrow().len(), 0);
    }
}
