//! DuetOS ACPI AML namespace walker.
//!
//! A memory-safe reimplementation of the former hand-written C++
//! TermList walker (`kernel/acpi/aml.cpp`). Walks the AML byte
//! stream of one ACPI table (DSDT / SSDT) and appends the named
//! objects it declares — Scope, Device, Method, Name, OperationRegion,
//! Mutex, Event, Alias, External, Processor, ThermalZone, PowerResource
//! — to the caller's namespace table, plus a constant-bound
//! OperationRegion + NamedField index the C++ evaluator backs
//! FieldUnit reads with.
//!
//! This is NOT a full AML interpreter: methods are recorded (with
//! their byte offset) but not evaluated, and computed (non-constant)
//! OperationRegion bounds are recorded as base=0/len=0. Execution
//! stays in C++ (`aml_eval.cpp`).
//!
//! Behaviour is byte-for-byte identical to the C++ walker it
//! replaces: same opcode subset, same "stop the current TermList on
//! an unrecognised opcode and let the parent resume at its PkgLength
//! end" recovery, same 32-deep recursion cap, same path encoding.
//!
//! Spec: ACPI 6.5 §20.2 (AML byte-stream encoding).

#![no_std]

use core::slice;

const KPATH_CAP: usize = 64;
const KMAX_RECURSION: u8 = 32;
const KSDT_HEADER_SIZE: usize = 36;

// AmlObjectKind discriminants — must match the enum order in
// kernel/acpi/aml.h.
const KIND_SCOPE: u8 = 0;
const KIND_DEVICE: u8 = 1;
const KIND_METHOD: u8 = 2;
const KIND_NAME: u8 = 3;
const KIND_OPREGION: u8 = 4;
const KIND_MUTEX: u8 = 5;
const KIND_EVENT: u8 = 6;
const KIND_ALIAS: u8 = 7;
const KIND_EXTERNAL: u8 = 8;
const KIND_PROCESSOR: u8 = 9;
const KIND_THERMALZONE: u8 = 10;
const KIND_POWERRESOURCE: u8 = 11;

// Region-space byte (ACPI 6.x §5.5.2.2): pass-through if <= 0x05,
// else 0xFF (AmlRegionSpace::Other).
const REGION_OTHER: u8 = 0xFF;

// Top-level opcodes.
const OP_ZERO: u8 = 0x00;
const OP_ONE: u8 = 0x01;
const OP_ALIAS: u8 = 0x06;
const OP_NAME: u8 = 0x08;
const OP_SCOPE: u8 = 0x10;
const OP_BUFFER: u8 = 0x11;
const OP_PACKAGE: u8 = 0x12;
const OP_VARPACKAGE: u8 = 0x13;
const OP_METHOD: u8 = 0x14;
const OP_EXTERNAL: u8 = 0x15;
const OP_EXT_PREFIX: u8 = 0x5B;

// Extended opcodes (after the 0x5B prefix).
const EXT_MUTEX: u8 = 0x01;
const EXT_EVENT: u8 = 0x02;
const EXT_OPREGION: u8 = 0x80;
const EXT_FIELD: u8 = 0x81;
const EXT_DEVICE: u8 = 0x82;
const EXT_PROCESSOR: u8 = 0x83;
const EXT_POWERRES: u8 = 0x84;
const EXT_THERMALZONE: u8 = 0x85;

#[repr(C)]
pub struct DuetosAmlEntry {
    pub path: [u8; 64],
    pub kind: u8,
    pub method_args: u8,
    pub source_table_idx: u8,
    pub _pad: u8,
    pub aml_offset: u32,
}

#[repr(C)]
pub struct DuetosAmlRegion {
    pub path: [u8; 64],
    pub space: u8,
    pub source_table_idx: u8,
    pub _pad: [u8; 2],
    pub base: u64,
    pub length: u64,
}

#[repr(C)]
pub struct DuetosAmlField {
    pub path: [u8; 64],
    pub region: [u8; 64],
    pub bit_offset: u32,
    pub bit_width: u32,
    pub access_bytes: u8,
    pub source_table_idx: u8,
    pub _pad: [u8; 2],
}

#[inline]
fn is_lead_name_char(c: u8) -> bool {
    c == b'_' || c.is_ascii_uppercase()
}

#[inline]
fn is_name_char(c: u8) -> bool {
    is_lead_name_char(c) || c.is_ascii_digit()
}

// Decode a PkgLength field (ACPI 6.x §20.2.4). Returns
// (encoded_length, bytes_consumed) or None on malformed input.
fn read_pkg_length(p: &[u8]) -> Option<(u32, u32)> {
    let lead = *p.first()? as u32;
    let follow = (lead >> 6) & 0x3;
    if p.len() < (1 + follow) as usize {
        return None;
    }
    if follow == 0 {
        return Some((lead & 0x3F, 1));
    }
    let mut len = lead & 0x0F;
    for i in 0..follow {
        len |= (p[(1 + i) as usize] as u32) << (4 + i * 8);
    }
    Some((len, 1 + follow))
}

struct NameString {
    text: [u8; 64], // NUL-terminated
    prefix_caret: u32,
    absolute: bool,
    null_name: bool,
}

impl NameString {
    fn new() -> Self {
        NameString {
            text: [0; 64],
            prefix_caret: 0,
            absolute: false,
            null_name: false,
        }
    }
}

// Decode a NameString. Returns (NameString, bytes_consumed) or None.
// Faithful port of aml.cpp ReadNameString.
fn read_name_string(p: &[u8]) -> Option<(NameString, u32)> {
    let remaining = p.len();
    let mut out = NameString::new();
    let mut pos: usize = 0;

    // Prefix: at most one '\\' or many '^'.
    if pos < remaining && p[pos] == b'\\' {
        out.absolute = true;
        pos += 1;
    } else {
        while pos < remaining && p[pos] == b'^' {
            out.prefix_caret += 1;
            pos += 1;
        }
    }

    if pos >= remaining {
        return None;
    }

    // NullName.
    if p[pos] == 0x00 {
        out.null_name = true;
        out.text[0] = 0;
        return Some((out, (pos + 1) as u32));
    }

    let mut seg_count: u8 = 1;
    if p[pos] == 0x2E {
        // DualNamePrefix
        seg_count = 2;
        pos += 1;
    } else if p[pos] == 0x2F {
        // MultiNamePrefix
        pos += 1;
        if pos >= remaining {
            return None;
        }
        seg_count = p[pos];
        pos += 1;
        if seg_count == 0 {
            return None;
        }
    }

    if pos + (seg_count as usize) * 4 > remaining {
        return None;
    }

    let mut write: usize = 0;
    for s in 0..seg_count {
        if s != 0 {
            if write + 1 >= out.text.len() {
                return None;
            }
            out.text[write] = b'.';
            write += 1;
        }
        for i in 0..4u8 {
            let c = p[pos + i as usize];
            let ok = if i == 0 { is_lead_name_char(c) } else { is_name_char(c) };
            if !ok {
                return None;
            }
            if write + 1 >= out.text.len() {
                return None;
            }
            out.text[write] = c;
            write += 1;
        }
        pos += 4;
    }
    out.text[write] = 0;
    Some((out, pos as u32))
}

// Length of a NUL-terminated byte buffer (capped at buf.len()).
fn cstr_len(buf: &[u8]) -> usize {
    buf.iter().position(|&c| c == 0).unwrap_or(buf.len())
}

// Compose `scope` (NUL-terminated) + parsed NameString into a
// canonical absolute path. Faithful port of aml.cpp ComposePath.
fn compose_path(scope: &[u8], name: &NameString) -> Option<[u8; 64]> {
    let mut buf = [0u8; KPATH_CAP];
    let mut w: usize = 0;

    if name.absolute {
        if w + 1 >= KPATH_CAP {
            return None;
        }
        buf[w] = b'\\';
        w += 1;
    } else {
        let slen = cstr_len(scope);
        let mut i = 0;
        while i < slen && w + 1 < KPATH_CAP {
            buf[w] = scope[i];
            w += 1;
            i += 1;
        }
        for _ in 0..name.prefix_caret {
            while w > 0 && buf[w - 1] != b'.' && buf[w - 1] != b'\\' {
                w -= 1;
            }
            if w > 0 && buf[w - 1] == b'.' {
                w -= 1;
            } else if w == 0 {
                return None; // '^' past the root
            }
        }
    }

    if !name.null_name {
        let need_dot = w > 0 && buf[w - 1] != b'\\';
        if need_dot {
            if w + 1 >= KPATH_CAP {
                return None;
            }
            buf[w] = b'.';
            w += 1;
        }
        let nlen = cstr_len(&name.text);
        let mut i = 0;
        while i < nlen && w + 1 < KPATH_CAP {
            buf[w] = name.text[i];
            w += 1;
            i += 1;
        }
        if i < nlen {
            return None; // truncated
        }
    }

    if w + 1 > KPATH_CAP {
        return None;
    }
    buf[w] = 0;
    Some(buf)
}

// Decode a constant-integer TermArg. Faithful port of
// aml.cpp ReadConstInteger. Returns (value, bytes_consumed).
fn read_const_integer(p: &[u8]) -> Option<(u64, u32)> {
    let b0 = *p.first()?;
    match b0 {
        0x00 => Some((0, 1)),
        0x01 => Some((1, 1)),
        0xFF => Some((!0u64, 1)),
        0x0A => {
            if p.len() < 2 {
                return None;
            }
            Some((p[1] as u64, 2))
        }
        0x0B => {
            if p.len() < 3 {
                return None;
            }
            Some(((p[1] as u64) | (p[2] as u64) << 8, 3))
        }
        0x0C => {
            if p.len() < 5 {
                return None;
            }
            Some((
                (p[1] as u64) | (p[2] as u64) << 8 | (p[3] as u64) << 16 | (p[4] as u64) << 24,
                5,
            ))
        }
        0x0E => {
            if p.len() < 9 {
                return None;
            }
            let mut v = 0u64;
            for i in 0..8 {
                v |= (p[1 + i] as u64) << (i * 8);
            }
            Some((v, 9))
        }
        _ => None,
    }
}

// Skip a simple DataRefObject. Faithful port of
// aml.cpp SkipDataRefObject. Returns bytes consumed, or 0 (= stop).
fn skip_data_ref_object(p: &[u8]) -> u32 {
    let remaining = p.len();
    if remaining == 0 {
        return 0;
    }
    match p[0] {
        0x00 | 0x01 | 0xFF => 1,
        0x0A => {
            if remaining >= 2 {
                2
            } else {
                0
            }
        }
        0x0B => {
            if remaining >= 3 {
                3
            } else {
                0
            }
        }
        0x0C => {
            if remaining >= 5 {
                5
            } else {
                0
            }
        }
        0x0E => {
            if remaining >= 9 {
                9
            } else {
                0
            }
        }
        0x0D => {
            // StringPrefix — NUL-terminated ASCII.
            let mut i = 1;
            while i < remaining && p[i] != 0 {
                i += 1;
            }
            if i >= remaining {
                0
            } else {
                (i + 1) as u32
            }
        }
        0x11 | 0x12 | 0x13 => {
            // Buffer / Package / VarPackage: PkgLength + body.
            match read_pkg_length(&p[1..]) {
                Some((pkg_len, _)) => {
                    let total = 1u64 + pkg_len as u64;
                    if total <= remaining as u64 {
                        total as u32
                    } else {
                        0
                    }
                }
                None => 0,
            }
        }
        _ => 0,
    }
}

fn access_type_to_bytes(field_flags: u8) -> u8 {
    match field_flags & 0x0F {
        2 => 2, // WordAcc
        3 => 4, // DWordAcc
        4 => 8, // QWordAcc
        _ => 1, // AnyAcc / ByteAcc / BufferAcc
    }
}

// Output context: the caller's namespace / region / field arrays
// plus their running counts. The walker appends; `record_*` are
// no-ops once the matching array is full (mirrors the C++ cap
// behaviour exactly — a full table silently stops recording).
struct Out<'a> {
    entries: &'a mut [DuetosAmlEntry],
    ecount: u32,
    regions: &'a mut [DuetosAmlRegion],
    rcount: u32,
    fields: &'a mut [DuetosAmlField],
    fcount: u32,
}

fn copy_cstr(dst: &mut [u8; 64], src: &[u8]) {
    let n = cstr_len(src).min(dst.len() - 1);
    dst[..n].copy_from_slice(&src[..n]);
    dst[n] = 0;
    for b in dst[n + 1..].iter_mut() {
        *b = 0;
    }
}

impl<'a> Out<'a> {
    fn record_entry(&mut self, path: &[u8], kind: u8, method_args: u8, src: u8, off: u32) {
        let i = self.ecount as usize;
        if i >= self.entries.len() {
            return;
        }
        let e = &mut self.entries[i];
        copy_cstr(&mut e.path, path);
        e.kind = kind;
        e.method_args = method_args;
        e.source_table_idx = src;
        e._pad = 0;
        e.aml_offset = off;
        self.ecount += 1;
    }

    fn record_region(&mut self, path: &[u8], space: u8, base: u64, length: u64, src: u8) {
        let i = self.rcount as usize;
        if i >= self.regions.len() {
            return;
        }
        let r = &mut self.regions[i];
        copy_cstr(&mut r.path, path);
        r.space = space;
        r.source_table_idx = src;
        r._pad = [0, 0];
        r.base = base;
        r.length = length;
        self.rcount += 1;
    }

    fn record_field(&mut self, unit: &[u8], region: &[u8], bit_off: u32, bit_w: u32, acc: u8, src: u8) {
        let i = self.fcount as usize;
        if i >= self.fields.len() {
            return;
        }
        let f = &mut self.fields[i];
        copy_cstr(&mut f.path, unit);
        copy_cstr(&mut f.region, region);
        f.bit_offset = bit_off;
        f.bit_width = bit_w;
        f.access_bytes = acc;
        f.source_table_idx = src;
        f._pad = [0, 0];
        self.fcount += 1;
    }
}

struct Walker<'a, 'o> {
    base: &'a [u8],
    source_idx: u8,
    depth: u8,
    next_pos: u32,
    out: &'o mut Out<'a>,
}

impl<'a, 'o> Walker<'a, 'o> {
    // Bytes [from, to) of the AML body. Callers guarantee
    // from <= to <= base.len() via the same bound checks the C++
    // walker used; clamp defensively so a logic slip can never
    // index out of range (it would just present an empty slice and
    // the helper's own length check stops the walk).
    #[inline]
    fn span(&self, from: u32, to: u32) -> &'a [u8] {
        let len = self.base.len();
        let f = (from as usize).min(len);
        let t = (to as usize).min(len).max(f);
        &self.base[f..t]
    }

    fn walk_term_list(&mut self, mut pos: u32, end: u32, scope: &[u8]) {
        if self.depth >= KMAX_RECURSION {
            return;
        }
        self.depth += 1;
        let length = self.base.len() as u32;

        while pos < end && pos < length && (self.out.ecount as usize) < self.out.entries.len() {
            let start = pos;
            let op = self.base[pos as usize];
            pos += 1;

            if op == OP_EXT_PREFIX {
                if pos >= end {
                    break;
                }
                let ext = self.base[pos as usize];
                pos += 1;
                if !self.handle_ext(start, pos, end, scope, ext) {
                    break;
                }
                pos = self.next_pos;
                continue;
            }

            match op {
                OP_ZERO | OP_ONE => continue,
                OP_ALIAS => {
                    if !self.record_name_pair(start, pos, end, scope, KIND_ALIAS) {
                        break;
                    }
                    pos = self.next_pos;
                    continue;
                }
                OP_NAME => {
                    let (ns, consumed) = match read_name_string(self.span(pos, end)) {
                        Some(v) => v,
                        None => break,
                    };
                    let path = match compose_path(scope, &ns) {
                        Some(p) => p,
                        None => break,
                    };
                    self.out.record_entry(&path, KIND_NAME, 0, self.source_idx, start);
                    pos += consumed;
                    let dr = skip_data_ref_object(self.span(pos, end));
                    if dr == 0 {
                        break;
                    }
                    pos += dr;
                    continue;
                }
                OP_SCOPE => {
                    if !self.handle_container(start, pos, end, scope, KIND_SCOPE, true) {
                        break;
                    }
                    pos = self.next_pos;
                    continue;
                }
                OP_METHOD => {
                    if !self.handle_method(start, pos, end, scope) {
                        break;
                    }
                    pos = self.next_pos;
                    continue;
                }
                OP_BUFFER | OP_PACKAGE | OP_VARPACKAGE => break,
                OP_EXTERNAL => {
                    let (ns, consumed) = match read_name_string(self.span(pos, end)) {
                        Some(v) => v,
                        None => break,
                    };
                    if pos + consumed + 2 > end {
                        break;
                    }
                    let path = match compose_path(scope, &ns) {
                        Some(p) => p,
                        None => break,
                    };
                    self.out.record_entry(&path, KIND_EXTERNAL, 0, self.source_idx, start);
                    pos += consumed + 2;
                    continue;
                }
                _ => break,
            }
        }

        self.depth -= 1;
    }

    fn handle_ext(&mut self, start: u32, after_op: u32, end: u32, scope: &[u8], ext: u8) -> bool {
        match ext {
            EXT_DEVICE => self.handle_container(start, after_op, end, scope, KIND_DEVICE, true),
            EXT_PROCESSOR => self.handle_container(start, after_op, end, scope, KIND_PROCESSOR, true),
            EXT_POWERRES => self.handle_container(start, after_op, end, scope, KIND_POWERRESOURCE, true),
            EXT_THERMALZONE => self.handle_container(start, after_op, end, scope, KIND_THERMALZONE, true),
            EXT_OPREGION => self.handle_op_region(start, after_op, end, scope),
            EXT_MUTEX => {
                let (ns, consumed) = match read_name_string(self.span(after_op, end)) {
                    Some(v) => v,
                    None => return false,
                };
                if after_op + consumed + 1 > end {
                    return false;
                }
                let path = match compose_path(scope, &ns) {
                    Some(p) => p,
                    None => return false,
                };
                self.out.record_entry(&path, KIND_MUTEX, 0, self.source_idx, start);
                self.next_pos = after_op + consumed + 1;
                true
            }
            EXT_EVENT => {
                let (ns, consumed) = match read_name_string(self.span(after_op, end)) {
                    Some(v) => v,
                    None => return false,
                };
                let path = match compose_path(scope, &ns) {
                    Some(p) => p,
                    None => return false,
                };
                self.out.record_entry(&path, KIND_EVENT, 0, self.source_idx, start);
                self.next_pos = after_op + consumed;
                true
            }
            EXT_FIELD => self.index_field_list(after_op, end, scope),
            _ => false,
        }
    }

    // OpRegion: NameString RegionSpace(1) RegionOffset(TermArg)
    // RegionLen(TermArg). Constant offset/length is indexed; a
    // computed one is recorded base=0/len=0 and stops the TermList.
    fn handle_op_region(&mut self, start: u32, after_op: u32, end: u32, scope: &[u8]) -> bool {
        let (ns, consumed) = match read_name_string(self.span(after_op, end)) {
            Some(v) => v,
            None => return false,
        };
        let path = match compose_path(scope, &ns) {
            Some(p) => p,
            None => return false,
        };
        self.out.record_entry(&path, KIND_OPREGION, 0, self.source_idx, start);
        let mut q = after_op + consumed;
        if q >= end {
            return false;
        }
        let space_b = self.base[q as usize];
        q += 1;
        let space = if space_b <= 0x05 { space_b } else { REGION_OTHER };
        let off = read_const_integer(self.span(q, end));
        if let Some((roff, c1)) = off {
            if let Some((rlen, c2)) = read_const_integer(self.span(q + c1, end)) {
                self.out.record_region(&path, space, roff, rlen, self.source_idx);
                self.next_pos = q + c1 + c2;
                return true;
            }
        }
        self.out.record_region(&path, space, 0, 0, self.source_idx);
        false
    }

    // Scope / Device / Processor / PowerRes / ThermalZone:
    //   <op> PkgLength NameString TermList
    fn handle_container(&mut self, start: u32, after_op: u32, end: u32, scope: &[u8], kind: u8, recurse: bool) -> bool {
        let (pkg_len, plen_consumed) = match read_pkg_length(self.span(after_op, end)) {
            Some(v) => v,
            None => return false,
        };
        if pkg_len > end - after_op {
            return false;
        }
        // PkgLength counts its own encoding bytes; a value below that
        // would push name_off past pkg_end and underflow the slice.
        if pkg_len < plen_consumed {
            return false;
        }
        let pkg_end = after_op + pkg_len;
        let name_off = after_op + plen_consumed;
        let (ns, consumed) = match read_name_string(self.span(name_off, pkg_end)) {
            Some(v) => v,
            None => return false,
        };
        let path = match compose_path(scope, &ns) {
            Some(p) => p,
            None => return false,
        };
        self.out.record_entry(&path, kind, 0, self.source_idx, start);
        let body_off = name_off + consumed;
        // Processor adds 6 operand bytes before its TermList,
        // PowerResource adds 3. Skip so recursion lands on the head.
        let mut body = body_off;
        if kind == KIND_PROCESSOR && body + 6 <= pkg_end {
            body += 6;
        } else if kind == KIND_POWERRESOURCE && body + 3 <= pkg_end {
            body += 3;
        }
        if recurse {
            self.walk_term_list(body, pkg_end, &path);
        }
        self.next_pos = pkg_end;
        true
    }

    fn handle_method(&mut self, start: u32, after_op: u32, end: u32, scope: &[u8]) -> bool {
        let (pkg_len, plen_consumed) = match read_pkg_length(self.span(after_op, end)) {
            Some(v) => v,
            None => return false,
        };
        if pkg_len > end - after_op {
            return false;
        }
        if pkg_len < plen_consumed {
            return false;
        }
        let pkg_end = after_op + pkg_len;
        let name_off = after_op + plen_consumed;
        let (ns, consumed) = match read_name_string(self.span(name_off, pkg_end)) {
            Some(v) => v,
            None => return false,
        };
        let flags_off = name_off + consumed;
        if flags_off >= pkg_end {
            return false;
        }
        let method_flags = self.base[flags_off as usize];
        let method_args = method_flags & 0x07;
        let path = match compose_path(scope, &ns) {
            Some(p) => p,
            None => return false,
        };
        self.out.record_entry(&path, KIND_METHOD, method_args, self.source_idx, start);
        self.next_pos = pkg_end;
        true
    }

    fn record_name_pair(&mut self, start: u32, after_op: u32, end: u32, scope: &[u8], kind: u8) -> bool {
        let (first, c1) = match read_name_string(self.span(after_op, end)) {
            Some(v) => v,
            None => return false,
        };
        let (_second, c2) = match read_name_string(self.span(after_op + c1, end)) {
            Some(v) => v,
            None => return false,
        };
        let path = match compose_path(scope, &first) {
            Some(p) => p,
            None => return false,
        };
        self.out.record_entry(&path, kind, 0, self.source_idx, start);
        self.next_pos = after_op + c1 + c2;
        true
    }

    // Field: PkgLength NameString(region) FieldFlags FieldList.
    // Records each NamedField unit. Always sets next_pos = pkg_end.
    fn index_field_list(&mut self, after_op: u32, end: u32, scope: &[u8]) -> bool {
        let (pkg_len, plen_consumed) = match read_pkg_length(self.span(after_op, end)) {
            Some(v) => v,
            None => return false,
        };
        if pkg_len > end - after_op {
            return false;
        }
        if pkg_len < plen_consumed {
            return false;
        }
        let pkg_end = after_op + pkg_len;
        self.next_pos = pkg_end; // walk continues here whatever we parse
        let mut q = after_op + plen_consumed;
        let (rns, c) = match read_name_string(self.span(q, pkg_end)) {
            Some(v) => v,
            None => return true,
        };
        q += c;
        let region_path = match compose_path(scope, &rns) {
            Some(p) => p,
            None => return true,
        };
        if q >= pkg_end {
            return true;
        }
        let mut acc = access_type_to_bytes(self.base[q as usize]);
        q += 1;
        let mut bit_off: u32 = 0;
        while q < pkg_end {
            let b = self.base[q as usize];
            if b == 0x00 {
                // ReservedField: 0x00 PkgLength(bits)
                q += 1;
                let (fl, fc) = match read_pkg_length(self.span(q, pkg_end)) {
                    Some(v) => v,
                    None => break,
                };
                q += fc;
                bit_off = bit_off.wrapping_add(fl);
            } else if b == 0x01 {
                // AccessField: 0x01 AccessType AccessAttrib
                if q + 3 > pkg_end {
                    break;
                }
                acc = access_type_to_bytes(self.base[(q + 1) as usize]);
                q += 3;
            } else if b == 0x03 {
                // ExtendedAccessField: 0x03 type attrib length
                if q + 4 > pkg_end {
                    break;
                }
                acc = access_type_to_bytes(self.base[(q + 1) as usize]);
                q += 4;
            } else if b == 0x02 {
                // ConnectField — GPIO/GenericSerialBus not modelled.
                break;
            } else {
                // NamedField: NameSeg(4) PkgLength(bit width)
                if q + 4 > pkg_end {
                    break;
                }
                let mut us = NameString::new();
                let mut ok = true;
                for i in 0..4u32 {
                    let ch = self.base[(q + i) as usize];
                    let good = if i == 0 { is_lead_name_char(ch) } else { is_name_char(ch) };
                    if !good {
                        ok = false;
                    }
                    us.text[i as usize] = ch;
                }
                us.text[4] = 0;
                q += 4;
                let (fl, fc) = match read_pkg_length(self.span(q, pkg_end)) {
                    Some(v) => v,
                    None => break,
                };
                q += fc;
                if ok {
                    if let Some(unit_path) = compose_path(scope, &us) {
                        self.out.record_field(&unit_path, &region_path, bit_off, fl, acc, self.source_idx);
                    }
                }
                bit_off = bit_off.wrapping_add(fl);
            }
        }
        true
    }
}

/// C FFI: walk one ACPI table's AML body, appending named objects to
/// the caller-provided arrays. See include/aml_rust.h.
///
/// # Safety
/// `sdt` must point at `total_len` readable bytes; the three array
/// pointers must each be valid for `*_cap` elements; the three count
/// pointers must be valid and hold the current (in/out) counts.
#[no_mangle]
pub unsafe extern "C" fn duetos_aml_walk_table(
    sdt: *const u8,
    total_len: u32,
    source_idx: u8,
    entries: *mut DuetosAmlEntry,
    entries_cap: u32,
    entries_count: *mut u32,
    regions: *mut DuetosAmlRegion,
    regions_cap: u32,
    regions_count: *mut u32,
    fields: *mut DuetosAmlField,
    fields_cap: u32,
    fields_count: *mut u32,
) {
    if sdt.is_null()
        || entries.is_null()
        || entries_count.is_null()
        || regions.is_null()
        || regions_count.is_null()
        || fields.is_null()
        || fields_count.is_null()
    {
        return;
    }
    if (total_len as usize) <= KSDT_HEADER_SIZE {
        return;
    }

    // SAFETY: the caller (kernel/acpi/aml.cpp) guarantees `sdt`
    // covers `total_len` readable bytes, each array pointer is valid
    // for its `*_cap` elements, and each count pointer is a valid
    // in/out u32. The null + length gates above cover the trivially
    // bad cases.
    let body = unsafe { slice::from_raw_parts(sdt.add(KSDT_HEADER_SIZE), total_len as usize - KSDT_HEADER_SIZE) };

    let mut out = Out {
        entries: unsafe { slice::from_raw_parts_mut(entries, entries_cap as usize) },
        ecount: unsafe { *entries_count },
        regions: unsafe { slice::from_raw_parts_mut(regions, regions_cap as usize) },
        rcount: unsafe { *regions_count },
        fields: unsafe { slice::from_raw_parts_mut(fields, fields_cap as usize) },
        fcount: unsafe { *fields_count },
    };

    let aml_len = body.len() as u32;
    let mut w = Walker {
        base: body,
        source_idx,
        depth: 0,
        next_pos: 0,
        out: &mut out,
    };
    // Root scope is "\\" (NUL-terminated).
    let root = [b'\\', 0u8];
    w.walk_term_list(0, aml_len, &root);

    unsafe {
        *entries_count = out.ecount;
        *regions_count = out.rcount;
        *fields_count = out.fcount;
    }
}
