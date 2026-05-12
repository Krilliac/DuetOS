#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]

use core::{ptr, slice};

const USAGE_PAGE_GENERIC: u16 = 0x01;
const USAGE_PAGE_KEYBOARD: u16 = 0x07;
const USAGE_PAGE_BUTTON: u16 = 0x09;
const USAGE_PAGE_CONSUMER: u16 = 0x0C;
const USAGE_PAGE_DIGITIZER: u16 = 0x0D;

const USAGE_GENERIC_POINTER: u16 = 0x01;
const USAGE_GENERIC_MOUSE: u16 = 0x02;
const USAGE_GENERIC_JOYSTICK: u16 = 0x04;
const USAGE_GENERIC_GAMEPAD: u16 = 0x05;
const USAGE_GENERIC_KEYBOARD: u16 = 0x06;
const USAGE_GENERIC_KEYPAD: u16 = 0x07;
const USAGE_GENERIC_X: u32 = 0x30;
const USAGE_GENERIC_Y: u32 = 0x31;
const USAGE_GENERIC_WHEEL: u32 = 0x38;
const USAGE_CONSUMER_AC_PAN: u32 = 0x238;

const TYPE_MAIN: u8 = 0;
const TYPE_GLOBAL: u8 = 1;
const TYPE_LOCAL: u8 = 2;

const MAIN_INPUT: u8 = 0x8;
const MAIN_OUTPUT: u8 = 0x9;
const MAIN_COLLECTION: u8 = 0xA;
const MAIN_FEATURE: u8 = 0xB;
const MAIN_END_COLLECTION: u8 = 0xC;

const GLOBAL_USAGE_PAGE: u8 = 0x0;
const GLOBAL_LOGICAL_MIN: u8 = 0x1;
const GLOBAL_REPORT_SIZE: u8 = 0x7;
const GLOBAL_REPORT_ID: u8 = 0x8;
const GLOBAL_REPORT_COUNT: u8 = 0x9;
const GLOBAL_PUSH: u8 = 0xA;
const GLOBAL_POP: u8 = 0xB;

const LOCAL_USAGE: u8 = 0x0;
const LOCAL_USAGE_MIN: u8 = 0x1;
const LOCAL_USAGE_MAX: u8 = 0x2;

const KIND_UNKNOWN: u8 = 0;
const KIND_KEYBOARD: u8 = 1;
const KIND_MOUSE: u8 = 2;
const KIND_POINTER: u8 = 3;
const KIND_KEYPAD: u8 = 4;
const KIND_JOYSTICK: u8 = 5;
const KIND_GAMEPAD: u8 = 6;
const KIND_CONSUMER: u8 = 7;
const KIND_DIGITIZER: u8 = 8;
const KIND_OTHER: u8 = 9;

const GLOBAL_STACK_MAX: usize = 4;
const LOCAL_USAGE_MAX_COUNT: usize = 8;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct DuetosUsbHidReportSummary {
    pub parse_ok: bool,
    pub bytes_consumed: u32,
    pub primary_kind: u8,
    pub top_usage_page: u16,
    pub top_usage: u16,
    pub collection_depth_max: u32,
    pub input_bits_total: u32,
    pub output_bits_total: u32,
    pub feature_bits_total: u32,
    pub button_field_count: u32,
    pub report_id_count: u32,
}

impl Default for DuetosUsbHidReportSummary {
    fn default() -> Self {
        Self {
            parse_ok: false,
            bytes_consumed: 0,
            primary_kind: KIND_UNKNOWN,
            top_usage_page: 0,
            top_usage: 0,
            collection_depth_max: 0,
            input_bits_total: 0,
            output_bits_total: 0,
            feature_bits_total: 0,
            button_field_count: 0,
            report_id_count: 0,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct DuetosUsbHidMouseField {
    pub present: bool,
    pub is_signed: bool,
    pub bit_size: u8,
    pub bit_offset: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct DuetosUsbHidMouseLayout {
    pub valid: bool,
    pub report_id: u8,
    pub report_size_bits: u32,
    pub buttons: DuetosUsbHidMouseField,
    pub x: DuetosUsbHidMouseField,
    pub y: DuetosUsbHidMouseField,
    pub wheel: DuetosUsbHidMouseField,
    pub h_tilt: DuetosUsbHidMouseField,
}

#[derive(Clone, Copy, Default)]
struct GlobalState {
    usage_page: u16,
    report_size: u32,
    report_count: u32,
    report_id: u32,
}

#[derive(Clone, Copy)]
struct LocalUsageList {
    count: usize,
    page: [u32; LOCAL_USAGE_MAX_COUNT],
    usage: [u32; LOCAL_USAGE_MAX_COUNT],
}

impl Default for LocalUsageList {
    fn default() -> Self {
        Self {
            count: 0,
            page: [0; LOCAL_USAGE_MAX_COUNT],
            usage: [0; LOCAL_USAGE_MAX_COUNT],
        }
    }
}

impl LocalUsageList {
    fn reset(&mut self) {
        self.count = 0;
    }

    fn append(&mut self, page: u32, usage: u32) {
        if self.count >= LOCAL_USAGE_MAX_COUNT {
            return;
        }
        self.page[self.count] = page;
        self.usage[self.count] = usage;
        self.count += 1;
    }
}

fn item_size(prefix: u8) -> u8 {
    match prefix & 0x03 {
        3 => 4,
        raw => raw,
    }
}

fn item_type(prefix: u8) -> u8 {
    (prefix >> 2) & 0x03
}

fn item_tag(prefix: u8) -> u8 {
    (prefix >> 4) & 0x0F
}

fn read_u_data(data: &[u8]) -> u32 {
    let mut value = 0u32;
    for (index, byte) in data.iter().copied().enumerate() {
        value |= u32::from(byte) << (index * 8);
    }
    value
}

fn sign_extend(data: u32, size: u8) -> i32 {
    match size {
        1 if (data & 0x80) != 0 => (data | 0xFFFF_FF00) as i32,
        2 if (data & 0x8000) != 0 => (data | 0xFFFF_0000) as i32,
        _ => data as i32,
    }
}

fn classify_top_usage(page: u16, usage: u16) -> u8 {
    if page == USAGE_PAGE_GENERIC {
        return match usage {
            USAGE_GENERIC_POINTER => KIND_POINTER,
            USAGE_GENERIC_MOUSE => KIND_MOUSE,
            USAGE_GENERIC_KEYBOARD => KIND_KEYBOARD,
            USAGE_GENERIC_KEYPAD => KIND_KEYPAD,
            USAGE_GENERIC_JOYSTICK => KIND_JOYSTICK,
            USAGE_GENERIC_GAMEPAD => KIND_GAMEPAD,
            _ => KIND_OTHER,
        };
    }
    if page == USAGE_PAGE_CONSUMER {
        return KIND_CONSUMER;
    }
    if page == USAGE_PAGE_DIGITIZER {
        return KIND_DIGITIZER;
    }
    if page == USAGE_PAGE_KEYBOARD {
        return KIND_KEYBOARD;
    }
    if page == USAGE_PAGE_BUTTON {
        return KIND_OTHER;
    }
    KIND_UNKNOWN
}

fn write_default<'a, T: Default>(out: *mut T) -> Option<&'a mut T> {
    if out.is_null() {
        return None;
    }
    // SAFETY: The C ABI requires `out` to point at writable storage for `T`.
    // This FFI entry owns the only mutable borrow for the duration of the call
    // and initializes the complete object before any early return.
    unsafe {
        ptr::write(out, T::default());
        Some(&mut *out)
    }
}

fn descriptor_from_raw<'a>(buf: *const u8, len: u32) -> Option<&'a [u8]> {
    if len == 0 {
        return Some(&[]);
    }
    if buf.is_null() {
        return None;
    }
    // SAFETY: The FFI contract requires non-empty descriptors to provide `len`
    // readable bytes. The parser never writes through this view and every HID
    // item read below is checked against the slice bounds.
    Some(unsafe { slice::from_raw_parts(buf, len as usize) })
}

fn consume_long_item(desc: &[u8], off: &mut usize) -> bool {
    if *off + 3 > desc.len() {
        return false;
    }
    let data_size = usize::from(desc[*off + 1]);
    let Some(next) = off.checked_add(3 + data_size) else {
        return false;
    };
    if next > desc.len() {
        return false;
    }
    *off = next;
    true
}

#[no_mangle]
pub extern "C" fn duetos_usbhid_parse_descriptor(
    buf: *const u8,
    len: u32,
    out: *mut DuetosUsbHidReportSummary,
) -> bool {
    let Some(out) = write_default(out) else {
        return false;
    };
    let Some(desc) = descriptor_from_raw(buf, len) else {
        return false;
    };

    let mut gs = GlobalState::default();
    let mut stack = [GlobalState::default(); GLOBAL_STACK_MAX];
    let mut stack_depth = 0usize;
    let mut coll_depth = 0u32;
    let mut saw_top_usage_page = false;
    let mut saw_top_usage = false;
    let mut report_id_seen = [false; 256];

    let mut off = 0usize;
    while off < desc.len() {
        let prefix = desc[off];
        if prefix == 0xFE {
            if !consume_long_item(desc, &mut off) {
                out.bytes_consumed = off as u32;
                return false;
            }
            continue;
        }

        let data_size = usize::from(item_size(prefix));
        let Some(data_end) = off.checked_add(1 + data_size) else {
            out.bytes_consumed = off as u32;
            return false;
        };
        if data_end > desc.len() {
            out.bytes_consumed = off as u32;
            return false;
        }

        let data = read_u_data(&desc[(off + 1)..data_end]);
        let item_type = item_type(prefix);
        let tag = item_tag(prefix);

        if item_type == TYPE_GLOBAL {
            match tag {
                GLOBAL_USAGE_PAGE => {
                    gs.usage_page = data as u16;
                    if !saw_top_usage_page {
                        out.top_usage_page = gs.usage_page;
                        saw_top_usage_page = true;
                    }
                }
                GLOBAL_REPORT_SIZE => gs.report_size = data,
                GLOBAL_REPORT_COUNT => {
                    // Cap at a generous-but-bounded value so a malicious
                    // HID descriptor declaring `report_count = u32::MAX`
                    // cannot drive the downstream
                    // `for field_index in 0..gs.report_count` loop into
                    // a multi-billion-iteration DoS in IRQ context. Real
                    // HID reports never exceed a few hundred fields per
                    // collection; 4096 is far past anything legitimate.
                    const MAX_REPORT_COUNT: u32 = 4096;
                    gs.report_count = if data > MAX_REPORT_COUNT { MAX_REPORT_COUNT } else { data };
                }
                GLOBAL_REPORT_ID => {
                    gs.report_id = data;
                    // HID Report IDs are one-byte, non-zero values. Keep the
                    // complete 1..=255 domain instead of a compact bitset so a
                    // malicious descriptor cannot hide high-numbered IDs.
                    if (1..=255).contains(&data) {
                        let id = data as usize;
                        if !report_id_seen[id] {
                            report_id_seen[id] = true;
                            out.report_id_count += 1;
                        }
                    }
                }
                GLOBAL_PUSH => {
                    if stack_depth < GLOBAL_STACK_MAX {
                        stack[stack_depth] = gs;
                        stack_depth += 1;
                    }
                }
                GLOBAL_POP => {
                    if stack_depth > 0 {
                        stack_depth -= 1;
                        gs = stack[stack_depth];
                    }
                }
                _ => {}
            }
        } else if item_type == TYPE_LOCAL {
            if tag == LOCAL_USAGE && !saw_top_usage {
                out.top_usage = data as u16;
                saw_top_usage = true;
            }
        } else if item_type == TYPE_MAIN {
            match tag {
                MAIN_COLLECTION => {
                    coll_depth += 1;
                    if coll_depth > out.collection_depth_max {
                        out.collection_depth_max = coll_depth;
                    }
                }
                MAIN_END_COLLECTION => {
                    coll_depth = coll_depth.saturating_sub(1);
                }
                MAIN_INPUT | MAIN_OUTPUT | MAIN_FEATURE => {
                    let bits = gs.report_size.saturating_mul(gs.report_count);
                    let is_constant = (data & 0x01) != 0;
                    if tag == MAIN_INPUT {
                        out.input_bits_total = out.input_bits_total.saturating_add(bits);
                        if !is_constant && gs.usage_page == USAGE_PAGE_BUTTON {
                            out.button_field_count += 1;
                        }
                    } else if tag == MAIN_OUTPUT {
                        out.output_bits_total = out.output_bits_total.saturating_add(bits);
                    } else {
                        out.feature_bits_total = out.feature_bits_total.saturating_add(bits);
                    }
                }
                _ => {}
            }
        }
        off = data_end;
    }

    out.bytes_consumed = off as u32;
    out.primary_kind = classify_top_usage(out.top_usage_page, out.top_usage);
    out.parse_ok = off == desc.len() && coll_depth == 0;
    out.parse_ok
}

fn record_field(field: &mut DuetosUsbHidMouseField, bit_offset: u32, bit_size: u8, is_signed: bool) {
    if field.present {
        return;
    }
    field.present = true;
    field.is_signed = is_signed;
    field.bit_size = bit_size;
    field.bit_offset = bit_offset;
}

#[no_mangle]
pub extern "C" fn duetos_usbhid_extract_mouse_layout(
    buf: *const u8,
    len: u32,
    out: *mut DuetosUsbHidMouseLayout,
) -> bool {
    let Some(out) = write_default(out) else {
        return false;
    };
    let Some(desc) = descriptor_from_raw(buf, len) else {
        return false;
    };

    let mut summary = DuetosUsbHidReportSummary::default();
    if !duetos_usbhid_parse_descriptor(buf, len, &mut summary) {
        return false;
    }
    if summary.primary_kind != KIND_MOUSE {
        return false;
    }

    let mut gs = GlobalState::default();
    let mut stack = [GlobalState::default(); GLOBAL_STACK_MAX];
    let mut stack_depth = 0usize;
    let mut locals = LocalUsageList::default();
    let mut usage_min_page = 0u32;
    let mut have_usage_min = false;
    let mut logical_min = 0i32;
    let mut in_mouse_collection = false;
    let mut mouse_app_depth = 0u32;
    let mut coll_depth = 0u32;
    let mut bit_cursor = 0u32;

    let mut off = 0usize;
    while off < desc.len() {
        let prefix = desc[off];
        if prefix == 0xFE {
            if !consume_long_item(desc, &mut off) {
                break;
            }
            continue;
        }

        let data_size = item_size(prefix);
        let data_size_usize = usize::from(data_size);
        let Some(data_end) = off.checked_add(1 + data_size_usize) else {
            break;
        };
        if data_end > desc.len() {
            break;
        }

        let data_u = read_u_data(&desc[(off + 1)..data_end]);
        let data_s = sign_extend(data_u, data_size);
        let item_type = item_type(prefix);
        let tag = item_tag(prefix);

        if item_type == TYPE_GLOBAL {
            match tag {
                GLOBAL_USAGE_PAGE => gs.usage_page = data_u as u16,
                GLOBAL_LOGICAL_MIN => logical_min = data_s,
                GLOBAL_REPORT_SIZE => gs.report_size = data_u,
                GLOBAL_REPORT_COUNT => gs.report_count = data_u,
                GLOBAL_REPORT_ID => {
                    gs.report_id = data_u;
                    if out.report_id == 0 && data_u != 0 && data_u <= 0xFF {
                        out.report_id = data_u as u8;
                    }
                }
                GLOBAL_PUSH => {
                    if stack_depth < GLOBAL_STACK_MAX {
                        stack[stack_depth] = gs;
                        stack_depth += 1;
                    }
                }
                GLOBAL_POP => {
                    if stack_depth > 0 {
                        stack_depth -= 1;
                        gs = stack[stack_depth];
                    }
                }
                _ => {}
            }
        } else if item_type == TYPE_LOCAL {
            match tag {
                LOCAL_USAGE => locals.append(u32::from(gs.usage_page), data_u),
                LOCAL_USAGE_MIN => {
                    usage_min_page = u32::from(gs.usage_page);
                    have_usage_min = true;
                }
                LOCAL_USAGE_MAX => {}
                _ => {}
            }
        } else if item_type == TYPE_MAIN {
            match tag {
                MAIN_COLLECTION => {
                    coll_depth += 1;
                    let app = data_u == 0x01;
                    let mut last_page = u32::from(gs.usage_page);
                    let mut last_usage = 0u32;
                    if locals.count > 0 {
                        last_page = locals.page[locals.count - 1];
                        last_usage = locals.usage[locals.count - 1];
                    }
                    if app
                        && last_page == u32::from(USAGE_PAGE_GENERIC)
                        && last_usage == u32::from(USAGE_GENERIC_MOUSE)
                        && !in_mouse_collection
                    {
                        in_mouse_collection = true;
                        mouse_app_depth = coll_depth;
                        bit_cursor = 0;
                    }
                    locals.reset();
                    have_usage_min = false;
                }
                MAIN_END_COLLECTION => {
                    if in_mouse_collection && coll_depth == mouse_app_depth {
                        in_mouse_collection = false;
                        mouse_app_depth = 0;
                    }
                    coll_depth = coll_depth.saturating_sub(1);
                    locals.reset();
                    have_usage_min = false;
                }
                MAIN_INPUT => {
                    let bits = gs.report_size.saturating_mul(gs.report_count);
                    let is_constant = (data_u & 0x01) != 0;
                    if in_mouse_collection {
                        if !is_constant && gs.report_size > 0 && gs.report_size <= 32 {
                            let size = gs.report_size;
                            let is_axis_signed = logical_min < 0;
                            if have_usage_min && usage_min_page == u32::from(USAGE_PAGE_BUTTON) {
                                let button_bits = if bits > 32 { 32 } else { bits } as u8;
                                record_field(&mut out.buttons, bit_cursor, button_bits, false);
                            } else {
                                for field_index in 0..gs.report_count {
                                    let mut field_page = u32::from(gs.usage_page);
                                    let mut field_usage = 0u32;
                                    let local_index = field_index as usize;
                                    if local_index < locals.count {
                                        field_page = locals.page[local_index];
                                        field_usage = locals.usage[local_index];
                                    } else if locals.count > 0 {
                                        field_page = locals.page[locals.count - 1];
                                        field_usage = locals.usage[locals.count - 1];
                                    }
                                    let sub_offset = bit_cursor.saturating_add(field_index.saturating_mul(size));
                                    if field_page == u32::from(USAGE_PAGE_GENERIC) {
                                        if field_usage == USAGE_GENERIC_X {
                                            record_field(&mut out.x, sub_offset, size as u8, is_axis_signed);
                                        } else if field_usage == USAGE_GENERIC_Y {
                                            record_field(&mut out.y, sub_offset, size as u8, is_axis_signed);
                                        } else if field_usage == USAGE_GENERIC_WHEEL {
                                            record_field(&mut out.wheel, sub_offset, size as u8, is_axis_signed);
                                        }
                                    } else if field_page == u32::from(USAGE_PAGE_CONSUMER)
                                        && field_usage == USAGE_CONSUMER_AC_PAN
                                    {
                                        record_field(&mut out.h_tilt, sub_offset, size as u8, is_axis_signed);
                                    }
                                }
                            }
                        }
                        bit_cursor = bit_cursor.saturating_add(bits);
                        if out.report_size_bits < bit_cursor {
                            out.report_size_bits = bit_cursor;
                        }
                    }
                    locals.reset();
                    have_usage_min = false;
                }
                MAIN_OUTPUT | MAIN_FEATURE => {
                    locals.reset();
                    have_usage_min = false;
                }
                _ => {}
            }
        }

        off = data_end;
    }

    out.valid = out.x.present && out.y.present;
    out.valid
}
