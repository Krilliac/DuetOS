#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]

use core::{ptr, slice};

const DESC_TYPE_CONFIG: u8 = 0x02;
const DESC_TYPE_INTERFACE: u8 = 0x04;
const DESC_TYPE_ENDPOINT: u8 = 0x05;

const CLASS_MSC: u8 = 0x08;
const CLASS_HUB: u8 = 0x09;
const CLASS_VIDEO: u8 = 0x0E;
const CLASS_WIRELESS: u8 = 0xE0;

const MSC_SUBCLASS_SCSI: u8 = 0x06;
const MSC_PROTOCOL_BULK_ONLY: u8 = 0x50;
const VIDEO_SUBCLASS_CONTROL: u8 = 0x01;
const VIDEO_SUBCLASS_STREAMING: u8 = 0x02;
const WIRELESS_SUBCLASS_RF: u8 = 0x01;
const WIRELESS_PROTOCOL_BLUETOOTH: u8 = 0x01;

const EP_DIR_IN: u8 = 0x80;
const EP_XFER_MASK: u8 = 0x03;
const EP_XFER_CONTROL: u8 = 0x00;
const EP_XFER_ISO: u8 = 0x01;
const EP_XFER_BULK: u8 = 0x02;
const EP_XFER_INTERRUPT: u8 = 0x03;

const FLAG_MSC_BULK_ONLY: u32 = 1u32 << 0;
const FLAG_HUB: u32 = 1u32 << 1;
const FLAG_UVC_CONTROL: u32 = 1u32 << 2;
const FLAG_UVC_STREAMING: u32 = 1u32 << 3;
const FLAG_BLUETOOTH: u32 = 1u32 << 4;

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct DuetosUsbClassEndpointSet {
    pub bulk_in: u8,
    pub bulk_out: u8,
    pub interrupt_in: u8,
    pub interrupt_out: u8,
    pub iso_in: u8,
    pub iso_out: u8,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct DuetosUsbClassSummary {
    pub parse_ok: bool,
    pub bytes_consumed: u32,
    pub config_value: u8,
    pub interface_count: u8,
    pub endpoint_count: u8,
    pub flags: u32,
    pub msc: DuetosUsbClassEndpointSet,
    pub hub: DuetosUsbClassEndpointSet,
    pub uvc_control: DuetosUsbClassEndpointSet,
    pub uvc_streaming: DuetosUsbClassEndpointSet,
    pub bluetooth: DuetosUsbClassEndpointSet,
}

#[derive(Clone, Copy, Default)]
struct InterfaceContext {
    active: bool,
    class_code: u8,
    subclass: u8,
    protocol: u8,
}

fn write_default<'a, T: Default>(out: *mut T) -> Option<&'a mut T> {
    if out.is_null() {
        return None;
    }
    // SAFETY: The C ABI requires `out` to point at writable storage for `T`.
    // This FFI entry owns the only mutable borrow for the duration of the call
    // and initializes the complete object before any parser branch can return.
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
    // SAFETY: The C ABI requires non-empty descriptors to provide `len`
    // readable bytes. The parser only reads through bounds-checked slices
    // derived from this view.
    Some(unsafe { slice::from_raw_parts(buf, len as usize) })
}

fn read_le16(buf: &[u8], offset: usize) -> u16 {
    u16::from(buf[offset]) | (u16::from(buf[offset + 1]) << 8)
}

fn endpoint_set_for(
    summary: &mut DuetosUsbClassSummary,
    iface: InterfaceContext,
) -> Option<&mut DuetosUsbClassEndpointSet> {
    match (iface.class_code, iface.subclass, iface.protocol) {
        (CLASS_MSC, MSC_SUBCLASS_SCSI, MSC_PROTOCOL_BULK_ONLY) => Some(&mut summary.msc),
        (CLASS_HUB, _, _) => Some(&mut summary.hub),
        (CLASS_VIDEO, VIDEO_SUBCLASS_CONTROL, _) => Some(&mut summary.uvc_control),
        (CLASS_VIDEO, VIDEO_SUBCLASS_STREAMING, _) => Some(&mut summary.uvc_streaming),
        (CLASS_WIRELESS, WIRELESS_SUBCLASS_RF, WIRELESS_PROTOCOL_BLUETOOTH) => Some(&mut summary.bluetooth),
        _ => None,
    }
}

fn mark_interface(summary: &mut DuetosUsbClassSummary, iface: InterfaceContext) {
    match (iface.class_code, iface.subclass, iface.protocol) {
        (CLASS_MSC, MSC_SUBCLASS_SCSI, MSC_PROTOCOL_BULK_ONLY) => summary.flags |= FLAG_MSC_BULK_ONLY,
        (CLASS_HUB, _, _) => summary.flags |= FLAG_HUB,
        (CLASS_VIDEO, VIDEO_SUBCLASS_CONTROL, _) => summary.flags |= FLAG_UVC_CONTROL,
        (CLASS_VIDEO, VIDEO_SUBCLASS_STREAMING, _) => summary.flags |= FLAG_UVC_STREAMING,
        (CLASS_WIRELESS, WIRELESS_SUBCLASS_RF, WIRELESS_PROTOCOL_BLUETOOTH) => summary.flags |= FLAG_BLUETOOTH,
        _ => {}
    }
}

fn record_endpoint(set: &mut DuetosUsbClassEndpointSet, endpoint_address: u8, attributes: u8) {
    let transfer = attributes & EP_XFER_MASK;
    let is_in = (endpoint_address & EP_DIR_IN) != 0;
    match (transfer, is_in) {
        (EP_XFER_BULK, true) if set.bulk_in == 0 => set.bulk_in = endpoint_address,
        (EP_XFER_BULK, false) if set.bulk_out == 0 => set.bulk_out = endpoint_address,
        (EP_XFER_INTERRUPT, true) if set.interrupt_in == 0 => set.interrupt_in = endpoint_address,
        (EP_XFER_INTERRUPT, false) if set.interrupt_out == 0 => set.interrupt_out = endpoint_address,
        (EP_XFER_ISO, true) if set.iso_in == 0 => set.iso_in = endpoint_address,
        (EP_XFER_ISO, false) if set.iso_out == 0 => set.iso_out = endpoint_address,
        (EP_XFER_CONTROL, _) => {}
        _ => {}
    }
}

#[no_mangle]
pub extern "C" fn duetos_usbclass_parse_config(buf: *const u8, len: u32, out: *mut DuetosUsbClassSummary) -> bool {
    let Some(out) = write_default(out) else {
        return false;
    };
    let Some(desc) = descriptor_from_raw(buf, len) else {
        return false;
    };

    if desc.len() < 9 || desc[0] < 9 || desc[1] != DESC_TYPE_CONFIG {
        out.bytes_consumed = 0;
        return false;
    }

    let total_length = usize::from(read_le16(desc, 2));
    if total_length < 9 || total_length > desc.len() {
        out.bytes_consumed = 0;
        return false;
    }

    out.config_value = desc[5];

    let mut iface = InterfaceContext::default();
    let mut off = usize::from(desc[0]);
    while off < total_length {
        if off + 2 > total_length {
            out.bytes_consumed = off as u32;
            return false;
        }
        let length = usize::from(desc[off]);
        let descriptor_type = desc[off + 1];
        if length < 2 || off + length > total_length {
            out.bytes_consumed = off as u32;
            return false;
        }

        match descriptor_type {
            DESC_TYPE_INTERFACE => {
                if length < 9 {
                    out.bytes_consumed = off as u32;
                    return false;
                }
                iface = InterfaceContext {
                    active: true,
                    class_code: desc[off + 5],
                    subclass: desc[off + 6],
                    protocol: desc[off + 7],
                };
                out.interface_count = out.interface_count.saturating_add(1);
                mark_interface(out, iface);
            }
            DESC_TYPE_ENDPOINT => {
                if length < 7 {
                    out.bytes_consumed = off as u32;
                    return false;
                }
                out.endpoint_count = out.endpoint_count.saturating_add(1);
                if iface.active {
                    if let Some(set) = endpoint_set_for(out, iface) {
                        record_endpoint(set, desc[off + 2], desc[off + 3]);
                    }
                }
            }
            _ => {}
        }

        off += length;
    }

    out.bytes_consumed = off as u32;
    out.parse_ok = off == total_length;
    out.parse_ok
}
