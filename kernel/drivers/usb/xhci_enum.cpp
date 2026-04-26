/*
 * DuetOS — xHCI driver: device enumeration pipeline.
 *
 * Sibling TU. Houses the slot-allocation + Address Device +
 * descriptor-fetch + HID-bring-up sequence that turns a freshly
 * reset port into a fully-configured HID device the poll task
 * (HidPollEntry, in xhci.cpp) can drive:
 *
 *   ZeroBytes             — small volatile-byte memset
 *   AllocDeviceSlot       — claim a g_devices entry
 *   AddressDevice         — Enable Slot + Address Device commands
 *   FetchDeviceDescriptor — GET_DESCRIPTOR(Device) on EP0
 *   FetchAndParseConfig   — two-phase Config-descriptor fetch + parse
 *   SetConfiguration      — USB SET_CONFIGURATION on EP0
 *   BringUpHidKeyboard    — Configure Endpoint + prime first IN TRB
 *
 * Cross-TU surface in xhci_internal.h. xhci.cpp's InitOne walks
 * each port and calls these in sequence.
 */

#include "drivers/usb/xhci.h"

#include "arch/x86_64/serial.h"
#include "log/klog.h"
#include "mm/frame_allocator.h"
#include "mm/page.h"
#include "drivers/usb/xhci_internal.h"

namespace duetos::drivers::usb::xhci::internal
{

// struct lowers to a memset call the linker can't resolve. Keep
// this local to the xHCI TU; a kernel-wide memset is a larger
// design decision than "reset my driver's per-device record".
void ZeroBytes(void* p, u64 n)
{
    auto* b = static_cast<volatile u8*>(p);
    for (u64 i = 0; i < n; ++i)
        b[i] = 0;
}

DeviceState* AllocDeviceSlot()
{
    for (u32 i = 0; i < kMaxDevicesTotal; ++i)
    {
        if (!g_devices[i].in_use)
        {
            ZeroBytes(&g_devices[i], sizeof(DeviceState));
            g_devices[i].in_use = true;
            if (i >= g_device_count)
                g_device_count = i + 1;
            return &g_devices[i];
        }
    }
    return nullptr;
}

// ---------------------------------------------------------------
// Device enumeration: Address Device + GET_DESCRIPTOR(Device).
// ---------------------------------------------------------------


bool AddressDevice(Runtime& rt, PortRecord& port)
{
    DeviceState* dev = AllocDeviceSlot();
    if (dev == nullptr)
    {
        arch::SerialWrite("[xhci]   device table full, skipping port ");
        arch::SerialWriteHex(port.port_num);
        arch::SerialWrite("\n");
        return false;
    }
    dev->slot_id = port.slot_id;
    dev->port_num = port.port_num;
    dev->speed = port.speed;

    // Device Context — sized ctx_bytes per entry, 32 entries, must
    // be 64-byte aligned. One 4 KiB page covers both 32B and 64B
    // contexts with room to spare.
    void* devctx_virt = nullptr;
    if (!AllocZeroPage(&dev->device_ctx_phys, &devctx_virt))
        return false;

    // Input Context — 1 control + 32 context slots.
    if (!AllocZeroPage(&dev->input_ctx_phys, &dev->input_ctx_virt))
        return false;

    // EP0 transfer ring — one page of Trb entries.
    void* ep0_virt = nullptr;
    if (!AllocZeroPage(&dev->ep0_ring_phys, &ep0_virt))
        return false;
    dev->ep0_ring = static_cast<Trb*>(ep0_virt);
    dev->ep0_slots = mm::kPageSize / sizeof(Trb);
    dev->ep0_idx = 0;
    dev->ep0_cycle = 1;
    // Install a trailing Link TRB so a future workload that fills
    // the ring doesn't crash — we don't expect to wrap during boot
    // but the structure should match spec.
    Trb& link = dev->ep0_ring[dev->ep0_slots - 1];
    link.param_lo = u32(dev->ep0_ring_phys);
    link.param_hi = u32(dev->ep0_ring_phys >> 32);
    link.status = 0;
    link.control = (kTrbTypeLink << 10) | (1u << 1) | 1u;

    // Scratch page for descriptor reads.
    void* scratch_virt = nullptr;
    if (!AllocZeroPage(&dev->scratch_phys, &scratch_virt))
        return false;
    dev->scratch_virt = static_cast<u8*>(scratch_virt);

    // Hand the device context to the controller via DCBAA[slot_id].
    rt.dcbaa[dev->slot_id] = dev->device_ctx_phys;

    // Build Input Context + submit Address Device.
    const u32 mps0 = DefaultMaxPacketSize0(dev->speed);
    BuildAddressDeviceInputContext(dev->input_ctx_virt, rt.ctx_bytes, dev->port_num, dev->speed, mps0,
                                   dev->ep0_ring_phys);

    // Address Device TRB: param = input_ctx_phys, control extra =
    // (slot_id << 24). BSR (Block Set Address Request) bit 9 is 0 —
    // we want the controller to both enable the slot AND issue the
    // SET_ADDRESS request in one shot.
    const u64 cmd_phys = SubmitCmd(rt, kTrbTypeAddressDevice, u32(dev->input_ctx_phys), u32(dev->input_ctx_phys >> 32),
                                   0, u32(dev->slot_id) << 24);
    if (cmd_phys == 0)
        return false;
    u32 status = 0;
    u8 slot_out = 0;
    if (!WaitCmdCompletion(rt, cmd_phys, &status, &slot_out))
    {
        arch::SerialWrite("[xhci]   Address Device timed out for slot ");
        arch::SerialWriteHex(dev->slot_id);
        arch::SerialWrite("\n");
        return false;
    }
    const u32 code = (status >> 24) & 0xFF;
    if (code != kCompletionCodeSuccess)
    {
        arch::SerialWrite("[xhci]   Address Device failed code=");
        arch::SerialWriteHex(code);
        arch::SerialWrite(" (");
        arch::SerialWrite(CompletionCodeName(code));
        arch::SerialWrite(") slot=");
        arch::SerialWriteHex(dev->slot_id);
        arch::SerialWrite("\n");
        return false;
    }
    port.addressed = true;
    return true;
}


bool FetchDeviceDescriptor(Runtime& rt, PortRecord& port)
{
    DeviceState* dev = DeviceForSlot(port.slot_id);
    if (dev == nullptr)
        return false;

    for (u32 i = 0; i < kDeviceDescriptorBytes; ++i)
        dev->scratch_virt[i] = 0;

    if (!DoControlIn(rt, dev, /*bmRequestType=*/0x80, kUsbReqGetDescriptor, kUsbDescriptorDevice, /*wIndex=*/0,
                     /*wLength=*/u16(kDeviceDescriptorBytes), "GET_DESCRIPTOR(Device)"))
        return false;

    const u8* d = dev->scratch_virt;
    port.max_packet_size_0 = d[7];
    port.vendor_id = u16(d[8]) | (u16(d[9]) << 8);
    port.product_id = u16(d[10]) | (u16(d[11]) << 8);
    port.device_class = d[4];
    port.device_subclass = d[5];
    port.device_protocol = d[6];
    port.descriptor_ok = true;
    dev->dev_class = port.device_class;
    dev->dev_subclass = port.device_subclass;
    return true;
}

// Fetch the Configuration descriptor in two phases: first the
// 9-byte header to learn wTotalLength, then the full
// wTotalLength-byte tree (capped by the scratch page size). Then
// parse for a HID boot keyboard. On success the port record is
// populated with hid_* fields.
bool FetchAndParseConfig(Runtime& rt, PortRecord& port)
{
    DeviceState* dev = DeviceForSlot(port.slot_id);
    if (dev == nullptr)
        return false;

    // Phase 1 — just the 9-byte header so we can read wTotalLength.
    for (u32 i = 0; i < kConfigDescriptorHeaderBytes; ++i)
        dev->scratch_virt[i] = 0;
    if (!DoControlIn(rt, dev, /*bmRequestType=*/0x80, kUsbReqGetDescriptor, kUsbDescriptorConfig, /*wIndex=*/0,
                     /*wLength=*/u16(kConfigDescriptorHeaderBytes), "GET_DESCRIPTOR(Config,hdr)"))
        return false;
    const u16 total_len = u16(dev->scratch_virt[2]) | (u16(dev->scratch_virt[3]) << 8);
    if (total_len < kConfigDescriptorHeaderBytes)
        return false;

    // Phase 2 — full tree. Cap at the scratch page so a pathological
    // device (wTotalLength > 4 KiB) doesn't overflow.
    u16 want = total_len;
    if (want > mm::kPageSize)
        want = u16(mm::kPageSize);
    for (u32 i = 0; i < want; ++i)
        dev->scratch_virt[i] = 0;
    if (!DoControlIn(rt, dev, /*bmRequestType=*/0x80, kUsbReqGetDescriptor, kUsbDescriptorConfig, /*wIndex=*/0,
                     /*wLength=*/want, "GET_DESCRIPTOR(Config,full)"))
        return false;
    port.config_desc_ok = true;
    port.config_desc_bytes = want;

    return ParseConfigForHidBoot(dev->scratch_virt, want, port);
}

// ---------------------------------------------------------------
// HID Boot Keyboard — SET_CONFIGURATION, Configure Endpoint,


bool SetConfiguration(Runtime& rt, DeviceState* dev, u8 config_value)
{
    return DoControlNoData(rt, dev, /*bmRequestType=*/0x00, kUsbReqSetConfiguration, /*wValue=*/u16(config_value),
                           /*wIndex=*/0, "SET_CONFIGURATION");
}


// Bring a HID Boot Keyboard all the way up: allocate its
// interrupt-IN transfer ring + 8-byte report buffer, build +
// submit the Configure Endpoint command, seed the first Normal
// TRB, mark the device hid_ready. The per-controller polling task
// picks up from there.
bool BringUpHidKeyboard(Runtime& rt, PortRecord& port)
{
    DeviceState* dev = DeviceForSlot(port.slot_id);
    if (dev == nullptr)
        return false;

    // SET_CONFIGURATION first so the HID interface is selected.
    if (!SetConfiguration(rt, dev, port.hid_config_value))
        return false;

    // Allocate the transfer ring + report buffer.
    mm::PhysAddr ring_phys = 0;
    void* ring_virt = nullptr;
    if (!AllocZeroPage(&ring_phys, &ring_virt))
        return false;
    mm::PhysAddr buf_phys = 0;
    void* buf_virt = nullptr;
    if (!AllocZeroPage(&buf_phys, &buf_virt))
        return false;

    dev->hid_ring_phys = ring_phys;
    dev->hid_ring = static_cast<Trb*>(ring_virt);
    dev->hid_ring_slots = mm::kPageSize / sizeof(Trb);
    dev->hid_ring_idx = 0;
    dev->hid_ring_cycle = 1;
    Trb& link = dev->hid_ring[dev->hid_ring_slots - 1];
    link.param_lo = u32(ring_phys);
    link.param_hi = u32(ring_phys >> 32);
    link.status = 0;
    link.control = (kTrbTypeLink << 10) | (1u << 1) | 1u;

    dev->hid_buf_phys = buf_phys;
    dev->hid_buf_virt = static_cast<u8*>(buf_virt);
    dev->hid_ep_addr = port.hid_ep_addr;
    dev->hid_ep_xhci_idx = EndpointDci(port.hid_ep_addr);
    dev->hid_ep_max_packet = port.hid_ep_max_packet;
    dev->hid_is_mouse = port.hid_mouse;

    // Configure Endpoint command — uses the command ring, not EP0.
    const u32 interval = HidXhciInterval(dev->speed, port.hid_ep_interval);
    BuildConfigureEndpointInputContext(dev->input_ctx_virt, rt.ctx_bytes, dev->port_num, dev->speed,
                                       dev->hid_ep_xhci_idx, kEpTypeInterruptIn, port.hid_ep_max_packet, interval,
                                       dev->hid_ring_phys);
    const u64 cmd_phys = SubmitCmd(rt, kTrbTypeConfigureEndpoint, u32(dev->input_ctx_phys),
                                   u32(dev->input_ctx_phys >> 32), 0, u32(dev->slot_id) << 24);
    if (cmd_phys == 0)
        return false;
    u32 cc = 0;
    u8 slot_out = 0;
    if (!WaitCmdCompletion(rt, cmd_phys, &cc, &slot_out))
    {
        arch::SerialWrite("[xhci]   Configure Endpoint timed out slot=");
        arch::SerialWriteHex(dev->slot_id);
        arch::SerialWrite("\n");
        return false;
    }
    const u32 code = (cc >> 24) & 0xFF;
    if (code != kCompletionCodeSuccess)
    {
        arch::SerialWrite("[xhci]   Configure Endpoint failed code=");
        arch::SerialWriteHex(code);
        arch::SerialWrite(" (");
        arch::SerialWrite(CompletionCodeName(code));
        arch::SerialWrite(") slot=");
        arch::SerialWriteHex(dev->slot_id);
        arch::SerialWrite("\n");
        return false;
    }

    // Seed the first Normal TRB + ring doorbell so the endpoint
    // has a TRB to fill when the keyboard has something to report.
    const u64 trb_phys = HidEnqueueNormalTrb(dev, dev->hid_buf_phys, dev->hid_ep_max_packet);
    if (trb_phys == 0)
        return false;
    dev->hid_outstanding_phys = trb_phys;
    for (u32 i = 0; i < 8; ++i)
        dev->hid_prev[i] = 0;
    RingDoorbell(rt, dev->slot_id, dev->hid_ep_xhci_idx);

    dev->hid_ready = true;
    return true;
}

} // namespace duetos::drivers::usb::xhci::internal
