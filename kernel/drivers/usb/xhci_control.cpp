/*
 * DuetOS — xHCI driver: control-EP0 transfer helpers.
 *
 * Sibling TU. Houses the three building blocks that every control
 * transfer on a device's default endpoint goes through:
 *
 *   DoControlIn         — IN data stage, common GET_DESCRIPTOR shape
 *   DoControlNoData     — no data stage, SET_CONFIGURATION / SET_IDLE
 *   ControlOutWithData  — OUT with optional payload, class-specific
 *
 * Each function takes a Runtime + DeviceState* — both internal::
 * types — and a USB Setup Packet's worth of fields, then enqueues
 * the canonical Setup / Data / Status TRB chain on the device's
 * EP0 ring and waits for the Status Stage Transfer Event.
 */

#include "../../arch/x86_64/serial.h"
#include "xhci_internal.h"

namespace duetos::drivers::usb::xhci::internal
{

// Generic USB control-IN transfer on EP0. Builds a three-TRB chain
// (Setup / Data / Status), rings DB[slot_id] target=1, and waits
// for the Transfer Event matching the Status Stage TRB. On success
// the device has written `wLength` bytes into `dev->scratch_virt`.
//
// bmRequestType / bRequest / wValue / wIndex / wLength map to the
// USB 2.0 §9.3 Setup Packet. Direction bit is expected to be IN
// (bmRequestType & 0x80); IN is the only variant this slice needs.
bool DoControlIn(Runtime& rt, DeviceState* dev, u8 bmRequestType, u8 bRequest, u16 wValue, u16 wIndex, u16 wLength,
                 const char* diag)
{
    const u32 setup_lo = u32(bmRequestType) | (u32(bRequest) << 8) | (u32(wValue) << 16);
    const u32 setup_hi = u32(wIndex) | (u32(wLength) << 16);
    const u32 setup_status = 8u;
    const u32 setup_ctl = (kTransferTypeInData << 16) | kTrbCtlIdt;
    const u64 setup_phys =
        EnqueueRingTrb(dev->ep0_ring, dev->ep0_ring_phys, dev->ep0_slots, dev->ep0_idx, dev->ep0_cycle,
                       kTrbTypeSetupStage, setup_lo, setup_hi, setup_status, setup_ctl);
    (void)setup_phys;

    const u64 data_phys =
        EnqueueRingTrb(dev->ep0_ring, dev->ep0_ring_phys, dev->ep0_slots, dev->ep0_idx, dev->ep0_cycle,
                       kTrbTypeDataStage, u32(dev->scratch_phys), u32(dev->scratch_phys >> 32), wLength, kTrbCtlDirIn);
    (void)data_phys;

    const u64 status_phys = EnqueueRingTrb(dev->ep0_ring, dev->ep0_ring_phys, dev->ep0_slots, dev->ep0_idx,
                                           dev->ep0_cycle, kTrbTypeStatusStage, 0, 0, 0, kTrbCtlIoc);
    if (status_phys == 0)
        return false;

    RingDoorbell(rt, dev->slot_id, 1);

    Trb event{};
    if (!WaitEvent(rt, status_phys, kTrbTypeTransferEvent, &event, 4'000'000))
    {
        arch::SerialWrite("[xhci]   control-IN ");
        arch::SerialWrite(diag);
        arch::SerialWrite(" timed out slot=");
        arch::SerialWriteHex(dev->slot_id);
        arch::SerialWrite("\n");
        return false;
    }
    const u32 code = (event.status >> 24) & 0xFF;
    if (code != kCompletionCodeSuccess)
    {
        arch::SerialWrite("[xhci]   control-IN ");
        arch::SerialWrite(diag);
        arch::SerialWrite(" failed code=");
        arch::SerialWriteHex(code);
        arch::SerialWrite(" (");
        arch::SerialWrite(CompletionCodeName(code));
        arch::SerialWrite(") slot=");
        arch::SerialWriteHex(dev->slot_id);
        arch::SerialWrite("\n");
        return false;
    }
    return true;
}

// Generic USB control transfer with NO data stage. Used by
// SET_CONFIGURATION + HID class-specific SET_PROTOCOL / SET_IDLE.
// bmRequestType is HOST-to-device (bit 7 = 0). The status stage
// for a no-data control transfer travels in the IN direction
// (opposite of what would have been the data direction, which
// for host-to-device is OUT — so status is IN).
bool DoControlNoData(Runtime& rt, DeviceState* dev, u8 bmRequestType, u8 bRequest, u16 wValue, u16 wIndex,
                     const char* diag)
{
    const u32 setup_lo = u32(bmRequestType) | (u32(bRequest) << 8) | (u32(wValue) << 16);
    const u32 setup_hi = u32(wIndex); // wLength = 0 for no-data transfer
    const u32 setup_status = 8u;
    const u32 setup_ctl = (kTransferTypeNoData << 16) | kTrbCtlIdt;
    const u64 setup_phys =
        EnqueueRingTrb(dev->ep0_ring, dev->ep0_ring_phys, dev->ep0_slots, dev->ep0_idx, dev->ep0_cycle,
                       kTrbTypeSetupStage, setup_lo, setup_hi, setup_status, setup_ctl);
    (void)setup_phys;

    // Status Stage IN (direction opposite of implied OUT data), IOC=1.
    const u64 status_phys = EnqueueRingTrb(dev->ep0_ring, dev->ep0_ring_phys, dev->ep0_slots, dev->ep0_idx,
                                           dev->ep0_cycle, kTrbTypeStatusStage, 0, 0, 0, kTrbCtlIoc | kTrbCtlDirIn);
    if (status_phys == 0)
        return false;

    RingDoorbell(rt, dev->slot_id, 1);

    Trb event{};
    if (!WaitEvent(rt, status_phys, kTrbTypeTransferEvent, &event, 4'000'000))
    {
        arch::SerialWrite("[xhci]   control-NoData ");
        arch::SerialWrite(diag);
        arch::SerialWrite(" timed out slot=");
        arch::SerialWriteHex(dev->slot_id);
        arch::SerialWrite("\n");
        return false;
    }
    const u32 code = (event.status >> 24) & 0xFF;
    if (code != kCompletionCodeSuccess)
    {
        arch::SerialWrite("[xhci]   control-NoData ");
        arch::SerialWrite(diag);
        arch::SerialWrite(" failed code=");
        arch::SerialWriteHex(code);
        arch::SerialWrite(" (");
        arch::SerialWrite(CompletionCodeName(code));
        arch::SerialWrite(") slot=");
        arch::SerialWriteHex(dev->slot_id);
        arch::SerialWrite("\n");
        return false;
    }
    return true;
}

bool ControlOutWithData(Runtime& rt, DeviceState* dev, u8 bmRequestType, u8 bRequest, u16 wValue, u16 wIndex,
                        const void* buf, u16 len, const char* diag)
{
    // bmRequestType bit 7 must be 0 (host-to-device).
    const u32 setup_lo = u32(bmRequestType) | (u32(bRequest) << 8) | (u32(wValue) << 16);
    const u32 setup_hi = u32(wIndex) | (u32(len) << 16);
    const u32 setup_status = 8u;
    const bool has_data = buf != nullptr && len > 0;
    const u32 transfer_type = has_data ? kTransferTypeOutData : kTransferTypeNoData;
    const u32 setup_ctl = (transfer_type << 16) | kTrbCtlIdt;

    const u64 setup_phys =
        EnqueueRingTrb(dev->ep0_ring, dev->ep0_ring_phys, dev->ep0_slots, dev->ep0_idx, dev->ep0_cycle,
                       kTrbTypeSetupStage, setup_lo, setup_hi, setup_status, setup_ctl);
    (void)setup_phys;

    if (has_data)
    {
        // Copy payload into the device's scratch page for DMA.
        const auto* src = static_cast<const u8*>(buf);
        for (u16 i = 0; i < len; ++i)
            dev->scratch_virt[i] = src[i];
        const u64 data_phys =
            EnqueueRingTrb(dev->ep0_ring, dev->ep0_ring_phys, dev->ep0_slots, dev->ep0_idx, dev->ep0_cycle,
                           kTrbTypeDataStage, u32(dev->scratch_phys), u32(dev->scratch_phys >> 32), len, /*ctl=*/0);
        (void)data_phys;
    }

    // Status stage IN (opposite of OUT data), IOC=1.
    const u64 status_phys = EnqueueRingTrb(dev->ep0_ring, dev->ep0_ring_phys, dev->ep0_slots, dev->ep0_idx,
                                           dev->ep0_cycle, kTrbTypeStatusStage, 0, 0, 0, kTrbCtlIoc | kTrbCtlDirIn);
    if (status_phys == 0)
        return false;
    RingDoorbell(rt, dev->slot_id, 1);
    Trb e{};
    if (!WaitEvent(rt, status_phys, kTrbTypeTransferEvent, &e, 4'000'000))
    {
        arch::SerialWrite("[xhci]   control-OUT ");
        arch::SerialWrite(diag);
        arch::SerialWrite(" timed out\n");
        return false;
    }
    const u32 code = (e.status >> 24) & 0xFF;
    if (code != kCompletionCodeSuccess)
    {
        arch::SerialWrite("[xhci]   control-OUT ");
        arch::SerialWrite(diag);
        arch::SerialWrite(" failed code=");
        arch::SerialWriteHex(code);
        arch::SerialWrite(" (");
        arch::SerialWrite(CompletionCodeName(code));
        arch::SerialWrite(")\n");
        return false;
    }
    return true;
}

} // namespace duetos::drivers::usb::xhci::internal
