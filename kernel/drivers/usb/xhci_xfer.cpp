/*
 * DuetOS — xHCI driver: public transfer surface (control + bulk).
 *
 * Sibling TU. Houses the public Xhci* surface that USB class
 * drivers (HID keyboard, MSC SCSI, CDC-ECM, RTL88xx, RNDIS) call
 * to issue control transfers on EP0 and bulk IN/OUT transfers on
 * configured class endpoints. Plus the three small accessor
 * helpers — DeviceForSlot, EndpointDci, HidEnqueueNormalTrb — that
 * cross both this TU and xhci.cpp via xhci_internal.h.
 *
 * All five publics delegate into the read-side primitives
 * (DoControlIn / DoControlNoData / ControlOutWithData,
 * BuildConfigureEndpointInputContext, SubmitCmd, EnqueueRingTrb,
 * RingDoorbell, WaitCmdCompletion, WaitEvent, TrbEventCacheTake)
 * already exposed in xhci_internal.h.
 */

#include "drivers/usb/xhci.h"

#include "arch/x86_64/serial.h"
#include "diag/cleanroom_trace.h"
#include "mm/page.h"
#include "sched/sched.h"
#include "drivers/usb/xhci_internal.h"

namespace duetos::drivers::usb::xhci
{

using namespace internal;

namespace internal
{

DeviceState* DeviceForSlot(u8 slot_id)
{
    for (u32 i = 0; i < kMaxDevicesTotal; ++i)
    {
        if (g_devices[i].in_use && g_devices[i].slot_id == slot_id)
            return &g_devices[i];
    }
    return nullptr;
}

// interrupt-IN transfer ring, periodic Normal TRB submission,
// report diff, KeyEvent injection.

// Translate a USB bEndpointAddress into the xHCI Device Context
// Index (DCI) used for both the input-context layout and the
// doorbell target. DCI = (ep_num * 2) + (direction==IN ? 1 : 0),
// with EP0 occupying DCI 1 regardless of direction.
u8 EndpointDci(u8 ep_addr)
{
    const u8 ep_num = ep_addr & 0x0F;
    const bool is_in = (ep_addr & 0x80) != 0;
    return u8((ep_num * 2) + (is_in ? 1 : 0));
}

// Enqueue one Normal TRB on the HID transfer ring. The controller
// reads `len` bytes into the buffer at `buf_phys`; we set IOC so
// the completion lands as a Transfer Event we can diff against the
// previous report.
u64 HidEnqueueNormalTrb(DeviceState* dev, u64 buf_phys, u32 len)
{
    return EnqueueRingTrb(dev->hid_ring, dev->hid_ring_phys, dev->hid_ring_slots, dev->hid_ring_idx,
                          dev->hid_ring_cycle, kTrbTypeNormal, u32(buf_phys), u32(buf_phys >> 32), len, kTrbCtlIoc);
}

} // namespace internal

bool XhciControlIn(u8 slot_id, u8 bmRequestType, u8 bRequest, u16 wValue, u16 wIndex, void* buf, u16 len)
{
    if ((bmRequestType & 0x80) == 0 || len > mm::kPageSize)
        return false;
    // A non-zero length with a null caller buffer is a caller bug —
    // we'd silently drop the device's IN data. Refuse so the bug
    // surfaces at the call site instead of as a missing read.
    if (buf == nullptr && len > 0)
        return false;
    DeviceState* dev = DeviceForSlot(slot_id);
    if (dev == nullptr)
        return false;
    Runtime& rt = g_poll_rt[dev->ctrlr_idx];
    if (!DoControlIn(rt, dev, bmRequestType, bRequest, wValue, wIndex, len, "user-control-IN"))
        return false;
    if (buf != nullptr && len > 0)
    {
        auto* dst = static_cast<u8*>(buf);
        for (u16 i = 0; i < len; ++i)
            dst[i] = dev->scratch_virt[i];
    }
    return true;
}

bool XhciControlOut(u8 slot_id, u8 bmRequestType, u8 bRequest, u16 wValue, u16 wIndex, const void* buf, u16 len)
{
    if ((bmRequestType & 0x80) != 0 || len > mm::kPageSize)
        return false;
    // Symmetric to XhciControlIn: claim len bytes but supply no
    // buffer is a caller bug. Refuse rather than silently degrade
    // to the no-data SETUP path inside ControlOutWithData.
    if (buf == nullptr && len > 0)
        return false;
    DeviceState* dev = DeviceForSlot(slot_id);
    if (dev == nullptr)
        return false;
    Runtime& rt = g_poll_rt[dev->ctrlr_idx];
    return ControlOutWithData(rt, dev, bmRequestType, bRequest, wValue, wIndex, buf, len, "user-control-OUT");
}

bool XhciConfigureBulkEndpoint(u8 slot_id, u8 ep_addr, u16 max_packet)
{
    DeviceState* dev = DeviceForSlot(slot_id);
    if (dev == nullptr)
        return false;
    const bool is_in = (ep_addr & 0x80) != 0;
    if (is_in && dev->bulk_in_ready)
        return true;
    if (!is_in && dev->bulk_out_ready)
        return true;

    mm::PhysAddr ring_phys = 0;
    void* ring_virt = nullptr;
    if (!AllocZeroPage(&ring_phys, &ring_virt))
        return false;

    auto* ring = static_cast<Trb*>(ring_virt);
    const u32 slots = mm::kPageSize / sizeof(Trb);
    Trb& link = ring[slots - 1];
    link.param_lo = u32(ring_phys);
    link.param_hi = u32(ring_phys >> 32);
    link.status = 0;
    link.control = (kTrbTypeLink << 10) | (1u << 1) | 1u;

    const u8 dci = EndpointDci(ep_addr);
    const u32 ep_type = is_in ? kEpTypeBulkIn : kEpTypeBulkOut;
    const u32 interval = 0; // bulk endpoints don't use the interval field

    Runtime& rt = g_poll_rt[dev->ctrlr_idx];
    BuildConfigureEndpointInputContext(dev->input_ctx_virt, rt.ctx_bytes, dev->port_num, dev->speed, dci, ep_type,
                                       max_packet, interval, ring_phys);
    const u64 cmd_phys = SubmitCmd(rt, kTrbTypeConfigureEndpoint, u32(dev->input_ctx_phys),
                                   u32(dev->input_ctx_phys >> 32), 0, u32(slot_id) << 24);
    if (cmd_phys == 0)
        return false;
    u32 cc = 0;
    u8 sl = 0;
    if (!WaitCmdCompletion(rt, cmd_phys, &cc, &sl))
        return false;
    const u32 code = (cc >> 24) & 0xFF;
    if (code != kCompletionCodeSuccess)
    {
        arch::SerialWrite("[xhci] bulk-EP configure failed code=");
        arch::SerialWriteHex(code);
        arch::SerialWrite(" (");
        arch::SerialWrite(CompletionCodeName(code));
        arch::SerialWrite(") slot=");
        arch::SerialWriteHex(slot_id);
        arch::SerialWrite(" ep=");
        arch::SerialWriteHex(ep_addr);
        arch::SerialWrite("\n");
        return false;
    }

    if (is_in)
    {
        dev->bulk_in_ep_addr = ep_addr;
        dev->bulk_in_dci = dci;
        dev->bulk_in_mps = max_packet;
        dev->bulk_in_ring_phys = ring_phys;
        dev->bulk_in_ring = ring;
        dev->bulk_in_ring_slots = slots;
        dev->bulk_in_ring_idx = 0;
        dev->bulk_in_ring_cycle = 1;
        dev->bulk_in_ready = true;
    }
    else
    {
        dev->bulk_out_ep_addr = ep_addr;
        dev->bulk_out_dci = dci;
        dev->bulk_out_mps = max_packet;
        dev->bulk_out_ring_phys = ring_phys;
        dev->bulk_out_ring = ring;
        dev->bulk_out_ring_slots = slots;
        dev->bulk_out_ring_idx = 0;
        dev->bulk_out_ring_cycle = 1;
        dev->bulk_out_ready = true;
    }
    return true;
}

u64 XhciBulkSubmit(u8 slot_id, u8 ep_addr, u64 buf_phys, u32 len)
{
    DeviceState* dev = DeviceForSlot(slot_id);
    if (dev == nullptr)
        return 0;
    const bool is_in = (ep_addr & 0x80) != 0;
    Runtime& rt = g_poll_rt[dev->ctrlr_idx];
    u64 trb_phys = 0;
    if (is_in)
    {
        if (!dev->bulk_in_ready || ep_addr != dev->bulk_in_ep_addr)
            return 0;
        trb_phys = EnqueueRingTrb(dev->bulk_in_ring, dev->bulk_in_ring_phys, dev->bulk_in_ring_slots,
                                  dev->bulk_in_ring_idx, dev->bulk_in_ring_cycle, kTrbTypeNormal, u32(buf_phys),
                                  u32(buf_phys >> 32), len, kTrbCtlIoc);
        RingDoorbell(rt, slot_id, dev->bulk_in_dci);
    }
    else
    {
        if (!dev->bulk_out_ready || ep_addr != dev->bulk_out_ep_addr)
            return 0;
        trb_phys = EnqueueRingTrb(dev->bulk_out_ring, dev->bulk_out_ring_phys, dev->bulk_out_ring_slots,
                                  dev->bulk_out_ring_idx, dev->bulk_out_ring_cycle, kTrbTypeNormal, u32(buf_phys),
                                  u32(buf_phys >> 32), len, kTrbCtlIoc);
        RingDoorbell(rt, slot_id, dev->bulk_out_dci);
    }
    return trb_phys;
}

bool XhciBulkPoll(u8 slot_id, u8 ep_addr, u64 trb_phys, u32* out_bytes, u64 timeout_us)
{
    DeviceState* dev = DeviceForSlot(slot_id);
    if (dev == nullptr || trb_phys == 0)
        return false;

    // Helper to compute bytes-actually-transferred from the
    // residual byte count + the TRB length we enqueued.
    auto compute_bytes = [&](u32 residual) -> u32
    {
        const Trb* ring = (ep_addr & 0x80) ? dev->bulk_in_ring : dev->bulk_out_ring;
        const u32 slots = (ep_addr & 0x80) ? dev->bulk_in_ring_slots : dev->bulk_out_ring_slots;
        const u64 ring_phys_base = (ep_addr & 0x80) ? dev->bulk_in_ring_phys : dev->bulk_out_ring_phys;
        u32 trb_idx = 0;
        if (trb_phys >= ring_phys_base && trb_phys < ring_phys_base + slots * sizeof(Trb))
            trb_idx = u32((trb_phys - ring_phys_base) / sizeof(Trb));
        const u32 trb_len = ring[trb_idx].status & 0x0001FFFF;
        return trb_len > residual ? trb_len - residual : 0;
    };

    // Runtime event-ring ownership belongs to HidPollEntry; bulk
    // waiters poll for their completion in the transfer-event cache.
    const u64 timeout_ticks = (timeout_us + 9'999) / 10'000; // 100 Hz kernel tick
    const u64 polls = timeout_ticks == 0 ? 1 : timeout_ticks;
    for (u64 i = 0; i < polls; ++i)
    {
        u32 code = 0;
        u32 residual = 0;
        u32 len_unused = 0;
        if (TrbEventCacheTake(trb_phys, &code, &residual, &len_unused))
        {
            if (out_bytes != nullptr)
                *out_bytes = compute_bytes(residual);
            core::CleanroomTraceRecord("xhci", "bulk-cache-hit", trb_phys, code, residual);
            return code == kCompletionCodeSuccess || code == 13 /* Short Packet */;
        }
        if (timeout_ticks != 0)
            duetos::sched::SchedSleepTicks(1);
    }
    core::CleanroomTraceRecord("xhci", "bulk-timeout", trb_phys, timeout_us, 0);
    return false;
}

} // namespace duetos::drivers::usb::xhci
