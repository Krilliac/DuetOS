/*
 * DuetOS — xHCI driver: per-controller IRQ + poll-task plumbing.
 *
 * Sibling TU. Houses the four per-controller IRQ stubs (one per
 * possible controller index, since the kernel's IrqHandler is a
 * context-less function pointer), the small XhciAckInterrupter
 * helper that clears IMAN.IP after dispatch, and the file-scope
 * tables (g_poll_args, g_poll_rt, kXhciIrqStamps) that wire it all
 * together. Definitions live here; declarations are in
 * xhci_internal.h so InitOne / XhciBindMsix / HidPollEntry / the
 * public xfer surface in xhci.cpp can reach them by name.
 */

#include "../../sched/sched.h"
#include "xhci_internal.h"

namespace duetos::drivers::usb::xhci::internal
{

constinit PollTaskArg g_poll_args[kMaxControllers] = {};
constinit Runtime g_poll_rt[kMaxControllers] = {};

namespace
{

// Acknowledge interrupter 0's IMAN.IP (the device-side pending
// bit). LAPIC EOI is handled by the generic IRQ dispatcher; this
// clears the xHCI-internal pending bit so a subsequent event
// re-asserts the line instead of being coalesced into the
// already-pending state. Keeps IE set so future events still
// trigger interrupts.
void XhciAckInterrupter(Runtime& rt)
{
    if (rt.intr0 == nullptr)
        return;
    const u32 iman = ReadMmio32(rt.intr0, kIntrIman);
    WriteMmio32(rt.intr0, kIntrIman, (iman & ~kImanIp) | kImanIp | kImanIe);
}

void XhciIrq0()
{
    XhciAckInterrupter(g_poll_rt[0]);
    duetos::sched::WaitQueueWakeOne(&g_poll_args[0].wait);
}
void XhciIrq1()
{
    XhciAckInterrupter(g_poll_rt[1]);
    duetos::sched::WaitQueueWakeOne(&g_poll_args[1].wait);
}
void XhciIrq2()
{
    XhciAckInterrupter(g_poll_rt[2]);
    duetos::sched::WaitQueueWakeOne(&g_poll_args[2].wait);
}
void XhciIrq3()
{
    XhciAckInterrupter(g_poll_rt[3]);
    duetos::sched::WaitQueueWakeOne(&g_poll_args[3].wait);
}

} // namespace

static_assert(kMaxControllers == 4, "per-controller IRQ stamps must match kMaxControllers");
const ::duetos::arch::IrqHandler kXhciIrqStamps[kMaxControllers] = {&XhciIrq0, &XhciIrq1, &XhciIrq2, &XhciIrq3};

} // namespace duetos::drivers::usb::xhci::internal
