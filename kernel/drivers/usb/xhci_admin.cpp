/*
 * DuetOS — xHCI driver: tiny public read-only accessors.
 *
 * Sibling TU. Houses the public Xhci* surface that does nothing
 * but inspect the driver's global tables — `g_controllers`,
 * `g_controller_count`, `g_devices`. None of these touch the
 * controller, the rings, or any TRB state, so they can live in
 * a separate TU once the tables are visible via xhci_internal.h.
 *
 *   XhciCount               — number of bound controllers
 *   XhciControllerAt        — bound-checked controller index
 *   XhciFindDeviceByClass   — first slot_id matching class/subclass
 *   XhciEnumerateDevices    — copy slot_ids out to a caller buffer
 *   XhciPauseEventConsumer  — compatibility no-op (routed-runtime
 *                             path doesn't need it; kept for
 *                             ABI stability)
 */

#include "drivers/usb/xhci.h"

#include "drivers/usb/xhci_internal.h"

namespace duetos::drivers::usb::xhci
{

using namespace internal;

u8 XhciFindDeviceByClass(u8 class_code, u8 subclass)
{
    for (u32 i = 0; i < kMaxDevicesTotal; ++i)
    {
        const DeviceState& d = g_devices[i];
        if (!d.in_use || d.slot_id == 0)
            continue;
        if (class_code != 0xFF && d.dev_class != class_code)
            continue;
        if (subclass != 0xFF && d.dev_subclass != subclass)
            continue;
        return d.slot_id;
    }
    return 0;
}

void XhciPauseEventConsumer(bool pause)
{
    // Router-backed runtime path: HidPollEntry is the event-ring
    // owner and forwards non-HID completions into the side cache
    // for bulk waiters. Keep this API as a compatibility no-op so
    // existing class-driver call-sites stay source-compatible.
    (void)pause;
}

u32 XhciEnumerateDevices(u8* out, u32 max)
{
    u32 n = 0;
    for (u32 i = 0; i < kMaxDevicesTotal && n < max; ++i)
    {
        const DeviceState& d = g_devices[i];
        if (!d.in_use || d.slot_id == 0)
            continue;
        if (out != nullptr)
            out[n] = d.slot_id;
        ++n;
    }
    return n;
}

u32 XhciCount()
{
    return g_controller_count;
}

const ControllerInfo* XhciControllerAt(u32 i)
{
    if (i >= g_controller_count)
        return nullptr;
    return &g_controllers[i];
}

} // namespace duetos::drivers::usb::xhci
