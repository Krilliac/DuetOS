// Host fuzz support shim for the USB-net class drivers (CDC-ECM +
// RNDIS). Both kernel TUs (kernel/drivers/usb/{cdc_ecm,rndis}.cpp)
// reach every attacker-controlled byte through the xHCI control-
// transfer surface (GET_DESCRIPTOR(Config), GET_DESCRIPTOR(String),
// and RNDIS GET_ENCAPSULATED_RESPONSE). This TU stands in for that
// surface: it serves the libFuzzer input as a *stream* the driver's
// sequence of control-IN transfers consume in order, so the real
// ParseConfigDescriptor / RndisParseConfig walkers and the RNDIS
// control-reply parsers run on fuzzed bytes — the fuzz_aml model
// (the harness/shim defines the device-facing accessors the kernel
// TU links against, then drives the real public entry point).
//
// The frame pool is deliberately ONE frame deep. CdcEcm/Rndis
// BringUp allocates the config-descriptor frame (used, then freed),
// then allocates the rx + tx DMA frames as a *pair*. With one frame
// the tx allocation fails, so BringUp returns false right BEFORE it
// latches the file-local g_state.online flag — which the harness
// cannot reach to reset. Without this, the first input would wedge
// the probe "online" and every later input would short-circuit, so
// the parser would see exactly one input. UsbnetFuzzFeed() resets
// the pool + stream cursor at the top of every iteration.

#include "drivers/usb/xhci.h"
#include "mm/frame_allocator.h"
#include "mm/page.h"
#include "net/stack.h"
#include "sched/sched.h"

#include <cstdint>

namespace
{
const duetos::u8* g_in = nullptr;
duetos::u32 g_in_len = 0;
duetos::u32 g_cursor = 0;

constexpr duetos::u32 kFrameBytes = 4096;
alignas(16) duetos::u8 g_frame[kFrameBytes];
bool g_frame_used = false;
constexpr duetos::mm::PhysAddr kFramePhys = 0x1000; // nonzero, != kNullFrame
} // namespace

// Called by the harness at the top of LLVMFuzzerTestOneInput: point
// the control-transfer stream at the fresh input and release the
// single DMA frame so the next probe starts from clean state.
extern "C" void UsbnetFuzzFeed(const uint8_t* data, uint32_t size)
{
    g_in = reinterpret_cast<const duetos::u8*>(data);
    g_in_len = size;
    g_cursor = 0;
    g_frame_used = false;
}

// --- mm: single-frame pool --------------------------------------
namespace duetos::mm
{
core::Result<PhysAddr> AllocateFrame()
{
    if (g_frame_used)
        return core::Err{core::ErrorCode::OutOfMemory};
    g_frame_used = true;
    return core::Result<PhysAddr>(kFramePhys);
}
void FreeFrame(PhysAddr frame)
{
    if (frame == kFramePhys)
        g_frame_used = false;
}
void* PhysToVirt(PhysAddr phys)
{
    return phys == kFramePhys ? static_cast<void*>(g_frame) : nullptr;
}
} // namespace duetos::mm

// --- net: bind/inject/dhcp are no-ops on the harness ------------
//
// The RX poll task never runs (SchedCreate below does not start it),
// so NetStackInjectRx is referenced only to satisfy the link.
namespace duetos::net
{
void NetStackInjectRx(u32, const void*, u64) {}
bool NetStackBindInterface(u32, MacAddress, Ipv4Address, NetTxFn)
{
    return true;
}
bool DhcpStart(u32)
{
    return true;
}
} // namespace duetos::net

// --- sched: do NOT run the rx task --------------------------------
//
// SchedCreate must return without invoking `entry` — cdc-ecm-rx /
// rndis-rx are `for (;;)` poll loops that would never return.
namespace duetos::sched
{
Task* SchedCreate(TaskEntry, void*, const char*, TaskPriority)
{
    return nullptr;
}
void SchedSleepTicks(u64) {}
} // namespace duetos::sched

// --- xhci: serve the fuzz input as the device's control responses -
namespace duetos::drivers::usb::xhci
{
bool XhciControlIn(u8, u8 /*bmRequestType*/, u8 /*bRequest*/, u16 /*wValue*/, u16 /*wIndex*/, void* buf, u16 len)
{
    auto* out = static_cast<u8*>(buf);
    u32 n = (g_cursor < g_in_len) ? (g_in_len - g_cursor) : 0;
    if (n > len)
        n = len;
    for (u32 i = 0; i < n; ++i)
        out[i] = g_in[g_cursor + i];
    for (u32 i = n; i < len; ++i)
        out[i] = 0; // short device reply -> zero-pad (a valid fuzz case)
    g_cursor += n;
    return true;
}
bool XhciControlOut(u8, u8, u8, u16, u16, const void*, u16)
{
    return true; // SET_CONFIGURATION / SET_INTERFACE / SEND_ENCAP carry no parsed reply
}
bool XhciConfigureBulkEndpoint(u8, u8, u16)
{
    return true;
}
u64 XhciBulkSubmit(u8, u8, u64, u32)
{
    return 1; // nonzero fake TRB; only the (never-run) rx/tx paths call this
}
bool XhciBulkPoll(u8, u8, u64, u32* out_bytes, u64)
{
    if (out_bytes != nullptr)
        *out_bytes = 0;
    return false;
}
u8 XhciFindDeviceByClass(u8, u8)
{
    return 1; // one device; drives the CDC-ECM fast-path BringUp
}
u32 XhciEnumerateDevices(u8* out, u32 max)
{
    if (max == 0)
        return 0;
    out[0] = 1;
    return 1;
}
void XhciPauseEventConsumer(bool) {}
} // namespace duetos::drivers::usb::xhci
