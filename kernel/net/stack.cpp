#include "stack.h"

#include "../arch/x86_64/serial.h"
#include "../core/klog.h"
#include "../core/panic.h"
#include "../drivers/net/net.h"

namespace customos::net
{

namespace
{

u64 g_interface_count = 0;

} // namespace

void NetStackInit()
{
    KLOG_TRACE_SCOPE("net/stack", "NetStackInit");
    static constinit bool s_done = false;
    KASSERT(!s_done, "net/stack", "NetStackInit called twice");
    s_done = true;

    // Walk the driver-layer NIC table. Today we just log a
    // one-line-per-interface "would bind" record — there's no
    // real TX/RX yet. The binding will be symmetric: each
    // `drivers::net::NicInfo` gets one entry in an internal
    // interface table keyed by (bus, device, function).
    const u64 n = drivers::net::NicCount();
    for (u64 i = 0; i < n; ++i)
    {
        const drivers::net::NicInfo& nic = drivers::net::Nic(i);
        arch::SerialWrite("[net-stack] would bind iface ");
        arch::SerialWriteHex(i);
        arch::SerialWrite(" to nic ");
        arch::SerialWriteHex(nic.bus);
        arch::SerialWrite(":");
        arch::SerialWriteHex(nic.device);
        arch::SerialWrite(".");
        arch::SerialWriteHex(nic.function);
        arch::SerialWrite(" (");
        arch::SerialWrite(nic.vendor);
        if (nic.family != nullptr)
        {
            arch::SerialWrite(" ");
            arch::SerialWrite(nic.family);
        }
        arch::SerialWrite(")\n");
        ++g_interface_count;
    }

    core::LogWithValue(core::LogLevel::Info, "net/stack", "interfaces registered", g_interface_count);
    if (g_interface_count == 0)
    {
        core::Log(core::LogLevel::Warn, "net/stack", "no NICs to bind — stack is up but silent");
    }
    else
    {
        core::Log(core::LogLevel::Warn, "net/stack", "stack bound but no packet I/O yet (skeleton slice)");
    }
}

u64 InterfaceCount()
{
    return g_interface_count;
}

} // namespace customos::net
