#pragma once

namespace duetos::core
{

// Fires every cleanroom-trace dispatch point that is otherwise
// silent on QEMU + emulated hardware (no real Wi-Fi NIC, no
// firmware-requesting driver). Registers a stub Wi-Fi backend,
// walks register -> scan -> connect -> disconnect, then asks
// the firmware loader for a synthetic blob that no backend can
// satisfy. Every call records into the trace ring so a survey
// run can verify the wiring without real silicon.
//
// Safe to call from any kernel thread; not safe from IRQ.
void CrProbeRun();

} // namespace duetos::core
