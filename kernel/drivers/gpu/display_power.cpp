/*
 * DuetOS — DPMS backend dispatcher: implementation.
 *
 * See `display_power.h` for the rationale + hook contract.
 */

#include "drivers/gpu/display_power.h"

#include "arch/x86_64/serial.h"
#include "core/init.h"
#include "debug/probes.h"
#include "drivers/gpu/bochs_vbe.h"
#include "drivers/gpu/dpms.h"
#include "drivers/gpu/virtio_gpu.h"
#include "log/klog.h"

namespace duetos::drivers::gpu
{

namespace
{

bool g_hook_registered = false;

// Per-backend enable shim. Each returns true iff a real controller
// was decoded AND accepted the toggle — anything else is "backend
// not present" and silently no-ops. The dispatcher commits the
// state regardless so the bookkeeper stays in sync with the
// operator's request.
bool ApplyVbe(bool enable)
{
    // VbeQuery does its own non-destructive presence probe. If the
    // controller isn't a BGA-family device the call returns
    // `present == false` and we skip the toggle.
    const VbeCaps c = VbeQuery();
    if (!c.present)
        return false;
    return VbeSetEnabled(enable);
}

bool ApplyVirtio(bool enable)
{
    const auto& sc = VirtioGpuScanoutInfo();
    if (!sc.ready)
        return false;
    return VirtioGpuSetScanoutEnabled(enable);
}

bool BackendHook(DpmsState from, DpmsState to, void* ctx)
{
    (void)from;
    (void)ctx;

    // virtio-gpu has only an enabled/disabled axis; Bochs VBE
    // ditto. Every low-power DPMS target maps to "off"; only the
    // explicit On state re-enables. A future driver with finer
    // power control (Intel/AMD/NVIDIA real-hardware paths) can
    // register a richer hook that consumes `from` and walks the
    // VESA H-sync / V-sync ladder.
    const bool enable = (to == DpmsState::On);

    // Drive every backend that's actually live. We don't short-
    // circuit on the first one — a host can have both Bochs VBE
    // and virtio-gpu in the same boot in theory (it's QEMU's
    // -device line that wires them); driving each in turn is
    // cheap and keeps the dispatcher's behaviour orthogonal to
    // PCI enumeration order.
    bool any_handled = false;
    any_handled = ApplyVbe(enable) || any_handled;
    any_handled = ApplyVirtio(enable) || any_handled;

    // Commit regardless. A boot with no display backend (headless
    // serial-only run) still benefits from the bookkeeper tracking
    // the request — shell commands and the settings app surface
    // `DpmsGet()` for the operator.
    if (!any_handled)
    {
        // Debug-gated breadcrumb so a headless boot doesn't litter
        // the log with "no backend" warnings on every transition.
        KLOG_DEBUG_S("drivers/gpu/display-power", "transition with no live backend; bookkeeper-only commit", "target",
                     DpmsStateName(to));
    }
    return true;
}

} // namespace

void DpmsRegisterBackendHook()
{
    if (g_hook_registered)
        return;
    DpmsRegisterHook(BackendHook, nullptr);
    g_hook_registered = true;
    arch::SerialWrite("[gpu/display-power] DPMS backend hook registered (Bochs VBE + virtio-gpu)\n");
}

void DisplayPowerSelfTest()
{
    // Snapshot pre-test state so we can restore the bookkeeper to
    // a known-good state regardless of what runtime requests have
    // already moved it through.
    const DpmsState entry = DpmsGet();
    const u64 entry_count = DpmsTransitionCount();

    // Force the hook through one Off → On cycle. The hook commits
    // unconditionally so both transitions land; we verify by
    // sampling DpmsGet() and the transition counter after each.
    bool ok = true;

    if (!DpmsSetState(DpmsState::Off))
        ok = false;
    if (DpmsGet() != DpmsState::Off)
        ok = false;

    if (!DpmsSetState(DpmsState::On))
        ok = false;
    if (DpmsGet() != DpmsState::On)
        ok = false;

    // The counter should have bumped twice (Off, On) iff both
    // states differ from entry. If entry was already On, only the
    // Off→On leg bumps; either way we should see >= 1.
    const u64 expected_min_bumps = (entry == DpmsState::On) ? 2u : 1u;
    if (DpmsTransitionCount() < entry_count + expected_min_bumps)
        ok = false;

    // Restore the entry state if it wasn't On — the bookkeeper
    // should look the same after the self-test as before it.
    if (entry != DpmsState::On)
        (void)DpmsSetState(entry);

    if (ok)
    {
        arch::SerialWrite("[gpu/display-power] selftest PASS (hook commits On/Off, bookkeeper bumped)\n");
        return;
    }

    KBP_PROBE_V(::duetos::debug::ProbeId::kBootSelftestFail, /*sub-check tag*/ 0xD7Au);
    arch::SerialWrite("[gpu/display-power] selftest FAIL (transition did not commit)\n");
}

namespace
{

::duetos::core::Result<void> RegisterDpmsHookInitcall()
{
    DpmsRegisterBackendHook();
    return {};
}

} // namespace

KERNEL_INITCALL(Drivers, "drivers/gpu.dpms-hook", RegisterDpmsHookInitcall)

} // namespace duetos::drivers::gpu
