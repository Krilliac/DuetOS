#pragma once

#include "util/types.h"

/*
 * DuetOS — VESA Display Power Management Signaling state machine
 * (clean room).
 *
 * Spec: VESA DPMS standard (1993, public) + the X.Org DPMS
 * extension protocol (publicly published by X.Org).
 *
 * DPMS defines four monitor power states; the host signals each
 * by manipulating the H-sync and V-sync lines:
 *
 *   On       - both syncs active. Power < monitor's max.
 *   Standby  - H-sync off, V-sync on. Power ~80 % of On.
 *   Suspend  - H-sync on, V-sync off. Power ~30 % of On.
 *   Off      - both syncs off. Power < 8 W.
 *
 * On modern flat panels the DPMS hooks are how the kernel asks
 * the panel to enter low-power sleep when the screensaver fires;
 * on real CRTs the same signaling brought the gun bias down.
 *
 * This TU is the bookkeeping surface. It tracks the current
 * state, validates transitions (per the spec, any→any is legal),
 * and notifies a registered driver callback so the GPU layer can
 * actually program the sync lines / panel-power pin / EDP eDP-
 * AUX power request etc. Without a registered callback the state
 * machine still records the desired state — useful for tests and
 * for a "headless / no-monitor" build.
 *
 * Eventual consumers:
 *   - Screensaver: after N seconds idle, transition to Standby,
 *     then Suspend, then Off.
 *   - Power-policy / lid-switch drivers.
 *   - Win32 SetMonitorPowerSetting / Linux sysfs `dpms` writes.
 *
 * No allocation, no global state outside the TU.
 */

namespace duetos::drivers::gpu
{

enum class DpmsState : u8
{
    On = 0,
    Standby = 1,
    Suspend = 2,
    Off = 3,
};

const char* DpmsStateName(DpmsState s);

/// Driver-side callback signature. The state-machine layer
/// invokes this before changing the recorded state. A driver
/// returning false vetoes the transition (keeps the previous
/// state); returning true commits.
using DpmsTransitionFn = bool (*)(DpmsState from, DpmsState to, void* ctx);

/// Boot-time init. Sets the recorded state to On and clears any
/// previously-registered hook. Idempotent.
void DpmsInit();

/// Register the per-driver hook. Replaces any previously-
/// registered hook. Pass nullptr to detach (state machine then
/// becomes "always-commit" and operates as a pure bookkeeper).
void DpmsRegisterHook(DpmsTransitionFn fn, void* ctx);

/// Request a transition. Returns true iff the new state landed.
/// Legal at any time after `DpmsInit`. Idempotent — transitioning
/// to the current state always succeeds and does not call the
/// driver hook.
bool DpmsSetState(DpmsState target);

/// Query the currently recorded state.
DpmsState DpmsGet();

/// Counter for "transitions that ran the driver hook" — used by
/// tests + the `inspect` shell tier when it lands.
u64 DpmsTransitionCount();

void DpmsSelfTest();

} // namespace duetos::drivers::gpu
