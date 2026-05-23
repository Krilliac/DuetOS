#pragma once

#include "drivers/gpu/dpms.h"

/*
 * DuetOS — DPMS backend dispatcher.
 *
 * `dpms.{h,cpp}` is a pure state-machine bookkeeper: it tracks the
 * requested DPMS state and offers a single-hook integration seam
 * (`DpmsRegisterHook`) that drivers can wire into. This TU is the
 * canonical hook implementation that actually drives the host-side
 * display controllers — Bochs VBE (QEMU `-vga std`) and virtio-gpu
 * (QEMU `-vga virtio`) — through power transitions.
 *
 * On `DpmsSetState(target)` the registered hook:
 *
 *   - If target == On  : re-bind every active backend.
 *     * Bochs VBE     : set ENABLE.ENABLED = 1
 *     * virtio-gpu    : SET_SCANOUT(scanout=0, resource_id=1, rect)
 *                       + push a full-resource flush so the host
 *                       sees current content
 *   - else (Standby / Suspend / Off) : detach every active backend.
 *     * Bochs VBE     : set ENABLE.ENABLED = 0
 *     * virtio-gpu    : SET_SCANOUT(scanout=0, resource_id=0, rect)
 *
 *   The three low-power targets all collapse to "detach" because
 *   neither QEMU backend models the spec's H-sync / V-sync power-
 *   level distinction. A future real-hardware driver (Intel DDI,
 *   AMD DCN, panel-power-pin) can register a richer hook that uses
 *   the `from` / `to` arguments to walk the spec ladder.
 *
 * The hook returns `true` (commit the recorded state) unconditionally
 * — a controller that's not present today is not a reason to leave
 * the bookkeeper out of sync with the operator's request. When NO
 * backend is wired, the function is a successful no-op and matches
 * the previous "always-commit" behaviour `dpms.cpp` had when the
 * hook was unregistered.
 *
 * Context: kernel. The hook itself runs in the calling task's
 * context (typically the shell's, when the operator types `dpms
 * off`), so it's safe to issue MMIO + controlq commands inline.
 */

namespace duetos::drivers::gpu
{

/// Register the canonical backend hook. Idempotent. Called from
/// the gpu module's `Drivers`-phase initcall after `GpuInit` so
/// the discovered-display cache is already populated; not strictly
/// required since the hook re-checks each backend's live state on
/// every transition, but it keeps the boot-log ordering tidy.
void DpmsRegisterBackendHook();

/// Self-test: drive a quick On→Off→On cycle through the registered
/// hook. Validates that the dispatcher commits its transitions and
/// returns the bookkeeper to On so the boot-time state matches the
/// post-self-test live state. Emits one structural sentinel line —
/// `[gpu/display-power] selftest PASS (...)` or `selftest FAIL` —
/// that CI greps for. Safe to call before any backend is brought
/// up; with no backends the hook is a no-op and we still verify
/// that the bookkeeper records the transitions.
void DisplayPowerSelfTest();

} // namespace duetos::drivers::gpu
