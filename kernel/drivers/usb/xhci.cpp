/*
 * DuetOS — xHCI USB host controller driver: implementation.
 *
 * Companion to xhci.h — see there for the controller record,
 * device-context shape, and the public API used by class
 * drivers (HID keyboard, MSC SCSI, CDC-ECM, RNDIS).
 *
 * WHAT
 *   Owns xHCI bring-up + a polling enumerator that walks every
 *   port, addresses each connected device, fetches its device
 *   descriptor, and dispatches to the matching class driver.
 *   Provides the per-device transfer ring API (control / bulk
 *   / interrupt) class drivers use to talk to their endpoints.
 *
 * HOW
 *   Each transfer ring is a TRB queue with a software-managed
 *   producer cycle bit; the controller's consumer cycle bit
 *   tells you when the entry has been consumed. Doorbell
 *   writes kick the controller after enqueue. Completions land
 *   in the event ring which we walk in `XhciPollEvents`.
 *
 *   Class-driver dispatch is by USB class code in the device
 *   descriptor; first match wins, no driver loops. Bulk
 *   transfer concurrency is serialised today (one outstanding
 *   per device) to avoid a TRB-queue race noted in
 *   .claude/knowledge/usb-rndis-driver-v0.md.
 *
 * WHY THIS FILE IS LARGE
 *   xHCI is intricate — context arrays, TRB types, ring
 *   wrap-around, completion-code translation, port reset
 *   sequencing. Plus the per-class probe chains live here too.
 */

#include "xhci.h"

#include "../../arch/x86_64/cpu.h"
#include "../../arch/x86_64/serial.h"
#include "../../core/cleanroom_trace.h"
#include "../../core/klog.h"
#include "../../core/result.h"
#include "../../mm/frame_allocator.h"
#include "../../mm/page.h"
#include "../../sched/sched.h"
#include "../input/ps2kbd.h"
#include "../input/ps2mouse.h"
#include "../pci/pci.h"
#include "usb.h"
#include "xhci_internal.h"

namespace duetos::drivers::usb::xhci
{

// Pull cross-TU helpers (CompletionCodeName, future struct/MMIO
// surface) into the outer namespace so existing call sites can keep
// using them unqualified after each per-aspect extraction.
using namespace internal;

namespace internal
{

// File-scope global tables. Declarations live in xhci_internal.h
// (extern constinit) so the per-aspect TUs can reach them; the
// definitions stay here so storage is single-TU.
constinit ControllerInfo g_controllers[kMaxControllers] = {};
constinit u32 g_controller_count = 0;
// "Is Init live" flag so XhciShutdown can clear it and a subsequent
// XhciInit re-runs — restartable drivers need this rewindable.
constinit bool g_init_done = false;

constinit DeviceState g_devices[kMaxDevicesTotal] = {};
constinit u32 g_device_count = 0;

} // namespace internal


} // namespace duetos::drivers::usb::xhci
